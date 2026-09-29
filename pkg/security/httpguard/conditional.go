package httpguard

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const MaxEntityTagListMembers = 128

// Entity tags are opaque octet sequences, not quoted strings: backslashes have
// no escape semantics and commas inside the quotes do not separate list items.
func entityTagPrefix(value string) (end int, weak, valid bool) {
	i := 0
	weak = strings.HasPrefix(value, "W/")
	if weak {
		i = 2
	}
	if i >= len(value) || value[i] != '"' {
		return 0, false, false
	}
	for i++; i < len(value); i++ {
		if value[i] == '"' {
			return i + 1, weak, true
		}
		// obs-text is excluded by the broker's existing ASCII field policy.
		if value[i] < 33 || value[i] > 126 {
			return 0, false, false
		}
	}
	return 0, false, false
}

func ValidateEntityTag(value string) (weak bool, err error) {
	if len(value) > 8192 {
		return false, fmt.Errorf("entity tag exceeds field limit")
	}
	end, weak, valid := entityTagPrefix(value)
	if !valid || end != len(value) {
		return false, fmt.Errorf("invalid entity tag")
	}
	return weak, nil
}

func validateEntityTagList(value string) error {
	if len(value) > 8192 {
		return fmt.Errorf("entity tag list exceeds field limit")
	}
	if value == "*" {
		return nil
	}
	position, tags := 0, 0
	for slots := 1; ; slots++ {
		if slots > MaxEntityTagListMembers {
			return fmt.Errorf("entity tag list exceeds member limit")
		}
		for position < len(value) && value[position] == ' ' {
			position++
		}
		if position < len(value) && value[position] != ',' {
			end, _, valid := entityTagPrefix(value[position:])
			if !valid {
				return fmt.Errorf("invalid conditional entity tag list")
			}
			position += end
			tags++
			for position < len(value) && value[position] == ' ' {
				position++
			}
		}
		if position == len(value) {
			if tags == 0 {
				return fmt.Errorf("conditional entity tag list must not be empty")
			}
			return nil
		}
		if value[position] != ',' {
			return fmt.Errorf("invalid entity tag list separator")
		}
		position++
	}
}

// MatchEntityTagList compares a validated conditional list with the current
// representation's entity tag. Strong comparisons require two strong tags;
// weak comparisons compare the opaque values without interpreting escapes.
func MatchEntityTagList(value, target string, strong bool) (bool, error) {
	if err := validateEntityTagList(value); err != nil {
		return false, err
	}
	targetWeak, err := ValidateEntityTag(target)
	if err != nil {
		return false, err
	}
	if value == "*" {
		return true, nil
	}
	for position := 0; position < len(value); {
		if value[position] == ' ' || value[position] == ',' {
			position++
			continue
		}
		end, weak, _ := entityTagPrefix(value[position:])
		tag := value[position : position+end]
		if (!strong || !weak && !targetWeak) && strings.TrimPrefix(tag, "W/") == strings.TrimPrefix(target, "W/") {
			return true, nil
		}
		position += end
	}
	return false, nil
}

const dateWeekday = `(Mon|Tue|Wed|Thu|Fri|Sat|Sun)`
const dateMonth = `(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)`
const dateTimeOfDay = `([0-9]{2}):([0-9]{2}):([0-9]{2})`

var imfDate = regexp.MustCompile(`^` + dateWeekday + `, ([0-9]{2}) ` + dateMonth + ` ([0-9]{4}) ` + dateTimeOfDay + ` GMT$`)
var obsoleteDate = regexp.MustCompile(`^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), ([0-9]{2})-` + dateMonth + `-([0-9]{2}) ` + dateTimeOfDay + ` GMT$`)
var asctimeDate = regexp.MustCompile(`^` + dateWeekday + ` ` + dateMonth + ` ([0-9]{2}| [0-9]) ` + dateTimeOfDay + ` ([0-9]{4})$`)

// ValidateHTTPDate enforces HTTP's three date grammars and calendar semantics.
// Outgoing generated dates use IMF-fixdate; recipients also accept both obsolete
// forms. It does not establish clock accuracy, resource state or date strength.
func ValidateHTTPDate(value string, allowObsolete bool) error {
	_, err := HTTPDateOrderKey(value, allowObsolete)
	return err
}

func validateHTTPDateAt(value string, allowObsolete bool, now time.Time) error {
	_, err := httpDateOrderKeyAt(value, allowObsolete, now)
	return err
}

// HTTPDateOrderKey validates a date and returns fixed-width calendar components
// for comparison. Unlike time.Time, this preserves 23:59:60 as distinct from the
// next day's midnight; it does not establish whether a validator is strong.
func HTTPDateOrderKey(value string, allowObsolete bool) (string, error) {
	return httpDateOrderKeyAt(value, allowObsolete, time.Now().UTC())
}

func httpDateOrderKeyAt(value string, allowObsolete bool, now time.Time) (string, error) {
	bad := func() (string, error) { return "", fmt.Errorf("invalid HTTP date") }
	if len(value) > 40 {
		return bad()
	}
	fields := imfDate.FindStringSubmatch(value)
	shortYear := false
	if fields == nil && allowObsolete {
		fields = obsoleteDate.FindStringSubmatch(value)
		shortYear = fields != nil
		if fields == nil {
			if a := asctimeDate.FindStringSubmatch(value); a != nil {
				fields = []string{a[0], a[1], strings.TrimSpace(a[3]), a[2], a[7], a[4], a[5], a[6]}
			}
		}
	}
	if fields == nil {
		return bad()
	}
	day, _ := strconv.Atoi(fields[2])
	month := time.Month(strings.Index("JanFebMarAprMayJunJulAugSepOctNovDec", fields[3])/3 + 1)
	year, _ := strconv.Atoi(fields[4])
	hour, _ := strconv.Atoi(fields[5])
	minute, _ := strconv.Atoi(fields[6])
	second, _ := strconv.Atoi(fields[7])
	if hour > 23 || minute > 59 || second > 60 || second == 60 && (hour != 23 || minute != 59) {
		return bad()
	}
	// Go time.Time does not represent leap seconds. Keep their original calendar
	// day for validation rather than normalizing them into the following day.
	calendarSecond := min(second, 59)
	if shortYear {
		cutoff := now.UTC().AddDate(50, 0, 0)
		year += cutoff.Year() / 100 * 100
		// Compare calendar components so 23:59:60 stays after 23:59:59 but
		// before the next day; time.Time would normalize both to midnight.
		candidate := fmt.Sprintf("%04d%02d%02d%02d%02d%02d", year, month, day, hour, minute, second)
		if candidate > cutoff.Format("20060102150405") {
			year -= 100
		}
	}
	date := time.Date(year, month, day, hour, minute, calendarSecond, 0, time.UTC)
	if year < 1900 || date.Year() != year || date.Month() != month || date.Day() != day || date.Weekday().String()[:3] != fields[1][:3] {
		return bad()
	}
	return fmt.Sprintf("%04d%02d%02d%02d%02d%02d", year, month, day, hour, minute, second), nil
}

func validateConditionalField(name, value string) error {
	switch name {
	case "if-match", "if-none-match":
		return validateEntityTagList(value)
	case "if-range":
		if weak, err := ValidateEntityTag(value); err == nil {
			if weak {
				return fmt.Errorf("If-Range requires a strong entity tag")
			}
			return nil
		}
		return ValidateHTTPDate(value, false)
	case "if-modified-since", "if-unmodified-since", "date":
		return ValidateHTTPDate(value, false)
	}
	return nil
}

// ValidateConditionalRequest applies the same field policy at MCP admission
// and the direct transport boundary. Multiple physical field values are denied
// locally; callers can send a bounded entity-tag list in one field value.
func ValidateConditionalRequest(method string, headers http.Header) error {
	seen := map[string]bool{}
	hasRange, ifRange := false, false
	for name, values := range headers {
		key := strings.ToLower(name)
		if key == "range" {
			hasRange = true
		}
		switch key {
		case "if-match", "if-none-match", "if-range", "if-modified-since", "if-unmodified-since", "date":
			if seen[key] || len(values) != 1 {
				return fmt.Errorf("duplicate conditional or Date field")
			}
			seen[key] = true
			if err := ValidateHeader(name, values[0]); err != nil {
				return err
			}
			ifRange = ifRange || key == "if-range"
		}
	}
	if ifRange {
		if !hasRange || method != "GET" {
			return fmt.Errorf("If-Range requires a GET Range request")
		}
		return ValidateRangeRequest(method, headers)
	}
	return nil
}
