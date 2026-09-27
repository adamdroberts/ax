// Bounded fragment lifetime policy for the reviewed cumulative Snort repair.
// SPDX-License-Identifier: GPL-2.0-only
#ifndef AX_FRAGMENT_LIFETIME_H
#define AX_FRAGMENT_LIFETIME_H
#include <cstdint>
#include <limits>

namespace ax_fragment
{
// RFC 8200 section 4.5 places a 60-second ceiling on IPv6 reassembly.
// A smaller configured budget is an explicitly stricter local policy.
inline uint32_t reassembly_seconds(bool ipv6, uint32_t configured)
{
    return ipv6 && configured > 60 ? 60 : configured;
}

// Keep the flow's rejection state past ordinary reassembly retention windows.
// This is a local IPS quarantine policy, not an RFC receiver requirement.
// The extra second covers the flow cache's whole-second expiration arithmetic.
inline uint32_t retention_seconds(bool ipv6, uint32_t configured)
{
    const uint32_t floor = ipv6 ? 60 : 120;
    const uint32_t value = configured < floor ? floor : configured;
    return value == std::numeric_limits<uint32_t>::max() ? value : value + 1;
}

inline bool lifetime_expired(int64_t now_seconds, int64_t now_microseconds,
    int64_t first_seconds, int64_t first_microseconds, uint32_t budget)
{
    // DAQ timestamps are trusted local metadata. Reject malformed or reversed
    // time instead of allowing underflow or a backward clock to extend a lease.
    if (now_seconds < 0 || first_seconds < 0 || now_microseconds < 0 ||
        now_microseconds >= 1000000 || first_microseconds < 0 ||
        first_microseconds >= 1000000 || now_seconds < first_seconds ||
        (now_seconds == first_seconds && now_microseconds < first_microseconds))
        return true;
    const uint64_t seconds = static_cast<uint64_t>(now_seconds) -
        static_cast<uint64_t>(first_seconds);
    return seconds > budget || (seconds == budget && now_microseconds >= first_microseconds);
}
}
#endif
