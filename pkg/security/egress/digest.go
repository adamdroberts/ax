package egress

import (
	"fmt"
	"github.com/google/ax/pkg/security/httpguard"
	"net/http"
)

type contentDigests = httpguard.ContentDigests
type contentDigestChecker = httpguard.ContentDigestChecker

func digestError() error { return fmt.Errorf("message violates the HTTP digest integrity policy") }
func responseDigests(headers http.Header) (*contentDigests, error) {
	return httpguard.ParseContentDigests(headers)
}
func responseRepresentationDigests(headers http.Header) (*contentDigests, error) {
	return httpguard.ParseRepresentationDigests(headers)
}
func checkResponseContentDigest(resp *http.Response, body []byte) error {
	return httpguard.CheckContentDigest(resp.Header, body)
}
