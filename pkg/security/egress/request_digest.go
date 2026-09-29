package egress

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/google/ax/pkg/security/httpguard"
)

// A digest-bearing request is buffered before DNS/dispatch. Hashing GetBody
// would permit the replay and actual streams to differ; read the actual Body
// once, then send precisely that verified snapshot. Digest-free requests keep
// the existing transport behavior.
func prepareRequestDigest(req *http.Request) error {
	digests, err := httpguard.ParseContentDigests(req.Header)
	var representation *httpguard.ContentDigests
	if err == nil {
		representation, err = httpguard.ParseRequestRepresentationDigests(req.Header)
	}
	if err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return err
	}
	if !digests.Present() && !representation.Present() {
		return nil
	}
	body := req.Body
	if body != nil {
		// net/http's request-body contract requires Close to unblock Read.
		// Cancellation closes the same stream without creating a detached reader.
		var closed sync.Once
		closeBody := func() { closed.Do(func() { body.Close() }) }
		stop := context.AfterFunc(req.Context(), closeBody)
		defer func() {
			stop()
			closeBody()
		}()
	}
	if err := req.Context().Err(); err != nil {
		return err
	}
	if req.ContentLength < -1 || req.ContentLength > httpguard.MaxRequestBodyBytes ||
		(body == nil || body == http.NoBody) && req.ContentLength > 0 {
		return fmt.Errorf("invalid digest-bearing request content length")
	}
	var content []byte
	if body != nil {
		content, err = io.ReadAll(io.LimitReader(body, httpguard.MaxRequestBodyBytes+1))
		if err != nil {
			return fmt.Errorf("digest-bearing request body could not be read")
		}
	}
	if err := req.Context().Err(); err != nil {
		return err
	}
	if len(content) > httpguard.MaxRequestBodyBytes ||
		req.ContentLength > 0 && req.ContentLength != int64(len(content)) {
		return fmt.Errorf("digest-bearing request body length violates policy")
	}
	if err := digests.CheckBody(content); err != nil {
		return err
	}
	if err := representation.CheckBody(content); err != nil {
		return err
	}
	req.ContentLength = int64(len(content))
	req.GetBody = func() (io.ReadCloser, error) {
		if len(content) == 0 {
			return http.NoBody, nil
		}
		return io.NopCloser(bytes.NewReader(content)), nil
	}
	req.Body, _ = req.GetBody()
	return nil
}
