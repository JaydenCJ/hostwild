// Package hmacauth implements the request signing scheme of the dynamic
// update API. Every mutating request carries a Unix timestamp and an
// HMAC-SHA256 over (method, path, timestamp, body-hash); the server
// rejects stale timestamps and compares signatures in constant time.
// There are no sessions and no tokens to leak — the shared key never
// travels on the wire.
package hmacauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Header names used by the API and the bundled client.
const (
	HeaderTimestamp = "X-Hostwild-Timestamp"
	HeaderSignature = "X-Hostwild-Signature"
)

// DefaultWindow is how far a request timestamp may deviate from server
// time before it is rejected as a replay or a clock problem.
const DefaultWindow = 5 * time.Minute

// Verification failures. All of them map to HTTP 401 so callers cannot
// probe which check failed, but logs and tests can distinguish them.
var (
	ErrBadTimestamp = errors.New("hmacauth: malformed timestamp")
	ErrStale        = errors.New("hmacauth: timestamp outside acceptance window")
	ErrBadSignature = errors.New("hmacauth: signature mismatch")
)

// Sign computes the hex signature for a request. The signed string is
//
//	METHOD \n PATH \n TIMESTAMP \n hex(sha256(BODY))
//
// Hashing the body (instead of embedding it) keeps the signed string
// printable and lets clients sign large bodies in one pass.
func Sign(key []byte, method, path string, ts int64, body []byte) string {
	bodyHash := sha256.Sum256(body)
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%s\n%s\n%d\n%s", method, path, ts, hex.EncodeToString(bodyHash[:]))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify checks a request's timestamp and signature headers against the
// shared key. window <= 0 means DefaultWindow.
func Verify(key []byte, method, path, tsHeader, sigHeader string, body []byte, now time.Time, window time.Duration) error {
	if window <= 0 {
		window = DefaultWindow
	}
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return ErrBadTimestamp
	}
	drift := now.Unix() - ts
	if drift < 0 {
		drift = -drift
	}
	if time.Duration(drift)*time.Second > window {
		return ErrStale
	}
	want := Sign(key, method, path, ts, body)
	// hmac.Equal is constant-time; comparing hex strings of equal length
	// through it avoids leaking a prefix-match timing signal.
	if !hmac.Equal([]byte(want), []byte(sigHeader)) {
		return ErrBadSignature
	}
	return nil
}
