// Signature-scheme tests with a pinned clock: acceptance inside the
// window, rejection of stale/future/tampered/cross-key requests, and the
// exact signed-string layout (frozen so third-party clients can implement
// it from the README alone).
package hmacauth

import (
	"errors"
	"strconv"
	"testing"
	"time"
)

var (
	key  = []byte("test-shared-key")
	now  = time.Unix(1_760_000_000, 0)
	body = []byte(`{"type":"A","value":"10.0.0.7"}`)
)

func TestSignIsDeterministicAndMatchesKnownVector(t *testing.T) {
	a := Sign(key, "PUT", "/v1/records/app", now.Unix(), body)
	b := Sign(key, "PUT", "/v1/records/app", now.Unix(), body)
	if a != b {
		t.Fatal("same inputs produced different signatures")
	}
	if len(a) != 64 {
		t.Fatalf("signature length %d, want 64 hex chars", len(a))
	}
	// Frozen test vector (independently reproducible with openssl):
	// changing the signed-string layout breaks every deployed client, so
	// this exact value is part of the API contract.
	got := Sign([]byte("k"), "PUT", "/p", 1, []byte("b"))
	const want = "2a1fd42a0daefe4f85cbc742bf809cc6c322b927bf2511efe0538651f120366c"
	if got != want {
		t.Fatalf("known-answer vector changed:\n got %s\nwant %s", got, want)
	}
}

func TestVerifyAcceptsFreshSignature(t *testing.T) {
	ts := now.Unix()
	sig := Sign(key, "PUT", "/v1/records/app", ts, body)
	err := Verify(key, "PUT", "/v1/records/app", itoa(ts), sig, body, now, 0)
	if err != nil {
		t.Fatalf("fresh request rejected: %v", err)
	}
}

func TestVerifyAcceptsSkewInsideWindow(t *testing.T) {
	for _, skew := range []time.Duration{-4 * time.Minute, 4 * time.Minute} {
		ts := now.Add(skew).Unix()
		sig := Sign(key, "GET", "/v1/records", ts, nil)
		if err := Verify(key, "GET", "/v1/records", itoa(ts), sig, nil, now, 0); err != nil {
			t.Errorf("skew %v rejected: %v", skew, err)
		}
	}
}

func TestVerifyRejectsStaleAndFuture(t *testing.T) {
	for _, skew := range []time.Duration{-6 * time.Minute, 6 * time.Minute} {
		ts := now.Add(skew).Unix()
		sig := Sign(key, "GET", "/v1/records", ts, nil)
		err := Verify(key, "GET", "/v1/records", itoa(ts), sig, nil, now, 0)
		if !errors.Is(err, ErrStale) {
			t.Errorf("skew %v: got %v, want ErrStale", skew, err)
		}
	}
	// A captured request replays fine inside the window (documented) but
	// must die once the window passes — this is the replay bound.
	ts := now.Unix()
	sig := Sign(key, "PUT", "/v1/records/app", ts, body)
	later := now.Add(DefaultWindow + time.Second)
	if err := Verify(key, "PUT", "/v1/records/app", itoa(ts), sig, body, later, 0); !errors.Is(err, ErrStale) {
		t.Errorf("replay after window: got %v, want ErrStale", err)
	}
}

func TestVerifyRejectsMalformedTimestamp(t *testing.T) {
	for _, ts := range []string{"", "abc", "12.5", "0x10"} {
		err := Verify(key, "GET", "/v1/records", ts, "deadbeef", nil, now, 0)
		if !errors.Is(err, ErrBadTimestamp) {
			t.Errorf("timestamp %q: got %v, want ErrBadTimestamp", ts, err)
		}
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	ts := now.Unix()
	sig := Sign([]byte("other-key"), "PUT", "/v1/records/app", ts, body)
	err := Verify(key, "PUT", "/v1/records/app", itoa(ts), sig, body, now, 0)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

func TestVerifyRejectsTamperedRequest(t *testing.T) {
	ts := now.Unix()
	sig := Sign(key, "PUT", "/v1/records/app", ts, body)
	cases := []struct {
		name         string
		method, path string
		body         []byte
	}{
		{"body swap", "PUT", "/v1/records/app", []byte(`{"type":"A","value":"6.6.6.6"}`)},
		{"path swap", "PUT", "/v1/records/other", body},
		{"method swap", "DELETE", "/v1/records/app", body},
	}
	for _, c := range cases {
		err := Verify(key, c.method, c.path, itoa(ts), sig, c.body, now, 0)
		if !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: got %v, want ErrBadSignature", c.name, err)
		}
	}
}

func TestVerifyHonorsCustomWindow(t *testing.T) {
	ts := now.Add(-30 * time.Second).Unix()
	sig := Sign(key, "GET", "/v1/records", ts, nil)
	if err := Verify(key, "GET", "/v1/records", itoa(ts), sig, nil, now, 10*time.Second); !errors.Is(err, ErrStale) {
		t.Fatalf("10s window accepted 30s skew: %v", err)
	}
	if err := Verify(key, "GET", "/v1/records", itoa(ts), sig, nil, now, time.Minute); err != nil {
		t.Fatalf("60s window rejected 30s skew: %v", err)
	}
}

func itoa(ts int64) string { return strconv.FormatInt(ts, 10) }
