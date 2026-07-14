// Update-API tests through httptest with a pinned clock: signed requests
// mutate the store, unsigned or mis-signed ones bounce with an opaque
// 401, and the DNS-01 helper lands TXT records exactly where a CA will
// look for them.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/JaydenCJ/hostwild/internal/dnswire"
	"github.com/JaydenCJ/hostwild/internal/hmacauth"
	"github.com/JaydenCJ/hostwild/internal/zone"
)

const testZone = "dev.example.test"

var (
	testKey = []byte("api-test-key")
	fixed   = time.Unix(1_760_000_000, 0)
)

func newAPI(t *testing.T) (*Handler, *zone.Store) {
	t.Helper()
	store := zone.NewStore("")
	return New(store, testZone, testKey, 0, func() time.Time { return fixed }), store
}

// signedRequest builds a correctly signed request against the handler.
func signedRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	ts := fixed.Unix()
	req.Header.Set(hmacauth.HeaderTimestamp, fmt.Sprintf("%d", ts))
	req.Header.Set(hmacauth.HeaderSignature,
		hmacauth.Sign(testKey, method, path, ts, []byte(body)))
	return req
}

func do(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("non-JSON response %q: %v", rec.Body.String(), err)
	}
	return out
}

func TestHealthzIsOpenAndReportsVersion(t *testing.T) {
	h, _ := newAPI(t)
	rec := do(h, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	out := decodeBody(t, rec)
	if out["ok"] != true || out["zone"] != testZone {
		t.Fatalf("body: %v", out)
	}
}

func TestPutARecordStoresIt(t *testing.T) {
	h, store := newAPI(t)
	rec := do(h, signedRequest("PUT", "/v1/records/app", `{"type":"A","value":"10.0.0.7","ttl":45}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	got := store.Lookup("app")
	if len(got) != 1 || got[0].Addr != netip.MustParseAddr("10.0.0.7") || got[0].TTL != 45 {
		t.Fatalf("stored record wrong: %+v", got)
	}
	if out := decodeBody(t, rec); out["fqdn"] != "app."+testZone {
		t.Fatalf("fqdn in response: %v", out["fqdn"])
	}
}

func TestPutAcceptsFullyQualifiedName(t *testing.T) {
	h, store := newAPI(t)
	path := "/v1/records/app." + testZone
	rec := do(h, signedRequest("PUT", path, `{"type":"A","value":"10.0.0.7"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if len(store.Lookup("app")) != 1 {
		t.Fatal("FQDN was not made zone-relative")
	}
}

func TestUnsignedOrStaleRequestsAre401(t *testing.T) {
	h, store := newAPI(t)
	req := httptest.NewRequest("PUT", "/v1/records/app", strings.NewReader(`{"type":"A","value":"10.0.0.7"}`))
	rec := do(h, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned: status %d, want 401", rec.Code)
	}
	if len(store.Lookup("app")) != 0 {
		t.Fatal("unsigned request mutated the store")
	}
	// A correctly signed request whose timestamp is outside the window.
	old := fixed.Add(-10 * time.Minute).Unix()
	req = httptest.NewRequest("GET", "/v1/records", nil)
	req.Header.Set(hmacauth.HeaderTimestamp, fmt.Sprintf("%d", old))
	req.Header.Set(hmacauth.HeaderSignature,
		hmacauth.Sign(testKey, "GET", "/v1/records", old, nil))
	if rec := do(h, req); rec.Code != http.StatusUnauthorized {
		t.Fatalf("stale: status %d, want 401", rec.Code)
	}
}

func TestTamperedBodyIs401WithOpaqueError(t *testing.T) {
	h, _ := newAPI(t)
	req := signedRequest("PUT", "/v1/records/app", `{"type":"A","value":"10.0.0.7"}`)
	// Swap the body after signing.
	req.Body = http.NoBody
	tampered := httptest.NewRequest("PUT", "/v1/records/app", strings.NewReader(`{"type":"A","value":"6.6.6.6"}`))
	tampered.Header = req.Header
	rec := do(h, tampered)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	// The error body must not reveal which check failed.
	if out := decodeBody(t, rec); out["error"] != "authentication failed" {
		t.Fatalf("error leaks detail: %v", out["error"])
	}
}

func TestPutRejectsBadPayloads(t *testing.T) {
	h, _ := newAPI(t)
	cases := map[string]string{
		"not json":      `{{{`,
		"unknown type":  `{"type":"MX","value":"mail"}`,
		"bad address":   `{"type":"A","value":"10.0.0.999"}`,
		"v6 in A":       `{"type":"A","value":"2001:db8::1"}`,
		"v4 in AAAA":    `{"type":"AAAA","value":"10.0.0.7"}`,
		"empty TXT":     `{"type":"TXT","value":""}`,
		"oversized TXT": fmt.Sprintf(`{"type":"TXT","value":%q}`, strings.Repeat("a", 256)),
	}
	for name, body := range cases {
		rec := do(h, signedRequest("PUT", "/v1/records/app", body))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, rec.Code)
		}
	}
	// Invalid owner names, including the apex, are rejected too.
	for _, path := range []string{
		"/v1/records/" + testZone,
		"/v1/records/bad!name",
		"/v1/records/-dash",
		"/v1/records/a.b.c.d",
	} {
		rec := do(h, signedRequest("PUT", path, `{"type":"A","value":"10.0.0.7"}`))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", path, rec.Code)
		}
	}
}

func TestDeleteRecordAndMissing404(t *testing.T) {
	h, store := newAPI(t)
	if err := store.Set("app", zone.Record{Type: dnswire.TypeA, Addr: netip.MustParseAddr("10.0.0.7")}); err != nil {
		t.Fatal(err)
	}
	if rec := do(h, signedRequest("DELETE", "/v1/records/app", "")); rec.Code != http.StatusOK {
		t.Fatalf("delete status %d", rec.Code)
	}
	if len(store.Lookup("app")) != 0 {
		t.Fatal("record survived delete")
	}
	if rec := do(h, signedRequest("DELETE", "/v1/records/app", "")); rec.Code != http.StatusNotFound {
		t.Fatalf("second delete status %d, want 404", rec.Code)
	}
}

func TestListReturnsSortedEntries(t *testing.T) {
	h, store := newAPI(t)
	for _, n := range []string{"zeta", "alpha"} {
		if err := store.Set(n, zone.Record{Type: dnswire.TypeA, Addr: netip.MustParseAddr("10.0.0.1")}); err != nil {
			t.Fatal(err)
		}
	}
	rec := do(h, signedRequest("GET", "/v1/records", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	entries := decodeBody(t, rec)["entries"].([]any)
	first := entries[0].(map[string]any)
	if len(entries) != 2 || first["name"] != "alpha" || first["fqdn"] != "alpha."+testZone {
		t.Fatalf("entries wrong: %v", entries)
	}
}

func TestAcmeSetCreatesChallengeTXT(t *testing.T) {
	h, store := newAPI(t)
	rec := do(h, signedRequest("PUT", "/v1/acme/app", `{"value":"tok-abc"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	got := store.Lookup("_acme-challenge.app")
	if len(got) != 1 || got[0].TXT[0] != "tok-abc" {
		t.Fatalf("challenge record wrong: %+v", got)
	}
	if out := decodeBody(t, rec); out["fqdn"] != "_acme-challenge.app."+testZone {
		t.Fatalf("fqdn: %v", out["fqdn"])
	}
	// "@" targets the zone apex: the challenge lands at the bare name.
	rec = do(h, signedRequest("PUT", "/v1/acme/@", `{"value":"tok-apex"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("apex status %d: %s", rec.Code, rec.Body)
	}
	if got := store.Lookup("_acme-challenge"); len(got) != 1 || got[0].TXT[0] != "tok-apex" {
		t.Fatalf("apex challenge wrong: %+v", got)
	}
}

func TestAcmeClearRemovesOnlyTheChallenge(t *testing.T) {
	h, store := newAPI(t)
	if err := store.Set("app", zone.Record{Type: dnswire.TypeA, Addr: netip.MustParseAddr("10.0.0.7")}); err != nil {
		t.Fatal(err)
	}
	if rec := do(h, signedRequest("PUT", "/v1/acme/app", `{"value":"tok"}`)); rec.Code != http.StatusOK {
		t.Fatalf("set status %d", rec.Code)
	}
	if rec := do(h, signedRequest("DELETE", "/v1/acme/app", "")); rec.Code != http.StatusOK {
		t.Fatalf("clear status %d", rec.Code)
	}
	if len(store.Lookup("_acme-challenge.app")) != 0 {
		t.Fatal("challenge survived clear")
	}
	if len(store.Lookup("app")) != 1 {
		t.Fatal("clear removed the app's A record")
	}
}

func TestMethodNotAllowed(t *testing.T) {
	h, _ := newAPI(t)
	for path, method := range map[string]string{
		"/healthz":        "POST",
		"/v1/records":     "PUT",
		"/v1/records/app": "POST",
		"/v1/acme/app":    "GET",
	} {
		rec := do(h, signedRequest(method, path, ""))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: status %d, want 405", method, path, rec.Code)
		}
	}
}

func TestOversizedBodyIs413(t *testing.T) {
	h, _ := newAPI(t)
	big := strings.Repeat("x", maxBody+1)
	rec := do(h, signedRequest("PUT", "/v1/records/app", big))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", rec.Code)
	}
}
