// Package api serves the dynamic-update HTTP API: register and remove
// records under the zone, and set or clear DNS-01 challenge TXT records.
// Every mutating or listing route requires an HMAC signature; only
// /healthz is open. The API binds loopback by default and never initiates
// outbound connections.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/JaydenCJ/hostwild/internal/dnswire"
	"github.com/JaydenCJ/hostwild/internal/hmacauth"
	"github.com/JaydenCJ/hostwild/internal/version"
	"github.com/JaydenCJ/hostwild/internal/zone"
)

// maxBody caps request bodies; record payloads are tiny.
const maxBody = 16 << 10

// AcmePrefix is the label prepended to a name for DNS-01 challenges.
const AcmePrefix = "_acme-challenge"

// Handler is the API's http.Handler.
type Handler struct {
	store  *zone.Store
	zone   string
	key    []byte
	window time.Duration
	now    func() time.Time
	mux    *http.ServeMux
}

// New builds the API handler. now may be nil (wall clock); it exists so
// tests can pin time.
func New(store *zone.Store, zoneName string, key []byte, window time.Duration, now func() time.Time) *Handler {
	if now == nil {
		now = time.Now
	}
	h := &Handler{store: store, zone: zoneName, key: key, window: window, now: now}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", h.health)
	mux.HandleFunc("/v1/records", h.list)
	mux.HandleFunc("/v1/records/", h.record)
	mux.HandleFunc("/v1/acme/", h.acme)
	h.mux = mux
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// writeJSON emits a JSON body with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

type errorBody struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	writeJSON(w, status, errorBody{Error: fmt.Sprintf(format, args...)})
}

// authenticate reads the body (bounded), verifies the HMAC headers, and
// returns the body on success. On failure it writes the response itself
// and returns ok=false. The 401 body is identical for every failure mode
// so the API leaks nothing about which check tripped.
func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "unreadable body")
		return nil, false
	}
	if len(body) > maxBody {
		writeError(w, http.StatusRequestEntityTooLarge, "body exceeds %d bytes", maxBody)
		return nil, false
	}
	err = hmacauth.Verify(h.key, r.Method, r.URL.Path,
		r.Header.Get(hmacauth.HeaderTimestamp), r.Header.Get(hmacauth.HeaderSignature),
		body, h.now(), h.window)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication failed")
		return nil, false
	}
	return body, true
}

// health is the only unauthenticated route.
func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method %s not allowed", r.Method)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "version": version.Version, "zone": h.zone,
		"serial": h.store.Serial(),
	})
}

// list returns every registered record, sorted by name.
func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method %s not allowed", r.Method)
		return
	}
	if _, ok := h.authenticate(w, r); !ok {
		return
	}
	type entry struct {
		Name    string        `json:"name"`
		FQDN    string        `json:"fqdn"`
		Records []zone.Record `json:"records"`
	}
	out := []entry{}
	for _, name := range h.store.Names() {
		out = append(out, entry{
			Name: name, FQDN: name + "." + h.zone,
			Records: h.store.Lookup(name),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"zone": h.zone, "entries": out})
}

// relName extracts and normalizes the {name} path segment after prefix.
// A fully-qualified name ending in the zone is accepted and made relative,
// so clients can pass either "app" or "app.dev.example.test".
func (h *Handler) relName(path, prefix string) (string, error) {
	name := strings.ToLower(strings.TrimPrefix(path, prefix))
	name = strings.TrimSuffix(name, ".")
	if suffix := "." + h.zone; strings.HasSuffix(name, suffix) {
		name = strings.TrimSuffix(name, suffix)
	} else if name == h.zone {
		return "", fmt.Errorf("cannot register the zone apex")
	}
	if err := zone.ValidateName(name); err != nil {
		return "", err
	}
	return name, nil
}

// recordRequest is the PUT /v1/records/{name} payload.
type recordRequest struct {
	Type  string `json:"type"`          // "A", "AAAA", or "TXT"
	Value string `json:"value"`         // address or TXT string
	TTL   uint32 `json:"ttl,omitempty"` // 0 = zone default
}

// record handles PUT and DELETE on /v1/records/{name}.
func (h *Handler) record(w http.ResponseWriter, r *http.Request) {
	body, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	name, err := h.relName(r.URL.Path, "/v1/records/")
	if err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var req recordRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "bad JSON: %s", err)
			return
		}
		rec, err := buildRecord(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, "%s", err)
			return
		}
		if err := h.store.Set(name, rec); err != nil {
			writeError(w, http.StatusInternalServerError, "store: %s", err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"name": name, "fqdn": name + "." + h.zone,
			"type": strings.ToUpper(req.Type), "serial": h.store.Serial(),
		})
	case http.MethodDelete:
		removed, err := h.store.Delete(name, 0)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "store: %s", err)
			return
		}
		if !removed {
			writeError(w, http.StatusNotFound, "no records at %q", name)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"name": name, "deleted": true, "serial": h.store.Serial()})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method %s not allowed", r.Method)
	}
}

// buildRecord validates a recordRequest into a store record.
func buildRecord(req recordRequest) (zone.Record, error) {
	switch strings.ToUpper(req.Type) {
	case "A", "AAAA":
		addr, err := netip.ParseAddr(req.Value)
		if err != nil {
			return zone.Record{}, fmt.Errorf("bad address %q", req.Value)
		}
		if strings.ToUpper(req.Type) == "A" {
			if !addr.Is4() && !addr.Is4In6() {
				return zone.Record{}, errors.New("A record needs an IPv4 address")
			}
			return zone.Record{Type: dnswire.TypeA, Addr: addr.Unmap(), TTL: req.TTL}, nil
		}
		if !addr.Is6() || addr.Is4In6() {
			return zone.Record{}, errors.New("AAAA record needs an IPv6 address")
		}
		return zone.Record{Type: dnswire.TypeAAAA, Addr: addr, TTL: req.TTL}, nil
	case "TXT":
		if req.Value == "" || len(req.Value) > 255 {
			return zone.Record{}, errors.New("TXT value must be 1-255 bytes")
		}
		return zone.Record{Type: dnswire.TypeTXT, TXT: []string{req.Value}, TTL: req.TTL}, nil
	default:
		return zone.Record{}, fmt.Errorf("unsupported type %q (want A, AAAA, or TXT)", req.Type)
	}
}

// acmeRequest is the PUT /v1/acme/{name} payload. Value is the exact TXT
// string the CA must see (for Let's Encrypt: base64url(sha256(keyAuth))).
type acmeRequest struct {
	Value string `json:"value"`
}

// acme handles PUT and DELETE on /v1/acme/{name}: it manages the TXT
// record at _acme-challenge.{name} so DNS-01 validation can complete.
// Passing "@" (or the zone itself) targets the apex challenge name.
func (h *Handler) acme(w http.ResponseWriter, r *http.Request) {
	body, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	raw := strings.ToLower(strings.TrimPrefix(r.URL.Path, "/v1/acme/"))
	raw = strings.TrimSuffix(raw, ".")
	if suffix := "." + h.zone; strings.HasSuffix(raw, suffix) {
		raw = strings.TrimSuffix(raw, suffix)
	}
	owner := AcmePrefix
	if raw != "@" && raw != "" && raw != h.zone {
		owner = AcmePrefix + "." + raw
	}
	if err := zone.ValidateName(owner); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var req acmeRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "bad JSON: %s", err)
			return
		}
		if req.Value == "" || len(req.Value) > 255 {
			writeError(w, http.StatusBadRequest, "value must be 1-255 bytes")
			return
		}
		rec := zone.Record{Type: dnswire.TypeTXT, TXT: []string{req.Value}, TTL: 30}
		if err := h.store.Set(owner, rec); err != nil {
			writeError(w, http.StatusInternalServerError, "store: %s", err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"fqdn": owner + "." + h.zone, "serial": h.store.Serial(),
		})
	case http.MethodDelete:
		removed, err := h.store.Delete(owner, dnswire.TypeTXT)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "store: %s", err)
			return
		}
		if !removed {
			writeError(w, http.StatusNotFound, "no challenge at %q", owner)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"fqdn": owner + "." + h.zone, "deleted": true})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method %s not allowed", r.Method)
	}
}
