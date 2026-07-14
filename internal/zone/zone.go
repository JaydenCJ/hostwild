// Package zone holds the mutable record store behind a hostwild zone:
// operator-seeded static records, records registered through the dynamic
// API, and DNS-01 challenge TXT records. The store is safe for concurrent
// use, bumps the SOA serial on every mutation, and can persist itself as
// deterministic JSON so registrations survive a restart.
package zone

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/JaydenCJ/hostwild/internal/dnswire"
)

// Record is one stored answer, keyed by its owner name relative to the
// zone apex ("" means the apex itself).
type Record struct {
	Type uint16     `json:"-"`
	Addr netip.Addr `json:"-"`
	TXT  []string   `json:"-"`
	TTL  uint32     `json:"ttl,omitempty"`
}

// recordJSON is the stable on-disk shape of a Record.
type recordJSON struct {
	Type  string   `json:"type"`
	Value string   `json:"value,omitempty"`
	TXT   []string `json:"txt,omitempty"`
	TTL   uint32   `json:"ttl,omitempty"`
}

// MarshalJSON renders the presentation form ("A" + dotted quad).
func (r Record) MarshalJSON() ([]byte, error) {
	j := recordJSON{Type: dnswire.TypeName(r.Type), TTL: r.TTL}
	switch r.Type {
	case dnswire.TypeA, dnswire.TypeAAAA:
		j.Value = r.Addr.String()
	case dnswire.TypeTXT:
		j.TXT = r.TXT
	default:
		return nil, fmt.Errorf("zone: cannot marshal record type %d", r.Type)
	}
	return json.Marshal(j)
}

// UnmarshalJSON parses the presentation form back.
func (r *Record) UnmarshalJSON(b []byte) error {
	var j recordJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	t, ok := dnswire.ParseType(j.Type)
	if !ok {
		return fmt.Errorf("zone: unknown record type %q", j.Type)
	}
	rec := Record{Type: t, TTL: j.TTL}
	switch t {
	case dnswire.TypeA, dnswire.TypeAAAA:
		a, err := netip.ParseAddr(j.Value)
		if err != nil {
			return fmt.Errorf("zone: bad address %q: %w", j.Value, err)
		}
		rec.Addr = a
	case dnswire.TypeTXT:
		rec.TXT = j.TXT
	default:
		return fmt.Errorf("zone: unsupported stored type %q", j.Type)
	}
	*r = rec
	return nil
}

// Store is the concurrent record store for one zone.
type Store struct {
	mu      sync.RWMutex
	records map[string][]Record // relative owner name → records
	serial  uint32
	path    string // persistence file, "" = memory only
}

// NewStore creates an empty store. If path is non-empty, mutations are
// persisted there and Load can restore them.
func NewStore(path string) *Store {
	return &Store{records: make(map[string][]Record), serial: 1, path: path}
}

// ErrBadName reports an owner name the store refuses to hold.
var ErrBadName = errors.New("zone: invalid record name")

// ValidateName checks a relative owner name: 1-3 dot-separated labels of
// [a-z0-9_-], each 1-63 chars, not starting or ending with '-'. The empty
// string (the apex) is rejected here — apex answers are configured, not
// registered.
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: empty name", ErrBadName)
	}
	labels := strings.Split(name, ".")
	if len(labels) > 3 {
		return fmt.Errorf("%w: more than 3 labels in %q", ErrBadName, name)
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return fmt.Errorf("%w: bad label length in %q", ErrBadName, name)
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("%w: label starts or ends with '-' in %q", ErrBadName, name)
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
			if !ok {
				return fmt.Errorf("%w: character %q in %q", ErrBadName, string(c), name)
			}
		}
	}
	return nil
}

// Set replaces all records of rec.Type at name with rec, creating the
// entry if needed, and bumps the serial.
func (s *Store) Set(name string, rec Record) error {
	name = strings.ToLower(name)
	if err := ValidateName(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.records[name][:0:0]
	for _, r := range s.records[name] {
		if r.Type != rec.Type {
			kept = append(kept, r)
		}
	}
	s.records[name] = append(kept, rec)
	s.serial++
	return s.persistLocked()
}

// Delete removes records at name; if typ is 0 all types go, otherwise only
// that type. It reports whether anything was removed.
func (s *Store) Delete(name string, typ uint16) (bool, error) {
	name = strings.ToLower(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.records[name]
	if !ok {
		return false, nil
	}
	var kept []Record
	if typ != 0 {
		for _, r := range old {
			if r.Type != typ {
				kept = append(kept, r)
			}
		}
	}
	if len(kept) == len(old) {
		return false, nil
	}
	if len(kept) == 0 {
		delete(s.records, name)
	} else {
		s.records[name] = kept
	}
	s.serial++
	return true, s.persistLocked()
}

// Lookup returns a copy of the records stored at the relative name.
func (s *Store) Lookup(name string) []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	recs := s.records[strings.ToLower(name)]
	if len(recs) == 0 {
		return nil
	}
	return append([]Record(nil), recs...)
}

// Names returns all owner names, sorted, for deterministic listings.
func (s *Store) Names() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.records))
	for n := range s.records {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Serial returns the current SOA serial. It starts at 1 and increments on
// every successful mutation.
func (s *Store) Serial() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serial
}

// snapshot is the on-disk file shape.
type snapshot struct {
	Serial  uint32              `json:"serial"`
	Records map[string][]Record `json:"records"`
}

// persistLocked writes the store atomically (tmp file + rename). Callers
// hold s.mu.
func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	snap := snapshot{Serial: s.serial, Records: s.records}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Load restores a previously persisted snapshot. A missing file is not an
// error — the store simply starts empty.
func (s *Store) Load() error {
	if s.path == "" {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("zone: corrupt state file %s: %w", s.path, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if snap.Records != nil {
		s.records = snap.Records
	}
	if snap.Serial > 0 {
		s.serial = snap.Serial
	}
	return nil
}
