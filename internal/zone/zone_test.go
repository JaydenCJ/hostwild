// Store tests: mutation semantics (per-type replace, typed delete),
// serial discipline, name validation, and crash-safe JSON persistence
// across restarts.
package zone

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/JaydenCJ/hostwild/internal/dnswire"
)

func aRec(ip string) Record {
	return Record{Type: dnswire.TypeA, Addr: netip.MustParseAddr(ip)}
}

func TestSetReplacesSameTypeKeepsOthers(t *testing.T) {
	s := NewStore("")
	if err := s.Set("app", aRec("10.0.0.1")); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("app", Record{Type: dnswire.TypeTXT, TXT: []string{"x"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("app", aRec("10.0.0.2")); err != nil {
		t.Fatal(err)
	}
	recs := s.Lookup("app")
	if len(recs) != 2 {
		t.Fatalf("want TXT + replaced A, got %d records", len(recs))
	}
	for _, r := range recs {
		if r.Type == dnswire.TypeA && r.Addr != netip.MustParseAddr("10.0.0.2") {
			t.Fatalf("A record not replaced: %s", r.Addr)
		}
	}
}

func TestDeleteTypedRemovesOnlyThatType(t *testing.T) {
	s := NewStore("")
	if err := s.Set("app", aRec("10.0.0.1")); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("app", Record{Type: dnswire.TypeTXT, TXT: []string{"x"}}); err != nil {
		t.Fatal(err)
	}
	removed, err := s.Delete("app", dnswire.TypeTXT)
	if err != nil || !removed {
		t.Fatalf("typed delete: removed=%v err=%v", removed, err)
	}
	recs := s.Lookup("app")
	if len(recs) != 1 || recs[0].Type != dnswire.TypeA {
		t.Fatalf("want the A record to survive, got %+v", recs)
	}
}

func TestDeleteAllAndMissing(t *testing.T) {
	s := NewStore("")
	if err := s.Set("app", aRec("10.0.0.1")); err != nil {
		t.Fatal(err)
	}
	if removed, _ := s.Delete("app", 0); !removed {
		t.Fatal("delete-all reported nothing removed")
	}
	if recs := s.Lookup("app"); recs != nil {
		t.Fatalf("records survived delete: %+v", recs)
	}
	if removed, _ := s.Delete("app", 0); removed {
		t.Fatal("second delete claimed to remove something")
	}
}

func TestSerialBumpsOnEveryMutationOnly(t *testing.T) {
	s := NewStore("")
	start := s.Serial()
	if err := s.Set("a", aRec("10.0.0.1")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Delete("a", 0); err != nil {
		t.Fatal(err)
	}
	if got := s.Serial(); got != start+2 {
		t.Fatalf("serial %d, want %d", got, start+2)
	}
	// A no-op delete must not burn a serial.
	if _, err := s.Delete("ghost", 0); err != nil {
		t.Fatal(err)
	}
	if got := s.Serial(); got != start+2 {
		t.Fatalf("no-op delete bumped serial to %d", got)
	}
}

func TestLookupIsCaseInsensitiveAndCopies(t *testing.T) {
	s := NewStore("")
	if err := s.Set("App", aRec("10.0.0.1")); err != nil {
		t.Fatal(err)
	}
	recs := s.Lookup("APP")
	if len(recs) != 1 {
		t.Fatal("case-insensitive lookup failed")
	}
	recs[0].Addr = netip.MustParseAddr("10.9.9.9") // mutate the copy
	if s.Lookup("app")[0].Addr != netip.MustParseAddr("10.0.0.1") {
		t.Fatal("Lookup leaked internal state")
	}
}

func TestValidateNameRules(t *testing.T) {
	good := []string{"app", "app-1", "a.b", "_acme-challenge.app", "x_y", "0", "a.b.c"}
	for _, n := range good {
		if err := ValidateName(n); err != nil {
			t.Errorf("ValidateName(%q) = %v, want ok", n, err)
		}
	}
	bad := []string{"", "-app", "app-", "a..b", "App", "a b", "a.b.c.d", "sub/../etc"}
	for _, n := range bad {
		if err := ValidateName(n); err == nil {
			t.Errorf("ValidateName(%q) accepted", n)
		}
	}
}

func TestPersistAndLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s := NewStore(path)
	if err := s.Set("app", aRec("10.0.0.1")); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("v6", Record{Type: dnswire.TypeAAAA, Addr: netip.MustParseAddr("2001:db8::1"), TTL: 90}); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("_acme-challenge.app", Record{Type: dnswire.TypeTXT, TXT: []string{"tok"}}); err != nil {
		t.Fatal(err)
	}

	restored := NewStore(path)
	if err := restored.Load(); err != nil {
		t.Fatal(err)
	}
	if restored.Serial() != s.Serial() {
		t.Fatalf("serial lost: %d != %d", restored.Serial(), s.Serial())
	}
	if got := restored.Lookup("v6"); len(got) != 1 || got[0].TTL != 90 ||
		got[0].Addr != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("AAAA record mangled: %+v", got)
	}
	if got := restored.Lookup("_acme-challenge.app"); len(got) != 1 || got[0].TXT[0] != "tok" {
		t.Fatalf("TXT record mangled: %+v", got)
	}
}

func TestLoadMissingFileStartsEmptyButCorruptFails(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "absent.json"))
	if err := s.Load(); err != nil {
		t.Fatalf("missing state file should not error: %v", err)
	}
	if len(s.Names()) != 0 {
		t.Fatal("store not empty")
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := NewStore(path).Load(); err == nil {
		t.Fatal("corrupt state file loaded silently")
	}
}

func TestNamesSorted(t *testing.T) {
	s := NewStore("")
	for _, n := range []string{"zeta", "alpha", "mid"} {
		if err := s.Set(n, aRec("10.0.0.1")); err != nil {
			t.Fatal(err)
		}
	}
	names := s.Names()
	if names[0] != "alpha" || names[1] != "mid" || names[2] != "zeta" {
		t.Fatalf("names not sorted: %v", names)
	}
}
