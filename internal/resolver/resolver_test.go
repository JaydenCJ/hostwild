// Resolver tests pin the answer-precedence contract: registered records
// beat magic extraction, magic beats the fallback, out-of-zone names are
// REFUSED, and every negative answer carries the SOA so resolvers can
// negative-cache.
package resolver

import (
	"net/netip"
	"testing"

	"github.com/JaydenCJ/hostwild/internal/dnswire"
	"github.com/JaydenCJ/hostwild/internal/zone"
)

const testZone = "dev.example.test"

func newResolver(t *testing.T, cfg Config) (*Resolver, *zone.Store) {
	t.Helper()
	cfg.Zone = testZone
	store := zone.NewStore("")
	return New(cfg, store), store
}

func ask(r *Resolver, name string, qtype uint16) Result {
	return r.Resolve(dnswire.Question{Name: name, Type: qtype, Class: dnswire.ClassINET})
}

func onlyA(t *testing.T, res Result, want string) {
	t.Helper()
	if res.RCode != dnswire.RCodeNoError || len(res.Answers) != 1 {
		t.Fatalf("want one NOERROR answer, got rcode=%s answers=%d",
			dnswire.RCodeName(res.RCode), len(res.Answers))
	}
	a, ok := res.Answers[0].Data.(dnswire.AData)
	if !ok {
		t.Fatalf("answer is %T, want AData", res.Answers[0].Data)
	}
	if a.Addr != netip.MustParseAddr(want) {
		t.Fatalf("answer %s, want %s", a.Addr, want)
	}
}

func TestMagicNamesResolve(t *testing.T) {
	r, _ := newResolver(t, Config{})
	onlyA(t, ask(r, "10.0.0.7."+testZone, dnswire.TypeA), "10.0.0.7")
	onlyA(t, ask(r, "app-192-168-1-9."+testZone, dnswire.TypeA), "192.168.1.9")
	res := ask(r, "2001-db8--7."+testZone, dnswire.TypeAAAA)
	if len(res.Answers) != 1 {
		t.Fatalf("IPv6: want one answer, got %d", len(res.Answers))
	}
	if got := res.Answers[0].Data.(dnswire.AAAAData).Addr; got != netip.MustParseAddr("2001:db8::7") {
		t.Fatalf("IPv6: got %s", got)
	}
}

func TestMagicIPv4NameQueriedForAAAAIsNodata(t *testing.T) {
	// The name exists (it encodes an IPv4), so AAAA must be NODATA —
	// NOERROR with zero answers and the SOA in authority — not NXDOMAIN,
	// or happy-eyeballs clients would wrongly drop the A too.
	r, _ := newResolver(t, Config{})
	res := ask(r, "10.0.0.7."+testZone, dnswire.TypeAAAA)
	if res.RCode != dnswire.RCodeNoError || len(res.Answers) != 0 {
		t.Fatalf("want NODATA, got rcode=%s answers=%d", dnswire.RCodeName(res.RCode), len(res.Answers))
	}
	if len(res.Authority) != 1 || res.Authority[0].Type != dnswire.TypeSOA {
		t.Fatal("NODATA must carry the SOA in authority")
	}
}

func TestOutOfZoneIsRefused(t *testing.T) {
	r, _ := newResolver(t, Config{})
	for _, name := range []string{"10.0.0.7.other.example", "example.test", "evil-dev.example.test"} {
		if res := ask(r, name, dnswire.TypeA); res.RCode != dnswire.RCodeRefused {
			t.Errorf("%q: rcode=%s, want REFUSED", name, dnswire.RCodeName(res.RCode))
		}
	}
}

func TestUnknownNameIsNXDomainWithSOA(t *testing.T) {
	r, _ := newResolver(t, Config{})
	res := ask(r, "nothing-here."+testZone, dnswire.TypeA)
	if res.RCode != dnswire.RCodeNXDomain {
		t.Fatalf("rcode=%s, want NXDOMAIN", dnswire.RCodeName(res.RCode))
	}
	if len(res.Authority) != 1 || res.Authority[0].Type != dnswire.TypeSOA {
		t.Fatal("NXDOMAIN must carry the SOA in authority")
	}
}

func TestRegisteredRecordBeatsMagic(t *testing.T) {
	// "app-10-0-0-7" would magically resolve to 10.0.0.7, but an explicit
	// registration must win — that is the whole point of the API.
	r, store := newResolver(t, Config{})
	rec := zone.Record{Type: dnswire.TypeA, Addr: netip.MustParseAddr("192.0.2.99")}
	if err := store.Set("app-10-0-0-7", rec); err != nil {
		t.Fatal(err)
	}
	onlyA(t, ask(r, "app-10-0-0-7."+testZone, dnswire.TypeA), "192.0.2.99")
}

func TestFallbackAnswersOnlyUnmatchedNames(t *testing.T) {
	r, _ := newResolver(t, Config{Fallback: netip.MustParseAddr("10.9.9.9")})
	onlyA(t, ask(r, "anything."+testZone, dnswire.TypeA), "10.9.9.9")
	// Magic extraction still beats the catch-all.
	onlyA(t, ask(r, "10.0.0.7."+testZone, dnswire.TypeA), "10.0.0.7")
}

func TestApexSOAAndNS(t *testing.T) {
	r, store := newResolver(t, Config{})
	res := ask(r, testZone, dnswire.TypeSOA)
	if len(res.Answers) != 1 {
		t.Fatalf("want SOA answer, got %d answers", len(res.Answers))
	}
	soa := res.Answers[0].Data.(dnswire.SOAData)
	if soa.MName != "ns."+testZone || soa.Serial != store.Serial() {
		t.Fatalf("SOA fields wrong: %+v", soa)
	}
	res = ask(r, testZone, dnswire.TypeNS)
	if len(res.Answers) != 1 || res.Answers[0].Data.(dnswire.NSData).Host != "ns."+testZone {
		t.Fatalf("NS answer wrong: %+v", res.Answers)
	}
}

func TestApexAAndNSHostAnswerWhenConfigured(t *testing.T) {
	r, _ := newResolver(t, Config{ApexA: netip.MustParseAddr("203.0.113.5")})
	onlyA(t, ask(r, testZone, dnswire.TypeA), "203.0.113.5")
	onlyA(t, ask(r, "ns."+testZone, dnswire.TypeA), "203.0.113.5")
}

func TestApexWithoutAddressIsNodataForA(t *testing.T) {
	r, _ := newResolver(t, Config{})
	res := ask(r, testZone, dnswire.TypeA)
	if res.RCode != dnswire.RCodeNoError || len(res.Answers) != 0 {
		t.Fatalf("want NODATA at apex, got rcode=%s answers=%d",
			dnswire.RCodeName(res.RCode), len(res.Answers))
	}
}

func TestAcmeChallengeTXTResolves(t *testing.T) {
	r, store := newResolver(t, Config{})
	rec := zone.Record{Type: dnswire.TypeTXT, TXT: []string{"tok-abc123"}, TTL: 30}
	if err := store.Set("_acme-challenge.app", rec); err != nil {
		t.Fatal(err)
	}
	res := ask(r, "_acme-challenge.app."+testZone, dnswire.TypeTXT)
	if len(res.Answers) != 1 {
		t.Fatalf("want TXT answer, got %d", len(res.Answers))
	}
	txt := res.Answers[0].Data.(dnswire.TXTData)
	if txt.Strings[0] != "tok-abc123" || res.Answers[0].TTL != 30 {
		t.Fatalf("TXT wrong: %+v ttl=%d", txt, res.Answers[0].TTL)
	}
}

func TestQueryNameMatchingIsCaseInsensitive(t *testing.T) {
	r, _ := newResolver(t, Config{})
	onlyA(t, ask(r, "10.0.0.7.DEV.Example.TEST.", dnswire.TypeA), "10.0.0.7")
}

func TestAnyQueryReturnsMatchingFamilies(t *testing.T) {
	r, store := newResolver(t, Config{})
	if err := store.Set("dual", zone.Record{Type: dnswire.TypeA, Addr: netip.MustParseAddr("10.1.1.1")}); err != nil {
		t.Fatal(err)
	}
	if err := store.Set("dual", zone.Record{Type: dnswire.TypeAAAA, Addr: netip.MustParseAddr("2001:db8::1")}); err != nil {
		t.Fatal(err)
	}
	res := ask(r, "dual."+testZone, dnswire.TypeANY)
	if len(res.Answers) != 2 {
		t.Fatalf("ANY returned %d answers, want 2", len(res.Answers))
	}
}

func TestNonINClassIsRefused(t *testing.T) {
	r, _ := newResolver(t, Config{})
	res := r.Resolve(dnswire.Question{Name: "10.0.0.7." + testZone, Type: dnswire.TypeA, Class: 3}) // CHAOS
	if res.RCode != dnswire.RCodeRefused {
		t.Fatalf("CHAOS class rcode=%s, want REFUSED", dnswire.RCodeName(res.RCode))
	}
}

func TestStoredTTLDefaultsToZoneTTL(t *testing.T) {
	r, store := newResolver(t, Config{TTL: 120})
	if err := store.Set("app", zone.Record{Type: dnswire.TypeA, Addr: netip.MustParseAddr("10.1.1.1")}); err != nil {
		t.Fatal(err)
	}
	res := ask(r, "app."+testZone, dnswire.TypeA)
	if res.Answers[0].TTL != 120 {
		t.Fatalf("TTL %d, want zone default 120", res.Answers[0].TTL)
	}
}
