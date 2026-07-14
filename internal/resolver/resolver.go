// Package resolver turns one DNS question into an authoritative answer.
// Precedence is deliberate and documented: registered records beat magic
// IP extraction, which beats the wildcard fallback; anything outside the
// zone is REFUSED so hostwild can never be abused as an open resolver.
package resolver

import (
	"net/netip"
	"strings"

	"github.com/JaydenCJ/hostwild/internal/dnswire"
	"github.com/JaydenCJ/hostwild/internal/magic"
	"github.com/JaydenCJ/hostwild/internal/zone"
)

// Config fixes the zone-level answers.
type Config struct {
	Zone     string     // apex, canonical form, e.g. "dev.example.test"
	TTL      uint32     // answer TTL (seconds)
	NegTTL   uint32     // SOA minimum / negative-caching TTL
	ApexA    netip.Addr // optional A/AAAA for the apex and the NS host
	Fallback netip.Addr // optional catch-all for names nothing else matched
	NSHost   string     // authoritative server name; default "ns." + Zone
	Mbox     string     // SOA RNAME; default "hostmaster." + Zone
}

// withDefaults fills derived fields.
func (c Config) withDefaults() Config {
	if c.TTL == 0 {
		c.TTL = 60
	}
	if c.NegTTL == 0 {
		c.NegTTL = 60
	}
	if c.NSHost == "" {
		c.NSHost = "ns." + c.Zone
	}
	if c.Mbox == "" {
		c.Mbox = "hostmaster." + c.Zone
	}
	return c
}

// Resolver answers questions for exactly one zone.
type Resolver struct {
	cfg   Config
	store *zone.Store
}

// New builds a Resolver over the given store.
func New(cfg Config, store *zone.Store) *Resolver {
	return &Resolver{cfg: cfg.withDefaults(), store: store}
}

// Result is the resolver's verdict for one question.
type Result struct {
	RCode     uint8
	Answers   []dnswire.RR
	Authority []dnswire.RR
}

// Resolve answers a single question. The flow, in order:
//
//	out of zone            → REFUSED
//	apex                   → SOA / NS / apex address
//	registered record      → stored answer (dynamic API or --record seed)
//	magic IP in the labels → synthesized A/AAAA
//	fallback configured    → wildcard answer
//	otherwise              → NXDOMAIN with SOA in authority
func (r *Resolver) Resolve(q dnswire.Question) Result {
	name := dnswire.CanonicalName(q.Name)
	if q.Class != dnswire.ClassINET && q.Class != 255 {
		return r.negative(dnswire.RCodeRefused)
	}
	rel, ok := r.relative(name)
	if !ok {
		return r.negative(dnswire.RCodeRefused)
	}
	if rel == "" {
		return r.apex(q)
	}
	if rel == r.nsRel() && r.cfg.ApexA.IsValid() {
		return r.addressAnswer(name, q.Type, r.cfg.ApexA)
	}
	if recs := r.store.Lookup(rel); len(recs) > 0 {
		return r.stored(name, q.Type, recs)
	}
	if addr, ok := magic.Extract(strings.Split(rel, ".")); ok {
		return r.addressAnswer(name, q.Type, addr)
	}
	if r.cfg.Fallback.IsValid() {
		return r.addressAnswer(name, q.Type, r.cfg.Fallback)
	}
	return r.negative(dnswire.RCodeNXDomain)
}

// relative maps a canonical query name to its zone-relative form; ok is
// false when the name is outside the zone.
func (r *Resolver) relative(name string) (string, bool) {
	if name == r.cfg.Zone {
		return "", true
	}
	if strings.HasSuffix(name, "."+r.cfg.Zone) {
		return strings.TrimSuffix(name, "."+r.cfg.Zone), true
	}
	return "", false
}

// nsRel returns the NS host relative to the zone, or "" when it lives
// elsewhere.
func (r *Resolver) nsRel() string {
	if strings.HasSuffix(r.cfg.NSHost, "."+r.cfg.Zone) {
		return strings.TrimSuffix(r.cfg.NSHost, "."+r.cfg.Zone)
	}
	return ""
}

// soa builds the zone's SOA record with the live serial.
func (r *Resolver) soa() dnswire.RR {
	return dnswire.RR{
		Name: r.cfg.Zone, Type: dnswire.TypeSOA, Class: dnswire.ClassINET, TTL: r.cfg.NegTTL,
		Data: dnswire.SOAData{
			MName: r.cfg.NSHost, RName: r.cfg.Mbox,
			Serial: r.store.Serial(), Refresh: 7200, Retry: 900,
			Expire: 1209600, Minimum: r.cfg.NegTTL,
		},
	}
}

func (r *Resolver) ns() dnswire.RR {
	return dnswire.RR{
		Name: r.cfg.Zone, Type: dnswire.TypeNS, Class: dnswire.ClassINET, TTL: r.cfg.TTL,
		Data: dnswire.NSData{Host: r.cfg.NSHost},
	}
}

// apex answers questions for the zone name itself.
func (r *Resolver) apex(q dnswire.Question) Result {
	var res Result
	want := func(t uint16) bool { return q.Type == t || q.Type == dnswire.TypeANY }
	if want(dnswire.TypeSOA) {
		res.Answers = append(res.Answers, r.soa())
	}
	if want(dnswire.TypeNS) {
		res.Answers = append(res.Answers, r.ns())
	}
	if r.cfg.ApexA.IsValid() {
		if rr, ok := addressRR(r.cfg.Zone, q.Type, r.cfg.ApexA, r.cfg.TTL); ok {
			res.Answers = append(res.Answers, rr)
		}
	}
	if len(res.Answers) == 0 {
		// The name exists but not this type: NODATA (NOERROR + SOA).
		return r.negative(dnswire.RCodeNoError)
	}
	return res
}

// stored converts store records into answers matching the question type.
func (r *Resolver) stored(name string, qtype uint16, recs []zone.Record) Result {
	var res Result
	for _, rec := range recs {
		if qtype != rec.Type && qtype != dnswire.TypeANY {
			continue
		}
		ttl := rec.TTL
		if ttl == 0 {
			ttl = r.cfg.TTL
		}
		rr := dnswire.RR{Name: name, Type: rec.Type, Class: dnswire.ClassINET, TTL: ttl}
		switch rec.Type {
		case dnswire.TypeA:
			rr.Data = dnswire.AData{Addr: rec.Addr}
		case dnswire.TypeAAAA:
			rr.Data = dnswire.AAAAData{Addr: rec.Addr}
		case dnswire.TypeTXT:
			rr.Data = dnswire.TXTData{Strings: rec.TXT}
		default:
			continue
		}
		res.Answers = append(res.Answers, rr)
	}
	if len(res.Answers) == 0 {
		return r.negative(dnswire.RCodeNoError) // NODATA
	}
	return res
}

// addressAnswer answers an A or AAAA question with one synthesized
// address, or NODATA when the family does not match the question.
func (r *Resolver) addressAnswer(name string, qtype uint16, addr netip.Addr) Result {
	if rr, ok := addressRR(name, qtype, addr, r.cfg.TTL); ok {
		return Result{Answers: []dnswire.RR{rr}}
	}
	return r.negative(dnswire.RCodeNoError) // name exists, type does not
}

// addressRR builds the RR for addr when the question type matches its
// family (ANY matches both).
func addressRR(name string, qtype uint16, addr netip.Addr, ttl uint32) (dnswire.RR, bool) {
	is4 := addr.Is4() || addr.Is4In6()
	if is4 && (qtype == dnswire.TypeA || qtype == dnswire.TypeANY) {
		return dnswire.RR{
			Name: name, Type: dnswire.TypeA, Class: dnswire.ClassINET, TTL: ttl,
			Data: dnswire.AData{Addr: addr.Unmap()},
		}, true
	}
	if !is4 && (qtype == dnswire.TypeAAAA || qtype == dnswire.TypeANY) {
		return dnswire.RR{
			Name: name, Type: dnswire.TypeAAAA, Class: dnswire.ClassINET, TTL: ttl,
			Data: dnswire.AAAAData{Addr: addr},
		}, true
	}
	return dnswire.RR{}, false
}

// negative builds an empty-answer result carrying the SOA in authority,
// so resolvers can negative-cache per RFC 2308.
func (r *Resolver) negative(rcode uint8) Result {
	res := Result{RCode: rcode}
	if rcode == dnswire.RCodeNXDomain || rcode == dnswire.RCodeNoError {
		res.Authority = []dnswire.RR{r.soa()}
	}
	return res
}
