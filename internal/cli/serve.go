package cli

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/JaydenCJ/hostwild/internal/api"
	"github.com/JaydenCJ/hostwild/internal/dnswire"
	"github.com/JaydenCJ/hostwild/internal/resolver"
	"github.com/JaydenCJ/hostwild/internal/server"
	"github.com/JaydenCJ/hostwild/internal/version"
	"github.com/JaydenCJ/hostwild/internal/zone"
)

// multiFlag is a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// runServe starts the DNS responder (UDP+TCP) and, unless disabled, the
// dynamic-update HTTP API. It prints the concrete bound addresses so
// `--dns 127.0.0.1:0` is scriptable.
func runServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	var (
		zoneName = fs.String("zone", "", "zone apex to serve, e.g. dev.example.test (required)")
		dnsAddr  = fs.String("dns", "127.0.0.1:5353", "DNS listen address (UDP and TCP)")
		httpAddr = fs.String("http", "127.0.0.1:8053", "update-API listen address")
		noHTTP   = fs.Bool("no-http", false, "disable the update API entirely")
		ttl      = fs.Uint("ttl", 60, "answer TTL in seconds")
		negTTL   = fs.Uint("neg-ttl", 60, "negative-caching (SOA minimum) TTL in seconds")
		apex     = fs.String("apex", "", "address to answer for the zone apex and its NS host")
		fallback = fs.String("fallback", "", "catch-all address for unmatched names")
		nsHost   = fs.String("ns", "", "authoritative server name (default ns.<zone>)")
		state    = fs.String("state", "", "JSON file persisting dynamic records across restarts")
		window   = fs.Duration("auth-window", 5*time.Minute, "HMAC timestamp acceptance window")
		records  multiFlag
		keys     keyFlags
	)
	fs.Var(&records, "record", "seed a static record, name=address (repeatable)")
	keys.register(fs)
	if !parseFlags(fs, args, stderr) {
		return ExitUsage
	}
	if *zoneName == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "hostwild serve: --zone is required and takes no positional arguments")
		return ExitUsage
	}

	cfg := resolver.Config{
		Zone:   dnswire.CanonicalName(*zoneName),
		TTL:    uint32(*ttl),
		NegTTL: uint32(*negTTL),
		NSHost: dnswire.CanonicalName(*nsHost),
	}
	var err error
	if cfg.ApexA, err = optionalAddr(*apex); err != nil {
		fmt.Fprintf(stderr, "hostwild serve: --apex: %v\n", err)
		return ExitUsage
	}
	if cfg.Fallback, err = optionalAddr(*fallback); err != nil {
		fmt.Fprintf(stderr, "hostwild serve: --fallback: %v\n", err)
		return ExitUsage
	}

	store := zone.NewStore(*state)
	if err := store.Load(); err != nil {
		fmt.Fprintf(stderr, "hostwild serve: %v\n", err)
		return ExitRuntime
	}
	if err := seedRecords(store, records); err != nil {
		fmt.Fprintf(stderr, "hostwild serve: %v\n", err)
		return ExitUsage
	}

	var key []byte
	if !*noHTTP {
		if key, err = keys.resolveKey(); err != nil {
			fmt.Fprintf(stderr, "hostwild serve: %v (or pass --no-http)\n", err)
			return ExitUsage
		}
	}

	srv := &server.Server{
		Resolver: resolver.New(cfg, store),
		Logger:   log.New(stderr, "hostwild: ", log.LstdFlags),
	}
	udpAddr, err := srv.ListenUDP(*dnsAddr)
	if err != nil {
		fmt.Fprintf(stderr, "hostwild serve: %v\n", err)
		return ExitRuntime
	}
	defer srv.Close()
	// Reuse the concrete UDP port for TCP so `--dns host:0` yields one
	// port for both transports.
	tcpAddr, err := srv.ListenTCP(udpAddr.String())
	if err != nil {
		fmt.Fprintf(stderr, "hostwild serve: %v\n", err)
		return ExitRuntime
	}

	fmt.Fprintf(stdout, "hostwild %s — zone %s\n", version.Version, cfg.Zone)
	fmt.Fprintf(stdout, "dns   udp %s\n", udpAddr)
	fmt.Fprintf(stdout, "dns   tcp %s\n", tcpAddr)

	errs := make(chan error, 3)
	go func() { errs <- srv.ServeUDP() }()
	go func() { errs <- srv.ServeTCP() }()

	if !*noHTTP {
		handler := api.New(store, cfg.Zone, key, *window, nil)
		ln, err := net.Listen("tcp", *httpAddr)
		if err != nil {
			fmt.Fprintf(stderr, "hostwild serve: %v\n", err)
			return ExitRuntime
		}
		fmt.Fprintf(stdout, "http  http://%s\n", ln.Addr())
		httpSrv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
		defer httpSrv.Close()
		go func() { errs <- httpSrv.Serve(ln) }()
	}
	fmt.Fprintln(stdout, "ready")

	if err := <-errs; err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(stderr, "hostwild serve: %v\n", err)
		return ExitRuntime
	}
	return ExitOK
}

// optionalAddr parses an address flag that may be empty.
func optionalAddr(s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, err
	}
	return a.Unmap(), nil
}

// seedRecords loads `--record name=address` seeds into the store.
func seedRecords(store *zone.Store, seeds []string) error {
	for _, s := range seeds {
		name, val, ok := strings.Cut(s, "=")
		if !ok {
			return fmt.Errorf("--record %q: want name=address", s)
		}
		addr, err := netip.ParseAddr(val)
		if err != nil {
			return fmt.Errorf("--record %q: %v", s, err)
		}
		addr = addr.Unmap()
		rec := zone.Record{Type: dnswire.TypeA, Addr: addr}
		if addr.Is6() {
			rec.Type = dnswire.TypeAAAA
		}
		if err := store.Set(dnswire.CanonicalName(name), rec); err != nil {
			return fmt.Errorf("--record %q: %v", s, err)
		}
	}
	return nil
}
