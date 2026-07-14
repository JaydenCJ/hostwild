// Command hostwild is a self-hosted wildcard dev DNS server: nip.io-style
// magic hostnames plus an HMAC-authenticated dynamic-update API and a
// DNS-01 challenge helper, in one stdlib-only binary.
package main

import (
	"os"

	"github.com/JaydenCJ/hostwild/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
