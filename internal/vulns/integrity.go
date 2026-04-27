// Package vulns — integrity.go provides SHA-256 fingerprinting of the embedded
// CVE database to detect silent tampering with the bundled vulnerability rules.
package vulns

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// dbExpectedHash is the SHA-256 fingerprint of the bundled CVE database.
// Regenerate with: recon-x -db-hash
// Any modification to db[] without updating this constant causes startup failure.
const dbExpectedHash = "99450bba69662261f02a09c00e4d4b01991c6d88c7627417b9ee59f45b8bae67"

func init() {
	verifyDB()
}

func verifyDB() {
	if dbExpectedHash == "TBD" {
		return // initial build — hash not yet stamped
	}
	got := ComputeDBHash()
	if got != dbExpectedHash {
		fmt.Fprintf(os.Stderr, "\n  [FATAL] CVE database integrity check FAILED\n")
		fmt.Fprintf(os.Stderr, "          Expected : %s\n", dbExpectedHash)
		fmt.Fprintf(os.Stderr, "          Computed : %s\n", got)
		fmt.Fprintf(os.Stderr, "          The CVE rules have been modified or the binary tampered with.\n\n")
		os.Exit(2)
	}
}

// ComputeDBHash returns the SHA-256 fingerprint of the current CVE database.
// Called at startup for integrity verification and via -db-hash flag for stamping.
func ComputeDBHash() string {
	h := sha256.New()
	for _, e := range db {
		fmt.Fprintf(h, "%s|%s|%.2f|%s|%s|%s\n",
			e.product, e.cve, e.cvss, e.severity,
			verStr(e.minVer), verStr(e.maxVer))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func verStr(v version) string {
	if !v.valid() {
		return "0"
	}
	s := make([]string, len(v.parts))
	for i, p := range v.parts {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ".")
}
