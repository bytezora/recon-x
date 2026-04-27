package vulns

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const dbExpectedHash = "99450bba69662261f02a09c00e4d4b01991c6d88c7627417b9ee59f45b8bae67"

func init() {
	verifyDB()
}

func verifyDB() {
	if dbExpectedHash == "TBD" {
		return
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
