package vulns

import "testing"

func TestFilterMatchesStrictKeepsHighVersioned(t *testing.T) {
	in := []Match{
		{CVE: "CVE-low", Confidence: "low", Version: "1.0", CVSS: 9.8},
		{CVE: "CVE-high-no-version", Confidence: "high", CVSS: 9.8},
		{CVE: "CVE-high-version", Confidence: "high", Version: "1.0", CVSS: 9.8},
		{CVE: "CVE-confirmed", Confidence: "confirmed"},
	}
	got := FilterMatches(in, PrecisionProfile("strict"))
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2: %+v", len(got), got)
	}
	if got[0].CVE != "CVE-high-version" || got[1].CVE != "CVE-confirmed" {
		t.Fatalf("unexpected output: %+v", got)
	}
}

func TestFilterMatchesKEVProfile(t *testing.T) {
	in := []Match{
		{CVE: "CVE-normal", Confidence: "high", Version: "1.0"},
		{CVE: "CVE-kev", Confidence: "medium", KEV: true},
	}
	got := FilterMatches(in, PrecisionProfile("kev"))
	if len(got) != 1 || got[0].CVE != "CVE-kev" {
		t.Fatalf("unexpected output: %+v", got)
	}
}
