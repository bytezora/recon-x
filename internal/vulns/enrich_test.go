package vulns

import "testing"

func TestFingerprintBannerBuildsCPE(t *testing.T) {
	fps := FingerprintBanner("host", 80, "Apache/2.4.49")
	if len(fps) == 0 {
		t.Fatal("expected at least one fingerprint")
	}
	got := fps[0]
	if got.Product != "apache" {
		t.Fatalf("product = %q, want apache", got.Product)
	}
	if got.Version != "2.4.49" {
		t.Fatalf("version = %q, want 2.4.49", got.Version)
	}
	if got.CPE != "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*" {
		t.Fatalf("unexpected cpe: %q", got.CPE)
	}
}

func TestPriorityForKEVHighEPSS(t *testing.T) {
	m := Match{
		CVE:        "CVE-2024-0001",
		CVSS:       9.8,
		Severity:   "CRITICAL",
		Confidence: "high",
		KEV:        true,
		EPSS:       0.95,
	}
	if got := priorityFor(m); got != "P0" {
		t.Fatalf("priority = %q, want P0", got)
	}
}

func TestMergeMatchKeepsBestEvidence(t *testing.T) {
	old := Match{Host: "h", Port: 443, CVE: "CVE-1", CVSS: 5, Confidence: "medium", Source: "offline-db"}
	fresh := Match{Host: "h", Port: 443, CVE: "CVE-1", CVSS: 9.8, Severity: "CRITICAL", Confidence: "high", Source: "nvd-live", CPE: "cpe:2.3:a:test:test:1:*:*:*:*:*:*:*"}
	got := mergeMatch(old, fresh)
	if got.CVSS != 9.8 || got.Severity != "CRITICAL" {
		t.Fatalf("expected stronger NVD score, got %+v", got)
	}
	if got.Confidence != "high" {
		t.Fatalf("confidence = %q, want high", got.Confidence)
	}
	if got.CPE == "" || got.Source != "offline-db,nvd-live" {
		t.Fatalf("expected merged cpe/source, got %+v", got)
	}
}

func TestNormalizeCPE23(t *testing.T) {
	got := normalizeCPE23("cpe:/a:nginx:nginx:1.18.0")
	want := "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
	if got != want {
		t.Fatalf("normalizeCPE23 = %q, want %q", got, want)
	}
}

func TestDedupeMatchesMergesSources(t *testing.T) {
	in := []Match{
		{Host: "h", Port: 443, CVE: "CVE-1", Confidence: "medium", Source: "offline-db", CVSS: 5},
		{Host: "h", Port: 443, CVE: "CVE-1", Confidence: "confirmed", Source: "active-verify", CVSS: 9.8},
	}
	got := DedupeMatches(in)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Confidence != "confirmed" || got[0].CVSS != 9.8 {
		t.Fatalf("unexpected merged match: %+v", got[0])
	}
	if got[0].Source != "offline-db,active-verify" {
		t.Fatalf("source = %q", got[0].Source)
	}
}
