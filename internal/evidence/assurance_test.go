package evidence

import (
	"path/filepath"
	"testing"

	"github.com/bytezora/recon-x/internal/vulns"
)

func TestEvaluateAssuranceFilePassesForStrictPublicServiceEvidence(t *testing.T) {
	dir := t.TempDir()
	scanPath := filepath.Join(dir, "scan.json")
	fps := make([]vulns.Fingerprint, 0, 10)
	for i := 0; i < 10; i++ {
		fps = append(fps, vulns.Fingerprint{
			Host:       "lab.local",
			Port:       8000 + i,
			Product:    "apache",
			Version:    "2.4.49",
			CPE:        "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
			Source:     "nmap-xml",
			Confidence: "version",
		})
	}
	writeJSON(t, scanPath, scanReport{
		Target:       "lab.local",
		Fingerprints: fps,
		CVEEnrichment: vulns.EnrichReport{
			Enabled:             true,
			Fingerprints:        10,
			FingerprintsWithCPE: 10,
			NVDQueries:          10,
			NVDMatches:          3,
		},
		CVEFilter: vulns.FilterReport{
			Profile:        "strict",
			MinConfidence:  "high",
			RequireVersion: true,
		},
		Vulns: []vulns.Match{
			{Host: "lab.local", Port: 8000, Product: "apache", Version: "2.4.49", CPE: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", CVE: "CVE-2021-41773", Confidence: "high"},
		},
	})

	report, err := EvaluateAssuranceFile(scanPath, "test", 0.90)
	if err != nil {
		t.Fatalf("EvaluateAssuranceFile() error = %v", err)
	}
	if !report.PublicServiceClaimEligible {
		t.Fatalf("public service claim should be eligible: %+v", report.Checks)
	}
	if report.WholeDomainClaimEligible {
		t.Fatalf("whole-domain all-CVE claim must not be eligible from external evidence alone")
	}
	if report.EvidenceReadinessScore != 1 {
		t.Fatalf("readiness score = %v, want 1", report.EvidenceReadinessScore)
	}
}

func TestEvaluateAssuranceFileFailsWhenEvidenceIsWeak(t *testing.T) {
	dir := t.TempDir()
	scanPath := filepath.Join(dir, "scan.json")
	writeJSON(t, scanPath, scanReport{
		Target: "weak.local",
		Fingerprints: []vulns.Fingerprint{
			{Host: "weak.local", Port: 80, Product: "apache", Source: "banner", Confidence: "presence"},
		},
		CVEFilter: vulns.FilterReport{
			Profile:       "balanced",
			MinConfidence: "medium",
		},
		Vulns: []vulns.Match{
			{Host: "weak.local", Port: 80, Product: "apache", CVE: "CVE-LOW", Confidence: "low"},
		},
	})

	report, err := EvaluateAssuranceFile(scanPath, "test", 0.90)
	if err != nil {
		t.Fatalf("EvaluateAssuranceFile() error = %v", err)
	}
	if report.PublicServiceClaimEligible {
		t.Fatalf("public service claim should not be eligible")
	}
	if len(report.MissingEvidence) == 0 {
		t.Fatalf("missing evidence should explain why assurance failed")
	}
	if report.Totals.VersionCoverage != 0 || report.Totals.CPECoverage != 0 {
		t.Fatalf("unexpected coverage: %+v", report.Totals)
	}
}
