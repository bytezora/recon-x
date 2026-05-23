package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bytezora/recon-x/internal/vulns"
)

type AssuranceReport struct {
	GeneratedAt                string            `json:"generated_at"`
	ToolVersion                string            `json:"tool_version"`
	DBHash                     string            `json:"db_hash"`
	ScanTarget                 string            `json:"scan_target,omitempty"`
	ScanGeneratedAt            string            `json:"scan_generated_at,omitempty"`
	ScanPath                   string            `json:"scan_path"`
	ScanSHA256                 string            `json:"scan_sha256"`
	Threshold                  float64           `json:"threshold"`
	Scope                      string            `json:"scope"`
	PublicServiceClaimEligible bool              `json:"public_service_90_claim_eligible"`
	WholeDomainClaimEligible   bool              `json:"whole_domain_90_claim_eligible"`
	EvidenceReadinessScore     float64           `json:"evidence_readiness_score"`
	Summary                    string            `json:"summary"`
	Totals                     AssuranceTotals   `json:"totals"`
	Checks                     []AssuranceCheck  `json:"checks"`
	MissingEvidence            []string          `json:"missing_evidence,omitempty"`
	Limitations                []string          `json:"limitations"`
	RecommendedCommands        []string          `json:"recommended_commands,omitempty"`
	RecommendedInputs          map[string]string `json:"recommended_inputs,omitempty"`
}

type AssuranceTotals struct {
	Fingerprints            int     `json:"fingerprints"`
	FingerprintsWithVersion int     `json:"fingerprints_with_version"`
	FingerprintsWithCPE     int     `json:"fingerprints_with_cpe"`
	Vulnerabilities         int     `json:"vulnerabilities"`
	HighOrConfirmedVulns    int     `json:"high_or_confirmed_vulns"`
	LowConfidenceVulns      int     `json:"low_confidence_vulns"`
	NVDLiveEnabled          bool    `json:"nvd_live_enabled"`
	NVDQueries              int     `json:"nvd_queries"`
	NVDMatches              int     `json:"nvd_matches"`
	NVDErrors               int     `json:"nvd_errors"`
	CVEFilterProfile        string  `json:"cve_filter_profile,omitempty"`
	CVEFilterMinConfidence  string  `json:"cve_filter_min_confidence,omitempty"`
	CVEFilterRequireVersion bool    `json:"cve_filter_require_version"`
	VersionCoverage         float64 `json:"version_coverage"`
	CPECoverage             float64 `json:"cpe_coverage"`
	HighConfidenceCoverage  float64 `json:"high_confidence_coverage"`
	NVDSuccessRate          float64 `json:"nvd_success_rate"`
}

type AssuranceCheck struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Status   string  `json:"status"`
	Scope    string  `json:"scope"`
	Score    float64 `json:"score"`
	Required float64 `json:"required"`
	Reason   string  `json:"reason"`
}

func EvaluateAssuranceFile(scanPath, toolVersion string, threshold float64) (AssuranceReport, error) {
	if threshold <= 0 {
		threshold = 0.90
	}
	scanBytes, scanHash, err := readAndHash(scanPath)
	if err != nil {
		return AssuranceReport{}, err
	}
	var scan scanReport
	if err := json.Unmarshal(scanBytes, &scan); err != nil {
		return AssuranceReport{}, fmt.Errorf("decode scan json: %w", err)
	}
	report := evaluateAssurance(scan, threshold)
	report.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	report.ToolVersion = toolVersion
	report.DBHash = vulns.ComputeDBHash()
	report.ScanPath = scanPath
	report.ScanSHA256 = scanHash
	report.ScanTarget = scan.Target
	report.ScanGeneratedAt = scan.GeneratedAt
	return report, nil
}

func evaluateAssurance(scan scanReport, threshold float64) AssuranceReport {
	if threshold <= 0 {
		threshold = 0.90
	}
	totals := assuranceTotals(scan)
	report := AssuranceReport{
		Threshold: threshold,
		Scope:     "public_external_service_version_cves",
		Totals:    totals,
		Limitations: []string{
			"Whole-domain all-CVE coverage is not provable from external unauthenticated scanning alone.",
			"Backend libraries, OS packages, private services, plugins, containers and authenticated-only application paths require internal inventory, SBOM or authenticated scanning.",
			"This assurance score is not measured precision/recall; measured precision/recall still requires -cve-evidence with ground truth.",
		},
		RecommendedCommands: []string{
			"nmap -sV -oX nmap.xml <authorized-domain>",
			"recon-x -target <authorized-domain> -nmap-xml nmap.xml -skip-portscan -cve-live -cve-profile strict -cve-require-version -json scan.json",
			"recon-x -cve-assurance scan.json -cve-assurance-report assurance.json -cve-assurance-markdown assurance.md",
		},
		RecommendedInputs: map[string]string{
			"nmap_xml":              "Version/CPE evidence for public network services.",
			"nvd_api_key":           "Stable live NVD enrichment and fewer rate-limit gaps.",
			"sbom_or_package_list":  "Required to reason about backend libraries, OS packages and containers.",
			"authenticated_context": "Required for CVEs exposed only after login or inside private applications.",
			"ground_truth":          "Required for measured 90% precision/recall proof.",
		},
	}

	checks := []AssuranceCheck{
		fingerprintCheck(totals),
		coverageCheck("version_coverage", "Version evidence coverage", totals.VersionCoverage, threshold, "public_external_services"),
		coverageCheck("cpe_coverage", "CPE evidence coverage", totals.CPECoverage, threshold, "public_external_services"),
		liveNVDCheck(totals, threshold),
		nvdHealthCheck(totals),
		strictPolicyCheck(totals),
		highConfidenceCheck(totals, threshold),
	}
	report.Checks = checks
	report.PublicServiceClaimEligible = allChecksPass(checks)
	report.WholeDomainClaimEligible = false
	report.EvidenceReadinessScore = readinessScore(checks)
	report.MissingEvidence = missingEvidence(checks)
	if report.PublicServiceClaimEligible {
		report.Summary = "Eligible for a high-confidence public service/version CVE claim. This does not prove all CVEs across the whole domain."
	} else {
		report.Summary = "Not eligible for a 90% public service/version CVE claim; see missing_evidence and failed checks."
	}
	return report
}

func assuranceTotals(scan scanReport) AssuranceTotals {
	t := AssuranceTotals{
		Fingerprints:            len(scan.Fingerprints),
		Vulnerabilities:         len(scan.Vulns),
		NVDLiveEnabled:          scan.CVEEnrichment.Enabled,
		NVDQueries:              scan.CVEEnrichment.NVDQueries,
		NVDMatches:              scan.CVEEnrichment.NVDMatches,
		NVDErrors:               len(scan.CVEEnrichment.NVDErrors),
		CVEFilterProfile:        scan.CVEFilter.Profile,
		CVEFilterMinConfidence:  scan.CVEFilter.MinConfidence,
		CVEFilterRequireVersion: scan.CVEFilter.RequireVersion,
	}
	for _, fp := range scan.Fingerprints {
		if strings.TrimSpace(fp.Version) != "" {
			t.FingerprintsWithVersion++
		}
		if strings.TrimSpace(fp.CPE) != "" {
			t.FingerprintsWithCPE++
		}
	}
	for _, m := range scan.Vulns {
		switch strings.ToLower(strings.TrimSpace(m.Confidence)) {
		case "confirmed", "high":
			t.HighOrConfirmedVulns++
		case "low":
			t.LowConfidenceVulns++
		}
	}
	t.VersionCoverage = ratio(t.FingerprintsWithVersion, t.Fingerprints)
	t.CPECoverage = ratio(t.FingerprintsWithCPE, t.Fingerprints)
	t.HighConfidenceCoverage = ratio(t.HighOrConfirmedVulns, t.Vulnerabilities)
	t.NVDSuccessRate = ratio(t.NVDQueries-t.NVDErrors, t.NVDQueries)
	return t
}

func fingerprintCheck(t AssuranceTotals) AssuranceCheck {
	pass := t.Fingerprints > 0
	score := 0.0
	if pass {
		score = 1
	}
	return AssuranceCheck{
		ID:       "fingerprints_present",
		Name:     "Service fingerprints present",
		Status:   checkStatus(pass),
		Scope:    "public_external_services",
		Score:    score,
		Required: 1,
		Reason:   fmt.Sprintf("%d service fingerprints found", t.Fingerprints),
	}
}

func coverageCheck(id, name string, score, required float64, scope string) AssuranceCheck {
	return AssuranceCheck{
		ID:       id,
		Name:     name,
		Status:   checkStatus(score >= required),
		Scope:    scope,
		Score:    score,
		Required: required,
		Reason:   fmt.Sprintf("%.2f%% coverage, required %.2f%%", score*100, required*100),
	}
}

func liveNVDCheck(t AssuranceTotals, threshold float64) AssuranceCheck {
	score := 0.0
	requiredQueries := int(float64(t.FingerprintsWithCPE) * threshold)
	if t.NVDLiveEnabled && t.FingerprintsWithCPE == 0 {
		score = 1
	} else if t.NVDLiveEnabled && t.FingerprintsWithCPE > 0 {
		score = ratio(t.NVDQueries, t.FingerprintsWithCPE)
	}
	pass := t.NVDLiveEnabled && score >= threshold
	reason := fmt.Sprintf("NVD live=%t, queries=%d, CPE fingerprints=%d", t.NVDLiveEnabled, t.NVDQueries, t.FingerprintsWithCPE)
	if requiredQueries > 0 {
		reason += fmt.Sprintf(", required queries>=%d", requiredQueries)
	}
	return AssuranceCheck{
		ID:       "nvd_live_coverage",
		Name:     "Live NVD enrichment coverage",
		Status:   checkStatus(pass),
		Scope:    "public_external_services",
		Score:    score,
		Required: threshold,
		Reason:   reason,
	}
}

func nvdHealthCheck(t AssuranceTotals) AssuranceCheck {
	required := 0.95
	score := t.NVDSuccessRate
	pass := score >= required
	if t.NVDQueries == 0 {
		score = 0
		pass = false
	}
	return AssuranceCheck{
		ID:       "nvd_error_health",
		Name:     "NVD query health",
		Status:   checkStatus(pass),
		Scope:    "public_external_services",
		Score:    score,
		Required: required,
		Reason:   fmt.Sprintf("%d NVD errors across %d queries", t.NVDErrors, t.NVDQueries),
	}
}

func strictPolicyCheck(t AssuranceTotals) AssuranceCheck {
	minConf := strings.ToLower(strings.TrimSpace(t.CVEFilterMinConfidence))
	strictConfidence := minConf == "high" || minConf == "confirmed"
	pass := t.CVEFilterRequireVersion && (strictConfidence || strings.EqualFold(t.CVEFilterProfile, "strict"))
	score := 0.0
	if pass {
		score = 1
	}
	return AssuranceCheck{
		ID:       "strict_cve_policy",
		Name:     "Strict CVE policy",
		Status:   checkStatus(pass),
		Scope:    "public_external_services",
		Score:    score,
		Required: 1,
		Reason:   fmt.Sprintf("profile=%q require_version=%t min_confidence=%q", t.CVEFilterProfile, t.CVEFilterRequireVersion, t.CVEFilterMinConfidence),
	}
}

func highConfidenceCheck(t AssuranceTotals, threshold float64) AssuranceCheck {
	if t.Vulnerabilities == 0 {
		return AssuranceCheck{
			ID:       "high_confidence_findings",
			Name:     "High-confidence CVE findings",
			Status:   "pass",
			Scope:    "public_external_services",
			Score:    1,
			Required: threshold,
			Reason:   "no CVE findings were reported",
		}
	}
	return coverageCheck("high_confidence_findings", "High-confidence CVE findings", t.HighConfidenceCoverage, threshold, "public_external_services")
}

func allChecksPass(checks []AssuranceCheck) bool {
	for _, c := range checks {
		if c.Status != "pass" {
			return false
		}
	}
	return true
}

func readinessScore(checks []AssuranceCheck) float64 {
	if len(checks) == 0 {
		return 0
	}
	total := 0.0
	for _, c := range checks {
		if c.Required <= 0 {
			continue
		}
		score := c.Score / c.Required
		if score > 1 {
			score = 1
		}
		if score < 0 {
			score = 0
		}
		total += score
	}
	return total / float64(len(checks))
}

func missingEvidence(checks []AssuranceCheck) []string {
	var missing []string
	for _, c := range checks {
		if c.Status == "pass" {
			continue
		}
		switch c.ID {
		case "fingerprints_present":
			missing = append(missing, "No service fingerprints. Run a full scan or import Nmap XML with -nmap-xml.")
		case "version_coverage":
			missing = append(missing, "Insufficient version evidence. Use Nmap -sV XML and safe version probes.")
		case "cpe_coverage":
			missing = append(missing, "Insufficient CPE evidence. Import Nmap XML and enable richer fingerprinting.")
		case "nvd_live_coverage":
			missing = append(missing, "Live NVD enrichment did not cover enough CPE fingerprints. Use -cve-live and an NVD API key.")
		case "nvd_error_health":
			missing = append(missing, "NVD enrichment had too many errors or did not run. Retry with a valid NVD API key.")
		case "strict_cve_policy":
			missing = append(missing, "CVE policy is not strict enough. Use -cve-profile strict -cve-require-version.")
		case "high_confidence_findings":
			missing = append(missing, "Too many reported CVEs are low/medium confidence. Require versioned evidence and strict filtering.")
		}
	}
	return missing
}

func checkStatus(pass bool) string {
	if pass {
		return "pass"
	}
	return "fail"
}

func WriteAssuranceJSON(path string, report AssuranceReport) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func WriteAssuranceMarkdown(path string, report AssuranceReport) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# CVE Assurance Report\n\n")
	fmt.Fprintf(&b, "- Public service 90%% claim: **%s**\n", passText(report.PublicServiceClaimEligible))
	fmt.Fprintf(&b, "- Whole-domain all-CVE 90%% claim: **%s**\n", passText(report.WholeDomainClaimEligible))
	fmt.Fprintf(&b, "- Evidence readiness score: %.2f%%\n", report.EvidenceReadinessScore*100)
	fmt.Fprintf(&b, "- Scope: `%s`\n", report.Scope)
	fmt.Fprintf(&b, "- Target: `%s`\n", report.ScanTarget)
	fmt.Fprintf(&b, "- Scan SHA-256: `%s`\n", report.ScanSHA256)
	fmt.Fprintf(&b, "- CVE DB hash: `%s`\n\n", report.DBHash)
	fmt.Fprintf(&b, "%s\n\n", report.Summary)

	fmt.Fprintf(&b, "## Totals\n\n")
	fmt.Fprintf(&b, "- Fingerprints: %d\n", report.Totals.Fingerprints)
	fmt.Fprintf(&b, "- Version coverage: %.2f%%\n", report.Totals.VersionCoverage*100)
	fmt.Fprintf(&b, "- CPE coverage: %.2f%%\n", report.Totals.CPECoverage*100)
	fmt.Fprintf(&b, "- NVD queries/errors: %d/%d\n", report.Totals.NVDQueries, report.Totals.NVDErrors)
	fmt.Fprintf(&b, "- CVE findings: %d\n\n", report.Totals.Vulnerabilities)

	fmt.Fprintf(&b, "## Checks\n\n")
	fmt.Fprintf(&b, "| Check | Status | Score | Required | Reason |\n")
	fmt.Fprintf(&b, "|---|---:|---:|---:|---|\n")
	for _, c := range report.Checks {
		fmt.Fprintf(&b, "| %s | %s | %.2f%% | %.2f%% | %s |\n",
			escapePipe(c.Name), c.Status, c.Score*100, c.Required*100, escapePipe(c.Reason))
	}

	if len(report.MissingEvidence) > 0 {
		fmt.Fprintf(&b, "\n## Missing Evidence\n\n")
		for _, item := range report.MissingEvidence {
			fmt.Fprintf(&b, "- %s\n", item)
		}
	}

	fmt.Fprintf(&b, "\n## Limitations\n\n")
	for _, item := range report.Limitations {
		fmt.Fprintf(&b, "- %s\n", item)
	}

	return os.WriteFile(path, []byte(b.String()), 0644)
}
