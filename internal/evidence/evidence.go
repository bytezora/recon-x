package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bytezora/recon-x/internal/vulns"
)

type Truth struct {
	Name             string   `json:"name,omitempty"`
	Source           string   `json:"source,omitempty"`
	ScopeUnknownAsFP *bool    `json:"scope_unknown_as_fp,omitempty"`
	IgnoreCVEs       []string `json:"ignore_cves,omitempty"`
	Cases            []Case   `json:"cases"`
}

type Case struct {
	Name         string   `json:"name,omitempty"`
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	Product      string   `json:"product,omitempty"`
	Version      string   `json:"version,omitempty"`
	ExpectedCVEs []string `json:"expected_cves"`
	IgnoreCVEs   []string `json:"ignore_cves,omitempty"`
	Notes        string   `json:"notes,omitempty"`
}

type Report struct {
	GeneratedAt     string       `json:"generated_at"`
	ToolVersion     string       `json:"tool_version"`
	DBHash          string       `json:"db_hash"`
	Dataset         string       `json:"dataset,omitempty"`
	DatasetSource   string       `json:"dataset_source,omitempty"`
	ScanTarget      string       `json:"scan_target,omitempty"`
	ScanGeneratedAt string       `json:"scan_generated_at,omitempty"`
	ScanPath        string       `json:"scan_path"`
	TruthPath       string       `json:"truth_path"`
	ScanSHA256      string       `json:"scan_sha256"`
	TruthSHA256     string       `json:"truth_sha256"`
	Threshold       float64      `json:"threshold"`
	ThresholdPolicy string       `json:"threshold_policy"`
	Passed          bool         `json:"passed"`
	Totals          Totals       `json:"totals"`
	Cases           []CaseResult `json:"cases"`
	OutsideScopeFP  []Detected   `json:"outside_scope_false_positives,omitempty"`
	Ignored         []Detected   `json:"ignored,omitempty"`
}

type Totals struct {
	Expected      int     `json:"expected"`
	Detected      int     `json:"detected"`
	TruePositive  int     `json:"true_positive"`
	FalsePositive int     `json:"false_positive"`
	FalseNegative int     `json:"false_negative"`
	Precision     float64 `json:"precision"`
	Recall        float64 `json:"recall"`
	F1            float64 `json:"f1"`
}

type CaseResult struct {
	Name           string   `json:"name,omitempty"`
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	Product        string   `json:"product,omitempty"`
	Version        string   `json:"version,omitempty"`
	ExpectedCVEs   []string `json:"expected_cves"`
	DetectedCVEs   []string `json:"detected_cves"`
	TruePositives  []string `json:"true_positives"`
	FalsePositives []string `json:"false_positives"`
	FalseNegatives []string `json:"false_negatives"`
	Precision      float64  `json:"precision"`
	Recall         float64  `json:"recall"`
	F1             float64  `json:"f1"`
	Passed         bool     `json:"passed"`
	Notes          string   `json:"notes,omitempty"`
}

type Detected struct {
	CVE        string  `json:"cve"`
	Host       string  `json:"host,omitempty"`
	Port       int     `json:"port,omitempty"`
	Product    string  `json:"product,omitempty"`
	Version    string  `json:"version,omitempty"`
	CPE        string  `json:"cpe,omitempty"`
	CVSS       float64 `json:"cvss,omitempty"`
	Severity   string  `json:"severity,omitempty"`
	Confidence string  `json:"confidence,omitempty"`
	Source     string  `json:"source,omitempty"`
	KEV        bool    `json:"kev,omitempty"`
	Priority   string  `json:"priority,omitempty"`
}

type scanReport struct {
	Target        string              `json:"target"`
	GeneratedAt   string              `json:"generated_at"`
	Fingerprints  []vulns.Fingerprint `json:"fingerprints,omitempty"`
	CVEEnrichment vulns.EnrichReport  `json:"cve_enrichment,omitempty"`
	CVEFilter     vulns.FilterReport  `json:"cve_filter,omitempty"`
	Vulns         []vulns.Match       `json:"vulns"`
}

func EvaluateFiles(scanPath, truthPath, toolVersion string, threshold float64) (Report, error) {
	if threshold <= 0 {
		threshold = 0.90
	}
	scanBytes, scanHash, err := readAndHash(scanPath)
	if err != nil {
		return Report{}, err
	}
	truthBytes, truthHash, err := readAndHash(truthPath)
	if err != nil {
		return Report{}, err
	}

	var scan scanReport
	if err := json.Unmarshal(scanBytes, &scan); err != nil {
		return Report{}, fmt.Errorf("decode scan json: %w", err)
	}
	var truth Truth
	if err := json.Unmarshal(truthBytes, &truth); err != nil {
		return Report{}, fmt.Errorf("decode truth json: %w", err)
	}
	if len(truth.Cases) == 0 {
		return Report{}, fmt.Errorf("truth file has no cases")
	}

	report := evaluate(scan, truth, threshold)
	report.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	report.ToolVersion = toolVersion
	report.DBHash = vulns.ComputeDBHash()
	report.ScanPath = scanPath
	report.TruthPath = truthPath
	report.ScanSHA256 = scanHash
	report.TruthSHA256 = truthHash
	report.ScanTarget = scan.Target
	report.ScanGeneratedAt = scan.GeneratedAt
	report.Dataset = truth.Name
	report.DatasetSource = truth.Source
	report.Threshold = threshold
	report.ThresholdPolicy = "precision_and_recall"
	report.Passed = report.Totals.Precision >= threshold && report.Totals.Recall >= threshold
	return report, nil
}

func evaluate(scan scanReport, truth Truth, threshold float64) Report {
	globalIgnore := set(truth.IgnoreCVEs)
	scopeUnknownAsFP := true
	if truth.ScopeUnknownAsFP != nil {
		scopeUnknownAsFP = *truth.ScopeUnknownAsFP
	}

	var report Report
	consumed := make(map[string]bool)
	for _, tc := range truth.Cases {
		caseIgnore := set(tc.IgnoreCVEs)
		for cve := range globalIgnore {
			caseIgnore[cve] = true
		}
		expected := set(tc.ExpectedCVEs)
		detected := make(map[string]vulns.Match)
		for _, m := range scan.Vulns {
			if !caseMatches(tc, m) {
				continue
			}
			key := matchKey(m)
			consumed[key] = true
			cve := strings.ToUpper(strings.TrimSpace(m.CVE))
			if cve == "" {
				continue
			}
			if caseIgnore[cve] {
				report.Ignored = append(report.Ignored, detectedFromMatch(m))
				continue
			}
			detected[cve] = m
		}

		cr := CaseResult{
			Name:         tc.Name,
			Host:         tc.Host,
			Port:         tc.Port,
			Product:      tc.Product,
			Version:      tc.Version,
			ExpectedCVEs: sortedKeys(expected),
			DetectedCVEs: sortedKeysFromMatches(detected),
			Notes:        tc.Notes,
		}
		for cve := range expected {
			if _, ok := detected[cve]; ok {
				cr.TruePositives = append(cr.TruePositives, cve)
			} else {
				cr.FalseNegatives = append(cr.FalseNegatives, cve)
			}
		}
		for cve := range detected {
			if !expected[cve] {
				cr.FalsePositives = append(cr.FalsePositives, cve)
			}
		}
		sort.Strings(cr.TruePositives)
		sort.Strings(cr.FalsePositives)
		sort.Strings(cr.FalseNegatives)
		cr.Precision, cr.Recall, cr.F1 = metrics(len(cr.TruePositives), len(cr.FalsePositives), len(cr.FalseNegatives))
		cr.Passed = cr.Precision >= threshold && cr.Recall >= threshold

		report.Totals.Expected += len(expected)
		report.Totals.TruePositive += len(cr.TruePositives)
		report.Totals.FalsePositive += len(cr.FalsePositives)
		report.Totals.FalseNegative += len(cr.FalseNegatives)
		report.Cases = append(report.Cases, cr)
	}

	if scopeUnknownAsFP {
		for _, m := range scan.Vulns {
			cve := strings.ToUpper(strings.TrimSpace(m.CVE))
			if cve == "" || globalIgnore[cve] || consumed[matchKey(m)] {
				continue
			}
			report.OutsideScopeFP = append(report.OutsideScopeFP, detectedFromMatch(m))
			report.Totals.FalsePositive++
		}
	}
	sort.Slice(report.OutsideScopeFP, func(i, j int) bool {
		return detectedSortKey(report.OutsideScopeFP[i]) < detectedSortKey(report.OutsideScopeFP[j])
	})
	sort.Slice(report.Ignored, func(i, j int) bool {
		return detectedSortKey(report.Ignored[i]) < detectedSortKey(report.Ignored[j])
	})
	report.Totals.Detected = report.Totals.TruePositive + report.Totals.FalsePositive
	report.Totals.Precision, report.Totals.Recall, report.Totals.F1 = metrics(
		report.Totals.TruePositive,
		report.Totals.FalsePositive,
		report.Totals.FalseNegative,
	)
	return report
}

func WriteJSON(path string, report Report) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func WriteMarkdown(path string, report Report) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# CVE Evidence Report\n\n")
	fmt.Fprintf(&b, "- Status: **%s**\n", passText(report.Passed))
	if report.Dataset != "" {
		fmt.Fprintf(&b, "- Dataset: %s\n", report.Dataset)
	}
	fmt.Fprintf(&b, "- Threshold: %.2f%% precision and recall\n", report.Threshold*100)
	fmt.Fprintf(&b, "- Precision: %.2f%%\n", report.Totals.Precision*100)
	fmt.Fprintf(&b, "- Recall: %.2f%%\n", report.Totals.Recall*100)
	fmt.Fprintf(&b, "- F1: %.2f%%\n", report.Totals.F1*100)
	fmt.Fprintf(&b, "- TP/FP/FN: %d/%d/%d\n", report.Totals.TruePositive, report.Totals.FalsePositive, report.Totals.FalseNegative)
	fmt.Fprintf(&b, "- Scan SHA-256: `%s`\n", report.ScanSHA256)
	fmt.Fprintf(&b, "- Truth SHA-256: `%s`\n", report.TruthSHA256)
	fmt.Fprintf(&b, "- CVE DB hash: `%s`\n\n", report.DBHash)

	fmt.Fprintf(&b, "## Cases\n\n")
	fmt.Fprintf(&b, "| Case | Target | Precision | Recall | TP | FP | FN |\n")
	fmt.Fprintf(&b, "|---|---:|---:|---:|---|---|---|\n")
	for _, c := range report.Cases {
		target := c.Host
		if c.Port > 0 {
			target += ":" + strconv.Itoa(c.Port)
		}
		name := c.Name
		if name == "" {
			name = target
		}
		fmt.Fprintf(&b, "| %s | %s | %.2f%% | %.2f%% | %s | %s | %s |\n",
			escapePipe(name), escapePipe(target), c.Precision*100, c.Recall*100,
			escapePipe(strings.Join(c.TruePositives, ", ")),
			escapePipe(strings.Join(c.FalsePositives, ", ")),
			escapePipe(strings.Join(c.FalseNegatives, ", ")),
		)
	}

	if len(report.OutsideScopeFP) > 0 {
		fmt.Fprintf(&b, "\n## Outside-Scope False Positives\n\n")
		for _, item := range report.OutsideScopeFP {
			fmt.Fprintf(&b, "- `%s` on `%s:%d` product=`%s` version=`%s` source=`%s`\n",
				item.CVE, item.Host, item.Port, item.Product, item.Version, item.Source)
		}
	}

	return os.WriteFile(path, []byte(b.String()), 0644)
}

func readAndHash(path string) ([]byte, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), nil
}

func caseMatches(tc Case, m vulns.Match) bool {
	if tc.Host != "" && !strings.EqualFold(tc.Host, m.Host) {
		return false
	}
	if tc.Port > 0 && tc.Port != m.Port {
		return false
	}
	if tc.Product != "" && !strings.EqualFold(tc.Product, m.Product) {
		return false
	}
	if tc.Version != "" && tc.Version != m.Version {
		return false
	}
	return true
}

func set(items []string) map[string]bool {
	out := make(map[string]bool, len(items))
	for _, item := range items {
		item = strings.ToUpper(strings.TrimSpace(item))
		if item != "" {
			out[item] = true
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeysFromMatches(m map[string]vulns.Match) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func metrics(tp, fp, fn int) (float64, float64, float64) {
	precision := ratio(tp, tp+fp)
	recall := ratio(tp, tp+fn)
	f1 := 0.0
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}
	return precision, recall, f1
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 1
	}
	return float64(num) / float64(den)
}

func matchKey(m vulns.Match) string {
	return strings.ToLower(m.Host) + "|" + strconv.Itoa(m.Port) + "|" + strings.ToUpper(m.CVE)
}

func detectedFromMatch(m vulns.Match) Detected {
	return Detected{
		CVE:        strings.ToUpper(m.CVE),
		Host:       m.Host,
		Port:       m.Port,
		Product:    m.Product,
		Version:    m.Version,
		CPE:        m.CPE,
		CVSS:       m.CVSS,
		Severity:   m.Severity,
		Confidence: m.Confidence,
		Source:     m.Source,
		KEV:        m.KEV,
		Priority:   m.Priority,
	}
}

func detectedSortKey(d Detected) string {
	return strings.ToLower(d.Host) + "|" + strconv.Itoa(d.Port) + "|" + d.CVE
}

func passText(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

func escapePipe(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}
