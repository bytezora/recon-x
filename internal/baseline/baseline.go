package baseline

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/bytezora/recon-x/internal/finding"
)

type Report struct {
	Findings []finding.Finding `json:"findings"`
}

type Rules struct {
	Fingerprints map[string]bool
	Types        map[string]bool
	CVEs         map[string]bool
	Contains     []string
}

type Summary struct {
	Before             int
	After              int
	BaselineSuppressed int
	AllowSuppressed    int
}

func LoadFingerprints(path string) (map[string]bool, error) {
	out := map[string]bool{}
	if path == "" {
		return out, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var report Report
	if err := json.NewDecoder(f).Decode(&report); err != nil {
		return nil, err
	}
	for _, item := range report.Findings {
		fp := item.Fingerprint
		if fp == "" {
			fp = finding.Fingerprint(item)
		}
		out[fp] = true
	}
	return out, nil
}

func LoadRules(path string) (Rules, error) {
	rules := Rules{
		Fingerprints: map[string]bool{},
		Types:        map[string]bool{},
		CVEs:         map[string]bool{},
	}
	if path == "" {
		return rules, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) && filepath.Base(path) == ".reconxignore" {
			return rules, nil
		}
		return rules, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			rules.Contains = append(rules.Contains, strings.ToLower(line))
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		switch key {
		case "fingerprint", "fp":
			rules.Fingerprints[val] = true
		case "type":
			rules.Types[strings.ToLower(val)] = true
		case "cve":
			rules.CVEs[strings.ToUpper(val)] = true
		case "url", "contains", "match":
			rules.Contains = append(rules.Contains, strings.ToLower(val))
		default:
			rules.Contains = append(rules.Contains, strings.ToLower(line))
		}
	}
	return rules, scanner.Err()
}

func Apply(findings []finding.Finding, baseline map[string]bool, rules Rules) ([]finding.Finding, Summary) {
	summary := Summary{Before: len(findings)}
	out := make([]finding.Finding, 0, len(findings))
	for _, item := range findings {
		if item.Fingerprint == "" {
			item.Fingerprint = finding.Fingerprint(item)
		}
		if baseline[item.Fingerprint] {
			summary.BaselineSuppressed++
			continue
		}
		if rules.Match(item) {
			summary.AllowSuppressed++
			continue
		}
		out = append(out, item)
	}
	summary.After = len(out)
	return out, summary
}

func (r Rules) Match(item finding.Finding) bool {
	if r.Fingerprints[item.Fingerprint] {
		return true
	}
	if r.Types[strings.ToLower(item.Type)] {
		return true
	}
	if item.CVE != "" && r.CVEs[strings.ToUpper(item.CVE)] {
		return true
	}
	haystack := strings.ToLower(strings.Join([]string{
		item.AffectedURL,
		item.Title,
		item.Evidence,
		item.Reason,
	}, "\n"))
	for _, needle := range r.Contains {
		if needle != "" && strings.Contains(haystack, needle) {
			return true
		}
	}
	return false
}
