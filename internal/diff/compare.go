package diff

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/bytezora/recon-x/internal/output"
)

type DiffReport struct {
	NewFindings       []string
	ResolvedFindings  []string
	NewSubdomains     []string
	RemovedSubdomains []string
	NewPorts          []string
	RemovedPorts      []string
}

func loadReport(path string) (*output.Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r output.Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func Compare(fileA, fileB string) (*DiffReport, error) {
	a, err := loadReport(fileA)
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", fileA, err)
	}
	b, err := loadReport(fileB)
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", fileB, err)
	}

	report := &DiffReport{}

	subsA := map[string]bool{}
	for _, s := range a.Subdomains {
		subsA[s.Subdomain] = true
	}
	subsB := map[string]bool{}
	for _, s := range b.Subdomains {
		subsB[s.Subdomain] = true
	}
	for sub := range subsB {
		if !subsA[sub] {
			report.NewSubdomains = append(report.NewSubdomains, sub)
		}
	}
	for sub := range subsA {
		if !subsB[sub] {
			report.RemovedSubdomains = append(report.RemovedSubdomains, sub)
		}
	}

	portsA := map[string]bool{}
	for _, p := range a.Ports {
		portsA[fmt.Sprintf("%s:%d", p.Host, p.Port)] = true
	}
	portsB := map[string]bool{}
	for _, p := range b.Ports {
		portsB[fmt.Sprintf("%s:%d", p.Host, p.Port)] = true
	}
	for port := range portsB {
		if !portsA[port] {
			report.NewPorts = append(report.NewPorts, port)
		}
	}
	for port := range portsA {
		if !portsB[port] {
			report.RemovedPorts = append(report.RemovedPorts, port)
		}
	}

	vulnsA := map[string]bool{}
	for _, v := range a.Vulns {
		vulnsA[v.CVE+":"+v.Host] = true
	}
	for _, v := range b.Vulns {
		key := v.CVE + ":" + v.Host
		if !vulnsA[key] {
			report.NewFindings = append(report.NewFindings, fmt.Sprintf("NEW CVE %s on %s", v.CVE, v.Host))
		}
	}
	vulnsB := map[string]bool{}
	for _, v := range b.Vulns {
		vulnsB[v.CVE+":"+v.Host] = true
	}
	for _, v := range a.Vulns {
		key := v.CVE + ":" + v.Host
		if !vulnsB[key] {
			report.ResolvedFindings = append(report.ResolvedFindings, fmt.Sprintf("RESOLVED CVE %s on %s", v.CVE, v.Host))
		}
	}

	return report, nil
}

func WriteDiff(path string, report *DiffReport) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
