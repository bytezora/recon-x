package diff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bytezora/recon-x/internal/output"
	"github.com/bytezora/recon-x/internal/portscan"
	"github.com/bytezora/recon-x/internal/subdomain"
	"github.com/bytezora/recon-x/internal/vulns"
)

func writeReport(t *testing.T, dir, name string, r output.Report) string {
	t.Helper()
	path := filepath.Join(dir, name)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCompare(t *testing.T) {
	dir := t.TempDir()

	reportA := output.Report{
		Target: "example.com",
		Subdomains: []subdomain.Result{
			{Subdomain: "www.example.com"},
			{Subdomain: "api.example.com"},
		},
		Ports: []portscan.Result{
			{Host: "1.2.3.4", Port: 80},
		},
		Vulns: []vulns.Match{
			{CVE: "CVE-2021-1234", Host: "1.2.3.4"},
		},
	}

	reportB := output.Report{
		Target: "example.com",
		Subdomains: []subdomain.Result{
			{Subdomain: "www.example.com"},
			{Subdomain: "new.example.com"},
		},
		Ports: []portscan.Result{
			{Host: "1.2.3.4", Port: 80},
			{Host: "1.2.3.4", Port: 443},
		},
		Vulns: []vulns.Match{
			{CVE: "CVE-2022-9999", Host: "1.2.3.4"},
		},
	}

	pathA := writeReport(t, dir, "a.json", reportA)
	pathB := writeReport(t, dir, "b.json", reportB)

	report, err := Compare(pathA, pathB)
	if err != nil {
		t.Fatalf("Compare error: %v", err)
	}

	if len(report.NewSubdomains) != 1 || report.NewSubdomains[0] != "new.example.com" {
		t.Errorf("expected new subdomain 'new.example.com', got %v", report.NewSubdomains)
	}
	if len(report.RemovedSubdomains) != 1 || report.RemovedSubdomains[0] != "api.example.com" {
		t.Errorf("expected removed subdomain 'api.example.com', got %v", report.RemovedSubdomains)
	}
	if len(report.NewPorts) != 1 {
		t.Errorf("expected 1 new port, got %v", report.NewPorts)
	}
	if len(report.NewFindings) != 1 {
		t.Errorf("expected 1 new finding, got %v", report.NewFindings)
	}
}
