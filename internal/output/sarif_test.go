package output

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/bytezora/recon-x/internal/cors"
	"github.com/bytezora/recon-x/internal/defaultcreds"
	"github.com/bytezora/recon-x/internal/sqli"
	"github.com/bytezora/recon-x/internal/takeover"
	"github.com/bytezora/recon-x/internal/templates"
	"github.com/bytezora/recon-x/internal/vulns"
)

func TestWriteSARIF_Empty(t *testing.T) {
	f, err := os.CreateTemp("", "sarif-*.json")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	f.Close()
	t.Cleanup(func() { os.Remove(name) })

	err = WriteSARIF(name, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", log.Version)
	}
}

func TestWriteSARIF_WithCVE(t *testing.T) {
	f, err := os.CreateTemp("", "sarif-*.json")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	f.Close()
	t.Cleanup(func() { os.Remove(name) })

	cves := []vulns.Match{
		{Host: "example.com", Port: 443, CVE: "CVE-2021-41773", Severity: "CRITICAL", Description: "test"},
	}
	err = WriteSARIF(name, cves, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(log.Runs) == 0 || len(log.Runs[0].Results) == 0 {
		t.Fatal("expected at least one result")
	}
	if log.Runs[0].Results[0].RuleID != "CVE-2021-41773" {
		t.Errorf("expected CVE-2021-41773, got %s", log.Runs[0].Results[0].RuleID)
	}
	if log.Runs[0].Results[0].Level != "error" {
		t.Errorf("expected level error for CRITICAL, got %s", log.Runs[0].Results[0].Level)
	}
}

func TestWriteSARIF_WithSQLi(t *testing.T) {
	f, err := os.CreateTemp("", "sarif-*.json")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	f.Close()
	t.Cleanup(func() { os.Remove(name) })

	sqliRes := []sqli.Result{
		{URL: "http://example.com/?id=1", Param: "id", Payload: "'", Evidence: "syntax error", Detected: true},
	}
	err = WriteSARIF(name, nil, sqliRes, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(log.Runs[0].Results) == 0 {
		t.Fatal("expected SQLi result")
	}
	_ = cors.Result{}
	_ = defaultcreds.Result{}
	_ = takeover.Result{}
	_ = templates.Match{}
}
