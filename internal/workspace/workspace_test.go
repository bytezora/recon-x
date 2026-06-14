package workspace

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bytezora/recon-x/internal/finding"
)

func TestInitImportListAndExportProject(t *testing.T) {
	root := t.TempDir()
	pf, err := InitProject(root, "acme-api", "Acme API")
	if err != nil {
		t.Fatal(err)
	}
	if pf.Project.ID != "acme-api" || pf.Project.Name != "Acme API" {
		t.Fatalf("unexpected project: %+v", pf.Project)
	}

	scanPath := filepath.Join(root, "scan.json")
	writeScan(t, scanPath, scanDocument{
		Target:      "repo:C:/work/acme",
		GeneratedAt: "2026-06-15T00:00:00Z",
		Source: struct {
			Root     string            `json:"root"`
			Findings []finding.Finding `json:"findings"`
		}{
			Root: "C:/work/acme",
			Findings: []finding.Finding{
				{Fingerprint: "rx1:a", Severity: finding.High, RiskScore: 80},
				{Fingerprint: "rx1:b", Severity: finding.Medium, RiskScore: 50},
			},
		},
	})

	meta, err := ImportScan(root, "acme-api", scanPath, ImportOptions{Profile: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	if meta.TargetType != "repo" || meta.Findings != 2 || meta.SeverityCounts["high"] != 1 {
		t.Fatalf("unexpected meta: %+v", meta)
	}
	if _, err := os.Stat(filepath.FromSlash(meta.ReportPath)); err != nil {
		t.Fatalf("copied scan missing: %v", err)
	}

	projects, err := ListProjects(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(projects) != 1 || projects[0].ScanCount != 1 || !projects[0].SourceReady {
		t.Fatalf("unexpected projects: %+v", projects)
	}

	out := filepath.Join(root, "export.json")
	ex, err := WriteExport(root, "acme-api", out)
	if err != nil {
		t.Fatal(err)
	}
	if ex.Project.ID != "acme-api" || len(ex.Scans) != 1 {
		t.Fatalf("unexpected export: %+v", ex)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("export file missing: %v", err)
	}

	loaded, raw, err := LoadScan(root, "acme-api", meta.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != meta.ID || len(raw) == 0 {
		t.Fatalf("unexpected loaded scan: %+v raw=%d", loaded, len(raw))
	}
	_, findings, err := LoadScanFindings(root, "acme-api", meta.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	state, err := UpdateFindingTriage(root, "acme-api", "rx1:a", TriageUpdate{Status: "accepted"}, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "accepted" || state.UpdatedBy != "tester" {
		t.Fatalf("unexpected triage state: %+v", state)
	}

	if err := AppendAudit(root, AuditEvent{
		ActorID:      "tester",
		Role:         "admin",
		Action:       "finding.triage",
		ProjectID:    "acme-api",
		ResourceType: "finding",
		ResourceID:   "rx1:a",
		Outcome:      "success",
	}); err != nil {
		t.Fatal(err)
	}
	events, err := ListAudit(root, "acme-api", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != "finding.triage" {
		t.Fatalf("unexpected audit events: %+v", events)
	}

	if _, err := SetQuota(root, "acme-api", Quota{MaxScans: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportScan(root, "acme-api", scanPath, ImportOptions{Profile: "ci"}); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("expected quota error, got %v", err)
	}
}

func TestInvalidProjectID(t *testing.T) {
	if _, err := InitProject(t.TempDir(), "../bad", "Bad"); err == nil {
		t.Fatal("expected invalid project id error")
	}
}

func writeScan(t *testing.T, path string, doc scanDocument) {
	t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
