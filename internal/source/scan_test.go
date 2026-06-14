package source

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanFindsSecretsRoutesAndManifests(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{"name":"demo","dependencies":{"express":"^4.18.0"}}`)
	writeFile(t, filepath.Join(dir, "server.js"), `
const api_key = "1234567890abcdef1234567890abcdef";
app.get("/api/users", handler);
`)

	res, err := Scan(Config{Path: dir, BaseURL: "http://localhost:3000"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(res.Manifests))
	}
	if len(res.Routes) != 1 || res.Routes[0].LiveURL != "http://localhost:3000/api/users" {
		t.Fatalf("unexpected routes: %+v", res.Routes)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected findings")
	}
	var foundSecret bool
	for _, f := range res.Findings {
		if f.Type == "repo-secret" {
			foundSecret = true
			if strings.Contains(f.Evidence, "1234567890abcdef") {
				t.Fatalf("secret was not redacted: %s", f.Evidence)
			}
			if f.Fingerprint == "" {
				t.Fatal("expected fingerprint")
			}
		}
	}
	if !foundSecret {
		t.Fatalf("expected repo-secret finding, got %+v", res.Findings)
	}
}

func TestScanHonorsScannerSelection(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "server.js"), `
const api_key = "1234567890abcdef1234567890abcdef";
app.get("/api/users", handler);
`)

	res, err := Scan(Config{Path: dir, Scanners: []string{"routes"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.Type == "repo-secret" {
			t.Fatalf("secret scanner should be disabled, got %+v", f)
		}
	}
	if len(res.Routes) != 1 {
		t.Fatalf("expected route discovery, got %+v", res.Routes)
	}
}

func TestScanConfigTLSRulesAvoidSafeVerificationValues(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.yml"), `
verify_ssl: true
ssl_verify: true
insecure_skip_verify: false
rejectUnauthorized: true
`)

	res, err := Scan(Config{Path: dir, Scanners: []string{"config"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Title, "Disabled TLS verification") {
			t.Fatalf("safe TLS verification setting was flagged: %+v", f)
		}
	}
}

func TestScanConfigTLSRulesFindDisabledVerification(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.yml"), `
verify_ssl: false
insecure_skip_verify: true
`)

	res, err := Scan(Config{Path: dir, Scanners: []string{"config"}})
	if err != nil {
		t.Fatal(err)
	}
	var count int
	for _, f := range res.Findings {
		if strings.Contains(f.Title, "Disabled TLS verification") {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("expected 2 disabled TLS findings, got %d: %+v", count, res.Findings)
	}
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}
