package apiserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/bytezora/recon-x/internal/finding"
	"github.com/bytezora/recon-x/internal/rbac"
	"github.com/bytezora/recon-x/internal/workspace"
)

func TestAPIServerAuthAndWorkspaceRoutes(t *testing.T) {
	root := t.TempDir()
	_, err := workspace.InitProject(root, "acme-api", "Acme API")
	if err != nil {
		t.Fatal(err)
	}
	scanPath := filepath.Join(root, "scan.json")
	writeAPIScan(t, scanPath)
	meta, err := workspace.ImportScan(root, "acme-api", scanPath, workspace.ImportOptions{Profile: "ci"})
	if err != nil {
		t.Fatal(err)
	}

	srv := New(Config{
		StoreDir: root,
		Version:  "test",
		Tokens: []Token{
			{Value: "owner-token", Actor: rbac.Actor{ID: "owner", Role: rbac.Owner, Projects: []string{"*"}}},
			{Value: "viewer-token", Actor: rbac.Actor{ID: "viewer", Role: rbac.Viewer, Projects: []string{"acme-api"}}},
		},
	})
	handler := srv.Handler()

	resp := request(handler, http.MethodGet, "/v1/projects", "viewer-token", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("projects status=%d body=%s", resp.Code, resp.Body.String())
	}
	if !bytes.Contains(resp.Body.Bytes(), []byte("acme-api")) {
		t.Fatalf("project missing: %s", resp.Body.String())
	}

	resp = request(handler, http.MethodPost, "/v1/projects", "viewer-token", []byte(`{"id":"new"}`))
	if resp.Code != http.StatusForbidden {
		t.Fatalf("viewer create status=%d", resp.Code)
	}

	resp = request(handler, http.MethodGet, "/v1/projects/acme-api/findings", "viewer-token", nil)
	if resp.Code != http.StatusOK || !bytes.Contains(resp.Body.Bytes(), []byte("repo-secret")) {
		t.Fatalf("findings response status=%d body=%s", resp.Code, resp.Body.String())
	}

	resp = request(handler, http.MethodGet, "/v1/projects/acme-api/scans/"+meta.ID+"/artifact", "viewer-token", nil)
	if resp.Code != http.StatusOK || !bytes.Contains(resp.Body.Bytes(), []byte("repo-secret")) {
		t.Fatalf("artifact response status=%d body=%s", resp.Code, resp.Body.String())
	}

	resp = request(handler, http.MethodPatch, "/v1/projects/acme-api/findings/rx1:a", "viewer-token", []byte(`{"status":"accepted"}`))
	if resp.Code != http.StatusForbidden {
		t.Fatalf("viewer triage status=%d body=%s", resp.Code, resp.Body.String())
	}

	resp = request(handler, http.MethodPatch, "/v1/projects/acme-api/findings/rx1:a", "owner-token", []byte(`{"status":"accepted","note":"known test fixture"}`))
	if resp.Code != http.StatusOK || !bytes.Contains(resp.Body.Bytes(), []byte(`"status": "accepted"`)) {
		t.Fatalf("owner triage status=%d body=%s", resp.Code, resp.Body.String())
	}

	resp = request(handler, http.MethodPut, "/v1/projects/acme-api/quota", "owner-token", []byte(`{"max_scans":1}`))
	if resp.Code != http.StatusOK || !bytes.Contains(resp.Body.Bytes(), []byte(`"max_scans": 1`)) {
		t.Fatalf("quota status=%d body=%s", resp.Code, resp.Body.String())
	}

	resp = request(handler, http.MethodGet, "/v1/projects/acme-api/audit", "owner-token", nil)
	if resp.Code != http.StatusOK || !bytes.Contains(resp.Body.Bytes(), []byte("finding.triage")) {
		t.Fatalf("audit response status=%d body=%s", resp.Code, resp.Body.String())
	}

	resp = request(handler, http.MethodGet, "/v1/projects", "", nil)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("missing auth status=%d", resp.Code)
	}
}

func TestParseTokenSpecs(t *testing.T) {
	tokens, err := ParseTokenSpecs("abc:admin:acme-api|billing,xyz:viewer:*")
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 || tokens[0].Actor.Role != rbac.Admin || len(tokens[0].Actor.Projects) != 2 {
		t.Fatalf("unexpected tokens: %+v", tokens)
	}
}

func request(handler http.Handler, method, path, token string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func writeAPIScan(t *testing.T, path string) {
	t.Helper()
	doc := map[string]interface{}{
		"target":       "repo:/tmp/acme",
		"generated_at": "2026-06-15T00:00:00Z",
		"source": map[string]interface{}{
			"root": "/tmp/acme",
			"findings": []finding.Finding{
				{Fingerprint: "rx1:a", Type: "repo-secret", Severity: finding.High, RiskScore: 80},
			},
		},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
