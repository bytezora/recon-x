package apiserver

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bytezora/recon-x/internal/rbac"
	"github.com/bytezora/recon-x/internal/workspace"
)

type Config struct {
	StoreDir string
	Version  string
	Tokens   []Token
}

type Token struct {
	Value string     `json:"-"`
	Actor rbac.Actor `json:"actor"`
}

type Server struct {
	cfg Config
}

type errorResponse struct {
	Error string `json:"error"`
}

func New(cfg Config) *Server {
	return &Server{cfg: cfg}
}

func ParseTokenSpecs(spec string) ([]Token, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	var tokens []Token
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.Split(item, ":")
		if len(parts) < 2 || strings.TrimSpace(parts[0]) == "" {
			return nil, fmt.Errorf("invalid api token spec %q; use token:role[:project1|project2|*]", item)
		}
		actor := rbac.Actor{
			ID:   "token:" + shortToken(parts[0]),
			Role: rbac.NormalizeRole(parts[1]),
		}
		if len(parts) >= 3 && strings.TrimSpace(parts[2]) != "" {
			actor.Projects = splitProjects(parts[2])
		}
		tokens = append(tokens, Token{Value: parts[0], Actor: actor})
	}
	return tokens, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/v1/roles", s.withAuth("", rbac.ProjectRead, s.roles))
	mux.HandleFunc("/v1/projects", s.withAuth("", rbac.ProjectRead, s.projects))
	mux.HandleFunc("/v1/projects/", s.projectResource)
	return securityHeaders(mux)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": s.cfg.Version,
	})
}

func (s *Server) roles(w http.ResponseWriter, r *http.Request, actor rbac.Actor, _ string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"actor":  actor,
		"policy": rbac.Policy(),
	})
}

func (s *Server) projects(w http.ResponseWriter, r *http.Request, actor rbac.Actor, _ string) {
	switch r.Method {
	case http.MethodGet:
		projects, err := workspace.ListProjects(s.cfg.StoreDir)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		filtered := projects[:0]
		for _, p := range projects {
			if rbac.ProjectAllowed(actor, p.ID) {
				filtered = append(filtered, p)
			}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"projects": filtered})
	case http.MethodPost:
		if !rbac.Check(actor, rbac.ProjectCreate, "").Allowed {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		var req struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		pf, err := workspace.InitProject(s.cfg.StoreDir, req.ID, req.Name)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		_ = workspace.AppendAudit(s.cfg.StoreDir, auditEvent(actor, "project.create", pf.Project.ID, "project", pf.Project.ID, "success", ""))
		writeJSON(w, http.StatusCreated, pf)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) projectResource(w http.ResponseWriter, r *http.Request) {
	parts := splitPath(strings.TrimPrefix(r.URL.Path, "/v1/projects/"))
	if len(parts) == 0 {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	projectID := parts[0]

	if len(parts) == 1 {
		s.withAuth(projectID, rbac.ProjectRead, s.projectShow)(w, r)
		return
	}
	if parts[1] == "audit" {
		s.withAuth(projectID, rbac.AuditRead, s.projectAudit)(w, r)
		return
	}
	if parts[1] == "quota" {
		perm := rbac.QuotaRead
		if r.Method == http.MethodPut || r.Method == http.MethodPatch {
			perm = rbac.QuotaUpdate
		}
		s.withAuth(projectID, perm, s.projectQuota)(w, r)
		return
	}
	if parts[1] != "scans" && parts[1] != "findings" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if parts[1] == "findings" {
		if len(parts) == 2 {
			s.withAuth(projectID, rbac.FindingRead, s.projectFindings)(w, r)
			return
		}
		perm := rbac.FindingRead
		if r.Method == http.MethodPatch || r.Method == http.MethodPut {
			perm = rbac.FindingTriage
		}
		s.withAuth(projectID, perm, s.projectFinding(parts[2]))(w, r)
		return
	}
	if len(parts) == 2 {
		s.withAuth(projectID, rbac.ScanRead, s.projectScans)(w, r)
		return
	}
	if len(parts) == 3 && parts[2] == "import" {
		s.withAuth(projectID, rbac.ScanCreate, s.projectImportScan)(w, r)
		return
	}
	if len(parts) >= 3 {
		if len(parts) == 4 && parts[3] == "artifact" {
			s.withAuth(projectID, rbac.ArtifactRead, s.scanArtifact(parts[2]))(w, r)
			return
		}
		s.withAuth(projectID, rbac.ScanRead, s.scanShow(parts[2]))(w, r)
		return
	}
	writeError(w, http.StatusNotFound, "not found")
}

func (s *Server) projectShow(w http.ResponseWriter, r *http.Request, _ rbac.Actor, projectID string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	pf, err := workspace.LoadProject(s.cfg.StoreDir, projectID)
	if err != nil {
		writeWorkspaceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pf)
}

func (s *Server) projectScans(w http.ResponseWriter, r *http.Request, _ rbac.Actor, projectID string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	pf, err := workspace.LoadProject(s.cfg.StoreDir, projectID)
	if err != nil {
		writeWorkspaceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"scans": pf.Scans})
}

func (s *Server) projectImportScan(w http.ResponseWriter, r *http.Request, actor rbac.Actor, projectID string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		ScanPath string `json:"scan_path"`
		Name     string `json:"name"`
		Profile  string `json:"profile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.ScanPath) == "" {
		writeError(w, http.StatusBadRequest, "scan_path is required")
		return
	}
	meta, err := workspace.ImportScan(s.cfg.StoreDir, projectID, req.ScanPath, workspace.ImportOptions{Name: req.Name, Profile: req.Profile})
	if err != nil {
		if errors.Is(err, workspace.ErrQuotaExceeded) {
			writeError(w, http.StatusTooManyRequests, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = workspace.AppendAudit(s.cfg.StoreDir, auditEvent(actor, "scan.import", projectID, "scan", meta.ID, "success", ""))
	writeJSON(w, http.StatusCreated, meta)
}

func (s *Server) scanShow(scanID string) func(http.ResponseWriter, *http.Request, rbac.Actor, string) {
	return func(w http.ResponseWriter, r *http.Request, _ rbac.Actor, projectID string) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		meta, _, err := workspace.LoadScan(s.cfg.StoreDir, projectID, scanID)
		if err != nil {
			writeWorkspaceError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, meta)
	}
}

func (s *Server) scanArtifact(scanID string) func(http.ResponseWriter, *http.Request, rbac.Actor, string) {
	return func(w http.ResponseWriter, r *http.Request, _ rbac.Actor, projectID string) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		meta, raw, err := workspace.LoadScan(s.cfg.StoreDir, projectID, scanID)
		if err != nil {
			writeWorkspaceError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="`+meta.ID+`.json"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
	}
}

func (s *Server) projectFindings(w http.ResponseWriter, r *http.Request, _ rbac.Actor, projectID string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	pf, err := workspace.LoadProject(s.cfg.StoreDir, projectID)
	if err != nil {
		writeWorkspaceError(w, err)
		return
	}
	if len(pf.Scans) == 0 {
		writeJSON(w, http.StatusOK, map[string]interface{}{"findings": []interface{}{}})
		return
	}
	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		scanID = pf.Scans[0].ID
	}
	meta, findings, err := workspace.LoadScanFindings(s.cfg.StoreDir, projectID, scanID)
	if err != nil {
		writeWorkspaceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"scan":     meta,
		"findings": findings,
		"triage":   pf.Findings,
	})
}

func (s *Server) projectFinding(fingerprint string) func(http.ResponseWriter, *http.Request, rbac.Actor, string) {
	return func(w http.ResponseWriter, r *http.Request, actor rbac.Actor, projectID string) {
		pf, err := workspace.LoadProject(s.cfg.StoreDir, projectID)
		if err != nil {
			writeWorkspaceError(w, err)
			return
		}
		state, ok := pf.Findings[fingerprint]
		if !ok {
			writeError(w, http.StatusNotFound, "finding not found")
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, state)
		case http.MethodPatch, http.MethodPut:
			var req struct {
				Status   string  `json:"status"`
				Assignee *string `json:"assignee"`
				Note     *string `json:"note"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			updated, err := workspace.UpdateFindingTriage(s.cfg.StoreDir, projectID, fingerprint, workspace.TriageUpdate{
				Status:   req.Status,
				Assignee: req.Assignee,
				Note:     req.Note,
			}, actor.ID)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			_ = workspace.AppendAudit(s.cfg.StoreDir, auditEvent(actor, "finding.triage", projectID, "finding", fingerprint, "success", ""))
			writeJSON(w, http.StatusOK, updated)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func (s *Server) projectQuota(w http.ResponseWriter, r *http.Request, actor rbac.Actor, projectID string) {
	pf, err := workspace.LoadProject(s.cfg.StoreDir, projectID)
	if err != nil {
		writeWorkspaceError(w, err)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, pf.Project.Quota)
	case http.MethodPut, http.MethodPatch:
		var quota workspace.Quota
		if err := json.NewDecoder(r.Body).Decode(&quota); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		project, err := workspace.SetQuota(s.cfg.StoreDir, projectID, quota)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		_ = workspace.AppendAudit(s.cfg.StoreDir, auditEvent(actor, "quota.update", projectID, "project", projectID, "success", ""))
		writeJSON(w, http.StatusOK, project.Quota)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) projectAudit(w http.ResponseWriter, r *http.Request, _ rbac.Actor, projectID string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	events, err := workspace.ListAudit(s.cfg.StoreDir, projectID, 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"events": events})
}

func (s *Server) withAuth(projectID string, permission rbac.Permission, next func(http.ResponseWriter, *http.Request, rbac.Actor, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, err := s.authenticate(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}
		if permission != "" {
			decision := rbac.Check(actor, permission, projectID)
			if !decision.Allowed {
				writeError(w, http.StatusForbidden, decision.Reason)
				return
			}
		}
		next(w, r, actor, projectID)
	}
}

func (s *Server) authenticate(r *http.Request) (rbac.Actor, error) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return rbac.Actor{}, errors.New("missing bearer token")
	}
	token := strings.TrimSpace(header[len("Bearer "):])
	for _, item := range s.cfg.Tokens {
		if subtle.ConstantTimeCompare([]byte(token), []byte(item.Value)) == 1 {
			return item.Actor, nil
		}
	}
	return rbac.Actor{}, errors.New("invalid bearer token")
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func splitPath(path string) []string {
	var out []string
	for _, part := range strings.Split(path, "/") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func splitProjects(s string) []string {
	var out []string
	for _, item := range strings.FieldsFunc(s, func(r rune) bool { return r == '|' || r == ';' }) {
		item = strings.ToLower(strings.TrimSpace(item))
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func shortToken(token string) string {
	if len(token) <= 6 {
		return token
	}
	return token[:3] + "..." + token[len(token)-3:]
}

func auditEvent(actor rbac.Actor, action, projectID, resourceType, resourceID, outcome, reason string) workspace.AuditEvent {
	return workspace.AuditEvent{
		ActorID:      actor.ID,
		Role:         string(actor.Role),
		Action:       action,
		ProjectID:    projectID,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Outcome:      outcome,
		Reason:       reason,
	}
}

func writeWorkspaceError(w http.ResponseWriter, err error) {
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeError(w, http.StatusInternalServerError, err.Error())
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorResponse{Error: message})
}

func ListenAndServe(listen string, cfg Config) error {
	server := &http.Server{
		Addr:              listen,
		Handler:           New(cfg).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return server.ListenAndServe()
}
