package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/bytezora/recon-x/internal/finding"
)

const (
	DefaultDir = ".reconx"
	Version    = 1
)

var ErrQuotaExceeded = errors.New("workspace quota exceeded")

type Project struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	CreatedAt      string         `json:"created_at"`
	UpdatedAt      string         `json:"updated_at"`
	LastScanAt     string         `json:"last_scan_at,omitempty"`
	LastScanID     string         `json:"last_scan_id,omitempty"`
	LastTarget     string         `json:"last_target,omitempty"`
	LastTargetType string         `json:"last_target_type,omitempty"`
	ScanCount      int            `json:"scan_count"`
	LatestFindings int            `json:"latest_findings"`
	SeverityCounts map[string]int `json:"severity_counts,omitempty"`
	TopRiskScore   int            `json:"top_risk_score,omitempty"`
	AcceptedRisk   int            `json:"accepted_risk,omitempty"`
	OpenCritical   int            `json:"open_critical,omitempty"`
	OpenHigh       int            `json:"open_high,omitempty"`
	OpenMedium     int            `json:"open_medium,omitempty"`
	SourceReady    bool           `json:"source_ready"`
	DomainReady    bool           `json:"domain_ready"`
	Quota          Quota          `json:"quota,omitempty"`
	RBACReadyHint  string         `json:"rbac_ready_hint,omitempty"`
}

type Quota struct {
	MaxScans           int `json:"max_scans,omitempty"`
	MaxFindingsPerScan int `json:"max_findings_per_scan,omitempty"`
}

type ScanMeta struct {
	ID             string         `json:"id"`
	ProjectID      string         `json:"project_id"`
	Target         string         `json:"target"`
	TargetType     string         `json:"target_type"`
	Profile        string         `json:"profile,omitempty"`
	GeneratedAt    string         `json:"generated_at,omitempty"`
	ImportedAt     string         `json:"imported_at"`
	SourceRoot     string         `json:"source_root,omitempty"`
	ReportPath     string         `json:"report_path"`
	Findings       int            `json:"findings"`
	SeverityCounts map[string]int `json:"severity_counts,omitempty"`
	TopRiskScore   int            `json:"top_risk_score,omitempty"`
	Fingerprints   []string       `json:"fingerprints,omitempty"`
}

type ProjectFile struct {
	Version  int                     `json:"version"`
	Project  Project                 `json:"project"`
	Scans    []ScanMeta              `json:"scans"`
	Findings map[string]FindingState `json:"findings,omitempty"`
}

type Export struct {
	Version    int                     `json:"version"`
	ExportedAt string                  `json:"exported_at"`
	Project    Project                 `json:"project"`
	Scans      []ScanMeta              `json:"scans"`
	Findings   map[string]FindingState `json:"findings,omitempty"`
	Notes      []string                `json:"notes,omitempty"`
}

type ImportOptions struct {
	Name    string
	Profile string
}

type FindingState struct {
	Fingerprint    string           `json:"fingerprint"`
	Status         string           `json:"status"`
	Severity       finding.Severity `json:"severity"`
	Type           string           `json:"type"`
	Title          string           `json:"title"`
	AffectedURL    string           `json:"affected_url"`
	FirstSeenScan  string           `json:"first_seen_scan"`
	LastSeenScan   string           `json:"last_seen_scan"`
	FirstSeenAt    string           `json:"first_seen_at"`
	LastSeenAt     string           `json:"last_seen_at"`
	UpdatedAt      string           `json:"updated_at,omitempty"`
	UpdatedBy      string           `json:"updated_by,omitempty"`
	Assignee       string           `json:"assignee,omitempty"`
	Note           string           `json:"note,omitempty"`
	RiskScore      int              `json:"risk_score,omitempty"`
	ManualRequired bool             `json:"manual_verification,omitempty"`
	CVE            string           `json:"cve,omitempty"`
}

type TriageUpdate struct {
	Status   string
	Assignee *string
	Note     *string
}

type AuditEvent struct {
	ID           string            `json:"id"`
	Time         string            `json:"time"`
	ActorID      string            `json:"actor_id,omitempty"`
	Role         string            `json:"role,omitempty"`
	Action       string            `json:"action"`
	ProjectID    string            `json:"project_id,omitempty"`
	ResourceType string            `json:"resource_type,omitempty"`
	ResourceID   string            `json:"resource_id,omitempty"`
	Outcome      string            `json:"outcome"`
	Reason       string            `json:"reason,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type scanDocument struct {
	Target      string            `json:"target"`
	GeneratedAt string            `json:"generated_at"`
	Findings    []finding.Finding `json:"findings"`
	Source      struct {
		Root     string            `json:"root"`
		Findings []finding.Finding `json:"findings"`
	} `json:"source"`
}

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

func InitProject(root, id, name string) (ProjectFile, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	if !ValidProjectID(id) {
		return ProjectFile{}, fmt.Errorf("invalid project id %q; use lowercase letters, numbers, dots, dashes or underscores", id)
	}
	if strings.TrimSpace(name) == "" {
		name = id
	}
	now := time.Now().UTC().Format(time.RFC3339)
	pf := ProjectFile{
		Version:  Version,
		Findings: map[string]FindingState{},
		Project: Project{
			ID:             id,
			Name:           strings.TrimSpace(name),
			CreatedAt:      now,
			UpdatedAt:      now,
			SeverityCounts: map[string]int{},
			RBACReadyHint:  "map this project to organization/project membership in the API layer",
		},
	}
	if err := os.MkdirAll(projectDir(root, id), 0o755); err != nil {
		return ProjectFile{}, err
	}
	path := projectFile(root, id)
	if _, err := os.Stat(path); err == nil {
		return ProjectFile{}, fmt.Errorf("project %q already exists", id)
	} else if !os.IsNotExist(err) {
		return ProjectFile{}, err
	}
	if err := writeJSON(path, pf); err != nil {
		return ProjectFile{}, err
	}
	return pf, nil
}

func ImportScan(root, projectID, scanPath string, opts ImportOptions) (ScanMeta, error) {
	projectID = strings.ToLower(strings.TrimSpace(projectID))
	if !ValidProjectID(projectID) {
		return ScanMeta{}, fmt.Errorf("invalid project id %q", projectID)
	}
	raw, err := os.ReadFile(scanPath)
	if err != nil {
		return ScanMeta{}, err
	}
	doc, findings, targetType := parseScan(raw)
	if targetType == "" {
		targetType = "domain"
	}
	if doc.Target == "" {
		doc.Target = "unknown"
	}

	pf, err := LoadProject(root, projectID)
	if err != nil {
		if !os.IsNotExist(err) {
			return ScanMeta{}, err
		}
		pf, err = InitProject(root, projectID, opts.Name)
		if err != nil {
			return ScanMeta{}, err
		}
	} else if strings.TrimSpace(opts.Name) != "" && pf.Project.Name == projectID {
		pf.Project.Name = strings.TrimSpace(opts.Name)
	}
	if err := checkQuota(pf.Project.Quota, len(pf.Scans), len(findings)); err != nil {
		return ScanMeta{}, err
	}

	now := time.Now().UTC()
	sum := sha256.Sum256(raw)
	short := hex.EncodeToString(sum[:])[:10]
	id := fmt.Sprintf("%s-%s", now.Format("20060102T150405Z"), short)
	dest := filepath.Join(projectDir(root, projectID), "scans", id+".json")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return ScanMeta{}, err
	}
	if err := os.WriteFile(dest, raw, 0o600); err != nil {
		return ScanMeta{}, err
	}

	counts := CountSeverities(findings)
	meta := ScanMeta{
		ID:             id,
		ProjectID:      projectID,
		Target:         doc.Target,
		TargetType:     targetType,
		Profile:        opts.Profile,
		GeneratedAt:    doc.GeneratedAt,
		ImportedAt:     now.Format(time.RFC3339),
		SourceRoot:     doc.Source.Root,
		ReportPath:     filepath.ToSlash(dest),
		Findings:       len(findings),
		SeverityCounts: counts,
		TopRiskScore:   topRisk(findings),
		Fingerprints:   fingerprints(findings),
	}
	pf.Scans = append(pf.Scans, meta)
	updateProjectFromScan(&pf.Project, meta)
	updateFindingIndex(&pf, meta, findings)
	updateProjectFromTriage(&pf.Project, pf.Findings)
	if err := writeJSON(projectFile(root, projectID), pf); err != nil {
		return ScanMeta{}, err
	}
	return meta, nil
}

func ListProjects(root string) ([]Project, error) {
	base := filepath.Join(rootOrDefault(root), "projects")
	entries, err := os.ReadDir(base)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var projects []Project
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pf, err := LoadProject(root, entry.Name())
		if err == nil {
			projects = append(projects, pf.Project)
		}
	}
	sort.Slice(projects, func(i, j int) bool { return projects[i].ID < projects[j].ID })
	return projects, nil
}

func LoadProject(root, id string) (ProjectFile, error) {
	var pf ProjectFile
	data, err := os.ReadFile(projectFile(root, strings.ToLower(strings.TrimSpace(id))))
	if err != nil {
		return ProjectFile{}, err
	}
	if err := json.Unmarshal(data, &pf); err != nil {
		return ProjectFile{}, err
	}
	if pf.Findings == nil {
		pf.Findings = map[string]FindingState{}
	}
	sort.Slice(pf.Scans, func(i, j int) bool { return pf.Scans[i].ImportedAt > pf.Scans[j].ImportedAt })
	return pf, nil
}

func LoadScan(root, projectID, scanID string) (ScanMeta, []byte, error) {
	projectID = strings.ToLower(strings.TrimSpace(projectID))
	scanID = strings.TrimSpace(scanID)
	if !ValidProjectID(projectID) {
		return ScanMeta{}, nil, fmt.Errorf("invalid project id %q", projectID)
	}
	pf, err := LoadProject(root, projectID)
	if err != nil {
		return ScanMeta{}, nil, err
	}
	var meta ScanMeta
	for _, scan := range pf.Scans {
		if scan.ID == scanID {
			meta = scan
			break
		}
	}
	if meta.ID == "" {
		return ScanMeta{}, nil, os.ErrNotExist
	}
	raw, err := os.ReadFile(scanFile(root, projectID, scanID))
	if err != nil {
		return ScanMeta{}, nil, err
	}
	return meta, raw, nil
}

func LoadScanFindings(root, projectID, scanID string) (ScanMeta, []finding.Finding, error) {
	meta, raw, err := LoadScan(root, projectID, scanID)
	if err != nil {
		return ScanMeta{}, nil, err
	}
	_, findings, _ := parseScan(raw)
	return meta, findings, nil
}

func WriteExport(root, id, out string) (Export, error) {
	pf, err := LoadProject(root, id)
	if err != nil {
		return Export{}, err
	}
	ex := Export{
		Version:    Version,
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
		Project:    pf.Project,
		Scans:      pf.Scans,
		Findings:   pf.Findings,
		Notes: []string{
			"Export contains project and scan metadata only; raw scan JSON files remain in the workspace scans directory.",
			"Use scan fingerprints as stable identifiers for triage, RBAC audit events and baseline policy.",
		},
	}
	if out != "" {
		if err := writeJSON(out, ex); err != nil {
			return Export{}, err
		}
	}
	return ex, nil
}

func SetQuota(root, projectID string, quota Quota) (Project, error) {
	pf, err := LoadProject(root, projectID)
	if err != nil {
		return Project{}, err
	}
	if quota.MaxScans < 0 || quota.MaxFindingsPerScan < 0 {
		return Project{}, fmt.Errorf("quota values must be non-negative")
	}
	pf.Project.Quota = quota
	pf.Project.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := writeJSON(projectFile(root, pf.Project.ID), pf); err != nil {
		return Project{}, err
	}
	return pf.Project, nil
}

func UpdateFindingTriage(root, projectID, fingerprint string, update TriageUpdate, actorID string) (FindingState, error) {
	pf, err := LoadProject(root, projectID)
	if err != nil {
		return FindingState{}, err
	}
	fingerprint = strings.TrimSpace(fingerprint)
	state, ok := pf.Findings[fingerprint]
	if !ok {
		return FindingState{}, os.ErrNotExist
	}
	if strings.TrimSpace(update.Status) != "" {
		status := normalizeStatus(update.Status)
		if status == "" {
			return FindingState{}, fmt.Errorf("invalid finding status %q", update.Status)
		}
		state.Status = status
	}
	if update.Assignee != nil {
		state.Assignee = strings.TrimSpace(*update.Assignee)
	}
	if update.Note != nil {
		state.Note = strings.TrimSpace(*update.Note)
	}
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	state.UpdatedBy = strings.TrimSpace(actorID)
	pf.Findings[fingerprint] = state
	updateProjectFromTriage(&pf.Project, pf.Findings)
	if err := writeJSON(projectFile(root, pf.Project.ID), pf); err != nil {
		return FindingState{}, err
	}
	return state, nil
}

func AppendAudit(root string, event AuditEvent) error {
	event.ProjectID = strings.ToLower(strings.TrimSpace(event.ProjectID))
	if event.ProjectID == "" || !ValidProjectID(event.ProjectID) {
		return fmt.Errorf("valid project id is required for audit events")
	}
	now := time.Now().UTC()
	if event.Time == "" {
		event.Time = now.Format(time.RFC3339)
	}
	if event.ID == "" {
		sum := sha256.Sum256([]byte(event.Time + event.ActorID + event.Action + event.ProjectID + event.ResourceID + event.Outcome))
		event.ID = now.Format("20060102T150405Z") + "-" + hex.EncodeToString(sum[:])[:10]
	}
	if event.Outcome == "" {
		event.Outcome = "success"
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	path := auditFile(root, event.ProjectID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

func ListAudit(root, projectID string, limit int) ([]AuditEvent, error) {
	projectID = strings.ToLower(strings.TrimSpace(projectID))
	if !ValidProjectID(projectID) {
		return nil, fmt.Errorf("invalid project id %q", projectID)
	}
	data, err := os.ReadFile(auditFile(root, projectID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var events []AuditEvent
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var event AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err == nil {
			events = append(events, event)
		}
	}
	if limit > 0 && len(events) > limit {
		events = events[len(events)-limit:]
	}
	return events, nil
}

func ValidProjectID(id string) bool {
	return slugRE.MatchString(id)
}

func CountSeverities(findings []finding.Finding) map[string]int {
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range findings {
		sev := strings.ToLower(string(f.Severity))
		if _, ok := counts[sev]; !ok {
			counts[sev] = 0
		}
		counts[sev]++
	}
	return counts
}

func parseScan(raw []byte) (scanDocument, []finding.Finding, string) {
	var doc scanDocument
	_ = json.Unmarshal(raw, &doc)
	findings := doc.Findings
	targetType := "domain"
	if doc.Source.Root != "" || len(doc.Source.Findings) > 0 || strings.HasPrefix(doc.Target, "repo:") {
		targetType = "repo"
		if len(findings) == 0 {
			findings = doc.Source.Findings
		}
	}
	return doc, findings, targetType
}

func updateProjectFromScan(project *Project, scan ScanMeta) {
	project.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	project.LastScanAt = scan.ImportedAt
	project.LastScanID = scan.ID
	project.LastTarget = scan.Target
	project.LastTargetType = scan.TargetType
	project.ScanCount++
	project.LatestFindings = scan.Findings
	project.SeverityCounts = scan.SeverityCounts
	project.TopRiskScore = scan.TopRiskScore
	project.OpenCritical = scan.SeverityCounts["critical"]
	project.OpenHigh = scan.SeverityCounts["high"]
	project.OpenMedium = scan.SeverityCounts["medium"]
	if scan.TargetType == "repo" {
		project.SourceReady = true
	}
	if scan.TargetType == "domain" {
		project.DomainReady = true
	}
	if project.RBACReadyHint == "" {
		project.RBACReadyHint = "map this project to organization/project membership in the API layer"
	}
}

func updateFindingIndex(pf *ProjectFile, scan ScanMeta, findings []finding.Finding) {
	if pf.Findings == nil {
		pf.Findings = map[string]FindingState{}
	}
	for _, item := range findings {
		if item.Fingerprint == "" {
			continue
		}
		state, exists := pf.Findings[item.Fingerprint]
		if !exists {
			state = FindingState{
				Fingerprint:   item.Fingerprint,
				Status:        "open",
				FirstSeenScan: scan.ID,
				FirstSeenAt:   scan.ImportedAt,
			}
		}
		state.Severity = item.Severity
		state.Type = item.Type
		state.Title = item.Title
		state.AffectedURL = item.AffectedURL
		state.LastSeenScan = scan.ID
		state.LastSeenAt = scan.ImportedAt
		state.RiskScore = item.RiskScore
		state.ManualRequired = item.ManualVerification
		state.CVE = item.CVE
		pf.Findings[item.Fingerprint] = state
	}
}

func updateProjectFromTriage(project *Project, findings map[string]FindingState) {
	var accepted, openCritical, openHigh, openMedium int
	for _, state := range findings {
		switch state.Status {
		case "accepted":
			accepted++
		case "open":
			switch state.Severity {
			case finding.Critical:
				openCritical++
			case finding.High:
				openHigh++
			case finding.Medium:
				openMedium++
			}
		}
	}
	project.AcceptedRisk = accepted
	project.OpenCritical = openCritical
	project.OpenHigh = openHigh
	project.OpenMedium = openMedium
	project.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
}

func checkQuota(quota Quota, existingScans, findings int) error {
	if quota.MaxScans > 0 && existingScans >= quota.MaxScans {
		return fmt.Errorf("%w: max_scans=%d", ErrQuotaExceeded, quota.MaxScans)
	}
	if quota.MaxFindingsPerScan > 0 && findings > quota.MaxFindingsPerScan {
		return fmt.Errorf("%w: max_findings_per_scan=%d findings=%d", ErrQuotaExceeded, quota.MaxFindingsPerScan, findings)
	}
	return nil
}

func normalizeStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "open", "accepted", "fixed", "false-positive", "false_positive", "ignored":
		if strings.ToLower(strings.TrimSpace(status)) == "false_positive" {
			return "false-positive"
		}
		return strings.ToLower(strings.TrimSpace(status))
	default:
		return ""
	}
}

func topRisk(findings []finding.Finding) int {
	top := 0
	for _, f := range findings {
		if f.RiskScore > top {
			top = f.RiskScore
		}
	}
	return top
}

func fingerprints(findings []finding.Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range findings {
		if f.Fingerprint == "" || seen[f.Fingerprint] {
			continue
		}
		seen[f.Fingerprint] = true
		out = append(out, f.Fingerprint)
	}
	sort.Strings(out)
	if len(out) > 500 {
		return out[:500]
	}
	return out
}

func rootOrDefault(root string) string {
	if strings.TrimSpace(root) == "" {
		return DefaultDir
	}
	return root
}

func projectDir(root, id string) string {
	return filepath.Join(rootOrDefault(root), "projects", id)
}

func projectFile(root, id string) string {
	return filepath.Join(projectDir(root, id), "project.json")
}

func scanFile(root, projectID, scanID string) string {
	return filepath.Join(projectDir(root, projectID), "scans", scanID+".json")
}

func auditFile(root, projectID string) string {
	return filepath.Join(projectDir(root, projectID), "audit.jsonl")
}

func writeJSON(path string, v interface{}) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}
