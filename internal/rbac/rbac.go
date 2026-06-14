package rbac

import "strings"

type Role string
type Permission string

const (
	Owner   Role = "owner"
	Admin   Role = "admin"
	Analyst Role = "analyst"
	Viewer  Role = "viewer"
	CIBot   Role = "ci-bot"
)

const (
	ProjectCreate  Permission = "project:create"
	ProjectRead    Permission = "project:read"
	ProjectUpdate  Permission = "project:update"
	ScanCreate     Permission = "scan:create"
	ScanRead       Permission = "scan:read"
	ScanCancel     Permission = "scan:cancel"
	FindingRead    Permission = "finding:read"
	FindingTriage  Permission = "finding:triage"
	BaselineRead   Permission = "baseline:read"
	BaselineUpdate Permission = "baseline:update"
	ArtifactRead   Permission = "artifact:read"
	MemberInvite   Permission = "member:invite"
	MemberUpdate   Permission = "member:update"
	QuotaRead      Permission = "quota:read"
	QuotaUpdate    Permission = "quota:update"
	AuditRead      Permission = "audit:read"
)

type Actor struct {
	ID       string   `json:"id"`
	Role     Role     `json:"role"`
	Projects []string `json:"projects,omitempty"`
}

type Decision struct {
	Allowed    bool       `json:"allowed"`
	Role       Role       `json:"role"`
	Permission Permission `json:"permission"`
	Reason     string     `json:"reason,omitempty"`
}

var rolePermissions = map[Role]map[Permission]bool{
	Owner: allowAll(),
	Admin: allow(
		ProjectCreate, ProjectRead, ProjectUpdate,
		ScanCreate, ScanRead, ScanCancel,
		FindingRead, FindingTriage,
		BaselineRead, BaselineUpdate,
		ArtifactRead, MemberInvite, MemberUpdate,
		QuotaRead, AuditRead,
	),
	Analyst: allow(
		ProjectRead, ScanCreate, ScanRead,
		FindingRead, FindingTriage,
		BaselineRead, ArtifactRead,
	),
	Viewer: allow(ProjectRead, ScanRead, FindingRead, BaselineRead, ArtifactRead),
	CIBot:  allow(ProjectRead, ScanCreate, ScanRead, ArtifactRead),
}

func NormalizeRole(role string) Role {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "owner":
		return Owner
	case "admin":
		return Admin
	case "analyst":
		return Analyst
	case "viewer", "read-only", "readonly":
		return Viewer
	case "ci", "ci-bot", "bot":
		return CIBot
	default:
		return Viewer
	}
}

func Check(actor Actor, permission Permission, projectID string) Decision {
	actor.Role = NormalizeRole(string(actor.Role))
	if !Can(actor.Role, permission) {
		return Decision{Allowed: false, Role: actor.Role, Permission: permission, Reason: "role lacks permission"}
	}
	if !ProjectAllowed(actor, projectID) {
		return Decision{Allowed: false, Role: actor.Role, Permission: permission, Reason: "actor is not scoped to project"}
	}
	return Decision{Allowed: true, Role: actor.Role, Permission: permission}
}

func Can(role Role, permission Permission) bool {
	role = NormalizeRole(string(role))
	perms, ok := rolePermissions[role]
	if !ok {
		return false
	}
	return perms[permission]
}

func ProjectAllowed(actor Actor, projectID string) bool {
	projectID = strings.ToLower(strings.TrimSpace(projectID))
	if projectID == "" || len(actor.Projects) == 0 {
		return true
	}
	for _, p := range actor.Projects {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "*" || p == projectID {
			return true
		}
	}
	return false
}

func Policy() map[Role][]Permission {
	out := map[Role][]Permission{}
	for role, perms := range rolePermissions {
		for perm := range perms {
			out[role] = append(out[role], perm)
		}
	}
	return out
}

func allow(perms ...Permission) map[Permission]bool {
	out := map[Permission]bool{}
	for _, perm := range perms {
		out[perm] = true
	}
	return out
}

func allowAll() map[Permission]bool {
	return allow(
		ProjectCreate, ProjectRead, ProjectUpdate,
		ScanCreate, ScanRead, ScanCancel,
		FindingRead, FindingTriage,
		BaselineRead, BaselineUpdate,
		ArtifactRead, MemberInvite, MemberUpdate,
		QuotaRead, QuotaUpdate,
		AuditRead,
	)
}
