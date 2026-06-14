package rbac

import "testing"

func TestRolePermissions(t *testing.T) {
	if !Can(Owner, QuotaUpdate) {
		t.Fatal("owner should update quota")
	}
	if Can(Viewer, ScanCreate) {
		t.Fatal("viewer should not create scans")
	}
	if !Can(CIBot, ScanCreate) || Can(CIBot, FindingTriage) {
		t.Fatal("ci-bot permissions are wrong")
	}
}

func TestProjectScope(t *testing.T) {
	actor := Actor{ID: "u1", Role: Analyst, Projects: []string{"api"}}
	if !Check(actor, ScanRead, "api").Allowed {
		t.Fatal("actor should read scoped project")
	}
	decision := Check(actor, ScanRead, "billing")
	if decision.Allowed || decision.Reason == "" {
		t.Fatalf("expected scoped denial, got %+v", decision)
	}
}

func TestNormalizeRole(t *testing.T) {
	if NormalizeRole("bot") != CIBot {
		t.Fatal("bot should normalize to ci-bot")
	}
	if NormalizeRole("bad-role") != Viewer {
		t.Fatal("unknown roles should normalize to viewer")
	}
}
