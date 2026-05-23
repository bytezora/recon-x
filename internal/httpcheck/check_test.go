package httpcheck

import (
	"testing"

	"github.com/bytezora/recon-x/internal/portscan"
)

func TestIsHTTPServiceUsesNmapServiceEvidence(t *testing.T) {
	if !isHTTPService(portscan.Result{Port: 9443, Service: "https", Banner: "ssl/http nginx"}) {
		t.Fatal("expected https service on non-standard port to be probed")
	}
	if isHTTPService(portscan.Result{Port: 22, Service: "ssh", Banner: "OpenSSH_9.6"}) {
		t.Fatal("did not expect ssh service to be treated as HTTP")
	}
}

func TestSchemeForUsesTLSServiceEvidence(t *testing.T) {
	got := schemeFor(portscan.Result{Port: 9443, Service: "https", Banner: "ssl/http"})
	if got != "https" {
		t.Fatalf("scheme = %q, want https", got)
	}
}
