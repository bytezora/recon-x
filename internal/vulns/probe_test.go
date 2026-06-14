package vulns

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestProbeFingerprintsRejectsHTMLAsVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>404 not found</body></html>"))
	}))
	defer srv.Close()

	host, port := splitTestServer(t, srv.URL)
	got := ProbeFingerprints("http", host, port)
	for _, fp := range got {
		if strings.Contains(fp.Version, "<html") {
			t.Fatalf("accepted HTML as version: %+v", fp)
		}
	}
}

func TestProbeFingerprintsAcceptsMagentoVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/magento_version" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("2.4.6-p3\n"))
	}))
	defer srv.Close()

	host, port := splitTestServer(t, srv.URL)
	got := ProbeFingerprints("http", host, port)
	for _, fp := range got {
		if fp.Product == "magento" && fp.Version == "2.4.6-p3" {
			return
		}
	}
	t.Fatalf("expected Magento version fingerprint, got %+v", got)
}

func TestCPEVersionRejectsHTML(t *testing.T) {
	cpe, _ := cpeFor("magento", "<html>not a version</html>")
	if strings.Contains(cpe, "<html>") {
		t.Fatalf("CPE contains unsanitized version: %s", cpe)
	}
	if !strings.Contains(cpe, ":*:*:*") {
		t.Fatalf("expected wildcard version for invalid evidence, got %s", cpe)
	}
}

func splitTestServer(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	addr := strings.TrimPrefix(rawURL, "http://")
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}
