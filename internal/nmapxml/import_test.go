package nmapxml

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseFileImportsOpenPortsAndFingerprints(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nmap.xml")
	data := `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostnames><hostname name="app.example.com" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0" tunnel="ssl">
          <cpe>cpe:/a:nginx:nginx:1.18.0</cpe>
        </service>
      </port>
      <port protocol="udp" portid="53"><state state="open"/></port>
    </ports>
  </host>
</nmaprun>`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}
	if len(got.Ports) != 1 {
		t.Fatalf("ports len = %d, want 1", len(got.Ports))
	}
	if got.Ports[0].Host != "app.example.com" || got.Ports[0].Port != 443 || got.Ports[0].Service != "https" {
		t.Fatalf("unexpected port: %+v", got.Ports[0])
	}
	if len(got.Fingerprints) != 1 {
		t.Fatalf("fingerprints len = %d, want 1", len(got.Fingerprints))
	}
	if got.Fingerprints[0].Product != "nginx" || got.Fingerprints[0].Version != "1.18.0" {
		t.Fatalf("unexpected fingerprint: %+v", got.Fingerprints[0])
	}
	if got.Fingerprints[0].CPE != "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*" {
		t.Fatalf("unexpected normalized cpe: %q", got.Fingerprints[0].CPE)
	}
}
