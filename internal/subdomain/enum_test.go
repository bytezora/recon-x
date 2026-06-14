package subdomain

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadSeedNamesAcceptsFQDNsAndLabels(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subs.txt")
	data := []byte("api\nwww.api.example.com\n# comment\nAdmin # inline\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	got := loadSeedNames(path, "example.com")
	want := []string{"api.example.com", "www.api.example.com", "admin.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loadSeedNames() = %v, want %v", got, want)
	}
}
