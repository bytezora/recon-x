package scope

import (
	"os"
	"testing"
)

func writeScopeFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "scope-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(f.Name()) })
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func TestInScope_Exact(t *testing.T) {
	path := writeScopeFile(t, "example.com\n")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !s.InScope("example.com") {
		t.Error("expected example.com to be in scope")
	}
	if s.InScope("sub.example.com") {
		t.Error("expected sub.example.com to be out of scope for exact match")
	}
}

func TestInScope_Wildcard(t *testing.T) {
	path := writeScopeFile(t, "*.example.com\n")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !s.InScope("sub.example.com") {
		t.Error("expected sub.example.com to be in scope")
	}
	if !s.InScope("example.com") {
		t.Error("expected example.com itself to be in scope via wildcard")
	}
	if s.InScope("other.com") {
		t.Error("expected other.com to be out of scope")
	}
}

func TestInScope_CIDR(t *testing.T) {
	path := writeScopeFile(t, "10.0.0.0/8\n")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !s.InScope("10.1.2.3") {
		t.Error("expected 10.1.2.3 to be in scope")
	}
	if s.InScope("192.168.1.1") {
		t.Error("expected 192.168.1.1 to be out of scope")
	}
}

func TestInScope_Empty(t *testing.T) {
	path := writeScopeFile(t, "")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.InScope("example.com") {
		t.Error("expected empty scope to have nothing in scope")
	}
}
