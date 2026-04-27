package vulns

import (
	"testing"
)

func TestParseVersion(t *testing.T) {
	cases := []struct {
		input string
		want  [4]int
	}{
		{"7.4.3", [4]int{7, 4, 3, 0}},
		{"1.18.0", [4]int{1, 18, 0, 0}},
		{"8.9p1", [4]int{8, 9, 0, 0}},
		{"2.4.55", [4]int{2, 4, 55, 0}},
		{"", [4]int{0, 0, 0, 0}},
	}
	for _, c := range cases {
		v := parseVersion(c.input)
		for i, want := range c.want {
			if i < len(v.parts) && v.parts[i] != want {
				t.Errorf("parseVersion(%q).parts[%d] = %d, want %d", c.input, i, v.parts[i], want)
			}
		}
	}
}

func TestVersionCmp(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"7.4.3", "7.4.3", 0},
		{"7.4.3", "7.4.4", -1},
		{"7.5.0", "7.4.9", 1},
		{"2.4.55", "2.4.50", 1},
		{"1.0", "2.0", -1},
	}
	for _, c := range cases {
		got := parseVersion(c.a).cmp(parseVersion(c.b))
		if got != c.want {
			t.Errorf("cmp(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCheckBanner_Match(t *testing.T) {
	matches := CheckBanner("host", 22, "SSH-2.0-OpenSSH_7.4")
	if len(matches) == 0 {
		t.Error("expected CVE matches for OpenSSH 7.4")
	}
	for _, m := range matches {
		if m.Confidence == "" {
			t.Error("expected non-empty Confidence field")
		}
	}
}

func TestCheckBanner_NoMatch(t *testing.T) {
	matches := CheckBanner("host", 22, "SSH-2.0-OpenSSH_9.9")
	if len(matches) != 0 {
		t.Errorf("expected no CVE matches for current OpenSSH version, got %d", len(matches))
	}
}

func TestCheckBanner_PresenceOnly_LowConfidence(t *testing.T) {
	matches := CheckHTTP("host", 80, map[string][]string{
		"X-Jenkins": {"2.387"},
	})
	for _, m := range matches {
		if m.Confidence != "high" {
			t.Errorf("version-matched entry should be high confidence, got %s", m.Confidence)
		}
	}
}
