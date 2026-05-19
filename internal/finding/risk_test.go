package finding

import "testing"

func TestEnrichAndSort_AssignsRiskAndPriorityAndSorts(t *testing.T) {
	in := []Finding{
		{Title: "low", Severity: Low, Confidence: Possible, CVSS: 3.1},
		{Title: "critical", Severity: Critical, Confidence: Confirmed, CVSS: 9.8},
		{Title: "medium", Severity: Medium, Confidence: Likely, CVSS: 6.5},
	}

	out := EnrichAndSort(in)
	if len(out) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(out))
	}

	if out[0].Title != "critical" {
		t.Fatalf("expected highest risk finding first, got %q", out[0].Title)
	}

	for _, f := range out {
		if f.RiskScore < 0 || f.RiskScore > 100 {
			t.Fatalf("risk score out of bounds: %d", f.RiskScore)
		}
		if f.Priority == "" {
			t.Fatalf("priority should be set")
		}
	}
}

func TestCalculateRiskScore_ManualVerificationPenalty(t *testing.T) {
	base := Finding{Severity: High, Confidence: Likely, CVSS: 8.0, ManualVerification: false}
	manual := base
	manual.ManualVerification = true

	baseScore := calculateRiskScore(base)
	manualScore := calculateRiskScore(manual)

	if manualScore >= baseScore {
		t.Fatalf("expected manual verification score (%d) < base (%d)", manualScore, baseScore)
	}
}

func TestPriorityFromScoreBoundaries(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{80, "p0"},
		{79, "p1"},
		{60, "p1"},
		{59, "p2"},
		{35, "p2"},
		{34, "p3"},
	}

	for _, tc := range cases {
		got := priorityFromScore(tc.score)
		if got != tc.want {
			t.Fatalf("score=%d: got %q, want %q", tc.score, got, tc.want)
		}
	}
}
