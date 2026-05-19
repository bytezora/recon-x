package finding

import "sort"

func EnrichAndSort(in []Finding) []Finding {
	out := make([]Finding, len(in))
	copy(out, in)
	for i := range out {
		score := calculateRiskScore(out[i])
		out[i].RiskScore = score
		out[i].Priority = priorityFromScore(score)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].RiskScore == out[j].RiskScore {
			return out[i].Title < out[j].Title
		}
		return out[i].RiskScore > out[j].RiskScore
	})
	return out
}

func calculateRiskScore(f Finding) int {
	score := severityBaseScore(f.Severity)
	score += confidenceScore(f.Confidence)
	score += int(f.CVSS * 4)
	if f.ManualVerification {
		score -= 10
	}
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func severityBaseScore(s Severity) int {
	switch s {
	case Critical:
		return 55
	case High:
		return 40
	case Medium:
		return 25
	case Low:
		return 12
	default:
		return 5
	}
}

func confidenceScore(c Confidence) int {
	switch c {
	case Confirmed:
		return 30
	case Likely:
		return 18
	case Possible:
		return 8
	default:
		return 0
	}
}

func priorityFromScore(score int) string {
	switch {
	case score >= 80:
		return "p0"
	case score >= 60:
		return "p1"
	case score >= 35:
		return "p2"
	default:
		return "p3"
	}
}
