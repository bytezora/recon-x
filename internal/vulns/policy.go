package vulns

import "strings"

type Policy struct {
	MinConfidence  string  `json:"min_confidence"`
	RequireVersion bool    `json:"require_version"`
	OnlyKEV        bool    `json:"only_kev"`
	MinCVSS        float64 `json:"min_cvss"`
}

type FilterReport struct {
	Before         int     `json:"before"`
	After          int     `json:"after"`
	Filtered       int     `json:"filtered"`
	Profile        string  `json:"profile"`
	MinConfidence  string  `json:"min_confidence"`
	RequireVersion bool    `json:"require_version"`
	OnlyKEV        bool    `json:"only_kev"`
	MinCVSS        float64 `json:"min_cvss"`
}

func (p Policy) normalize() Policy {
	if p.MinConfidence == "" {
		p.MinConfidence = "medium"
	}
	p.MinConfidence = strings.ToLower(p.MinConfidence)
	return p
}

func FilterMatches(in []Match, policy Policy) []Match {
	out, _ := FilterMatchesDetailed(in, policy, "")
	return out
}

func FilterMatchesDetailed(in []Match, policy Policy, profile string) ([]Match, FilterReport) {
	policy = policy.normalize()
	out := make([]Match, 0, len(in))
	for _, m := range in {
		if keepMatch(m, policy) {
			out = append(out, m)
		}
	}
	return out, FilterReport{
		Before:         len(in),
		After:          len(out),
		Filtered:       len(in) - len(out),
		Profile:        profile,
		MinConfidence:  policy.MinConfidence,
		RequireVersion: policy.RequireVersion,
		OnlyKEV:        policy.OnlyKEV,
		MinCVSS:        policy.MinCVSS,
	}
}

func keepMatch(m Match, policy Policy) bool {
	if strings.EqualFold(m.Confidence, "confirmed") {
		return true
	}
	if policy.OnlyKEV && !m.KEV {
		return false
	}
	if policy.RequireVersion && m.Version == "" {
		return false
	}
	if policy.MinCVSS > 0 && m.CVSS < policy.MinCVSS {
		return false
	}
	return confidenceWeight(m.Confidence) >= confidenceWeight(policy.MinConfidence)
}

func PrecisionProfile(name string) Policy {
	switch strings.ToLower(name) {
	case "strict":
		return Policy{MinConfidence: "high", RequireVersion: true}
	case "kev":
		return Policy{MinConfidence: "medium", OnlyKEV: true}
	case "broad":
		return Policy{MinConfidence: "low"}
	default:
		return Policy{MinConfidence: "medium"}
	}
}
