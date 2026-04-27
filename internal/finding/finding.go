package finding

type Confidence string

const (
	Confirmed Confidence = "confirmed"
	Likely    Confidence = "likely"
	Possible  Confidence = "possible"
)

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

type Finding struct {
	Type               string     `json:"type"`
	Severity           Severity   `json:"severity"`
	Confidence         Confidence `json:"confidence"`
	Title              string     `json:"title"`
	AffectedURL        string     `json:"affected_url"`
	Evidence           string     `json:"evidence"`
	Reason             string     `json:"reason"`
	Remediation        string     `json:"remediation,omitempty"`
	ManualVerification bool       `json:"manual_verification"`
	CVE                string     `json:"cve,omitempty"`
	CVSS               float64    `json:"cvss,omitempty"`
	References         []string   `json:"references,omitempty"`
}
