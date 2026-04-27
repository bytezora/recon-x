package templates

type Template struct {
	ID       string            `yaml:"id"`
	Name     string            `yaml:"name"`
	Severity string            `yaml:"severity"`
	Tags     []string          `yaml:"tags"`
	Request  RequestDef        `yaml:"request"`
	Matchers []MatcherDef      `yaml:"matchers"`
}

type RequestDef struct {
	Method  string            `yaml:"method"`
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
	Body    string            `yaml:"body"`
}

type MatcherDef struct {
	Type      string   `yaml:"type"`
	Words     []string `yaml:"words"`
	Status    []int    `yaml:"status"`
	Condition string   `yaml:"condition"`
}

type Match struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	Tags       []string `json:"tags"`
	URL        string `json:"url"`
	Matched    string `json:"matched"`
}
