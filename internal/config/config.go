package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Targets           []string `yaml:"targets"`
	TargetType        string   `yaml:"target_type"`
	RepoPath          string   `yaml:"repo_path"`
	BaseURL           string   `yaml:"base_url"`
	Project           string   `yaml:"project"`
	ProjectName       string   `yaml:"project_name"`
	StoreDir          string   `yaml:"store_dir"`
	Profile           string   `yaml:"profile"`
	Scanners          []string `yaml:"scanners"`
	Modules           []string `yaml:"modules"`
	Threads           int      `yaml:"threads"`
	OutputDir         string   `yaml:"output_dir"`
	OutputFormat      string   `yaml:"output_format"`
	Baseline          string   `yaml:"baseline"`
	Allowlist         string   `yaml:"allowlist"`
	FailOn            string   `yaml:"fail_on"`
	SubdomainFile     string   `yaml:"subdomain_file"`
	Retries           int      `yaml:"retries"`
	Rate              int      `yaml:"rate"`
	Silent            bool     `yaml:"silent"`
	NoTUI             bool     `yaml:"no_tui"`
	Verbose           bool     `yaml:"verbose"`
	ShowSecrets       bool     `yaml:"show_secrets"`
	RedactPercent     int      `yaml:"redact_percent"`
	GithubToken       string   `yaml:"github_token"`
	Templates         []string `yaml:"templates"`
	Resolver          string   `yaml:"resolver"`
	CVELive           bool     `yaml:"cve_live"`
	NVDAPIKey         string   `yaml:"nvd_api_key"`
	CVETimeout        int      `yaml:"cve_timeout"`
	NmapXML           string   `yaml:"nmap_xml"`
	SkipPortScan      bool     `yaml:"skip_portscan"`
	CVEProfile        string   `yaml:"cve_profile"`
	CVEMinConfidence  string   `yaml:"cve_min_confidence"`
	CVERequireVersion bool     `yaml:"cve_require_version"`
	CVEOnlyKEV        bool     `yaml:"cve_only_kev"`
	CVEMinCVSS        float64  `yaml:"cve_min_cvss"`
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var cfg Config
	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func Default() *Config {
	return &Config{
		Threads:       50,
		Profile:       "standard",
		OutputFormat:  "html",
		Retries:       2,
		Rate:          50,
		RedactPercent: 100,
	}
}
