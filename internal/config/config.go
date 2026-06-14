package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Targets           []string `yaml:"targets"`
	Modules           []string `yaml:"modules"`
	Threads           int      `yaml:"threads"`
	OutputDir         string   `yaml:"output_dir"`
	OutputFormat      string   `yaml:"output_format"`
	SubdomainFile     string   `yaml:"subdomain_file"`
	Retries           int      `yaml:"retries"`
	Rate              int      `yaml:"rate"`
	Silent            bool     `yaml:"silent"`
	Verbose           bool     `yaml:"verbose"`
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
		Threads:      50,
		OutputFormat: "html",
		Retries:      2,
		Rate:         50,
	}
}
