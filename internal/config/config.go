package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Targets      []string `yaml:"targets"`
	Modules      []string `yaml:"modules"`
	Threads      int      `yaml:"threads"`
	OutputDir    string   `yaml:"output_dir"`
	OutputFormat string   `yaml:"output_format"`
	Retries      int      `yaml:"retries"`
	Rate         int      `yaml:"rate"`
	Silent       bool     `yaml:"silent"`
	Verbose      bool     `yaml:"verbose"`
	GithubToken  string   `yaml:"github_token"`
	Templates    []string `yaml:"templates"`
	Resolver     string   `yaml:"resolver"`
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
