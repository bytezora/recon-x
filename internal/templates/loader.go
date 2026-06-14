package templates

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed builtins
var builtinFS embed.FS

func LoadBuiltins() ([]Template, error) {
	var out []Template
	err := fs.WalkDir(builtinFS, "builtins", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		data, err := builtinFS.ReadFile(path)
		if err != nil {
			return err
		}
		var t Template
		if err := yaml.Unmarshal(data, &t); err != nil {
			return err
		}
		out = append(out, t)
		return nil
	})
	return out, err
}

func LoadCustom(paths []string) ([]Template, error) {
	var out []Template
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("custom template path %q: %w", p, err)
		}
		if info.IsDir() {
			err := filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() || !isYAML(path) {
					return nil
				}
				t, err := loadTemplateFile(path)
				if err != nil {
					return err
				}
				out = append(out, t)
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("custom template dir %q: %w", p, err)
			}
			continue
		}
		if !isYAML(p) {
			continue
		}
		t, err := loadTemplateFile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

func loadTemplateFile(path string) (Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Template{}, err
	}
	var t Template
	if err := yaml.Unmarshal(data, &t); err != nil {
		return Template{}, fmt.Errorf("%s: %w", path, err)
	}
	return t, nil
}

func isYAML(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}
