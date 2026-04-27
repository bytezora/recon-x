package templates

import (
	"embed"
	"io/fs"
	"path/filepath"

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
		data, err := fs.ReadFile(builtinFS, p)
		if err != nil {
			return nil, err
		}
		var t Template
		if err := yaml.Unmarshal(data, &t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}
