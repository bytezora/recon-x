package source

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bytezora/recon-x/internal/finding"
)

type Config struct {
	Path        string
	BaseURL     string
	Scanners    []string
	ShowSecrets bool
}

type Result struct {
	Root      string            `json:"root"`
	BaseURL   string            `json:"base_url,omitempty"`
	Scanners  []string          `json:"scanners"`
	Files     int               `json:"files"`
	Manifests []ManifestSummary `json:"manifests,omitempty"`
	Routes    []Route           `json:"routes,omitempty"`
	Findings  []finding.Finding `json:"findings,omitempty"`
}

type ManifestSummary struct {
	Path         string   `json:"path"`
	Ecosystem    string   `json:"ecosystem"`
	PackageName  string   `json:"package_name,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
}

type Route struct {
	File    string `json:"file"`
	Method  string `json:"method,omitempty"`
	Path    string `json:"path"`
	Line    int    `json:"line,omitempty"`
	Source  string `json:"source"`
	LiveURL string `json:"live_url,omitempty"`
}

var secretRules = []struct {
	label string
	re    *regexp.Regexp
}{
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"GitHub Token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,255}`)},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`)},
	{"Private Key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
	{"Generic API Key", regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{16,})`)},
	{"Database URL", regexp.MustCompile(`(?i)(postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^\s"'<>]+`)},
}

var routeRules = []struct {
	source string
	re     *regexp.Regexp
}{
	{"express", regexp.MustCompile(`\b(?:app|router)\.(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|ALL|get|post|put|patch|delete|options|head|all)\s*\(\s*["']([^"']+)["']`)},
	{"decorator", regexp.MustCompile(`@(Get|Post|Put|Patch|Delete|Controller|Route|GET|POST|PUT|PATCH|DELETE)\s*\(\s*["']?([^"')]+)["']?\s*\)`)},
	{"django", regexp.MustCompile(`\bpath\s*\(\s*["']([^"']+)["']`)},
	{"flask-fastapi", regexp.MustCompile(`@(?:app|router)\.(get|post|put|patch|delete|api_route)\s*\(\s*["']([^"']+)["']`)},
	{"go-http", regexp.MustCompile(`(?:HandleFunc|Handle)\s*\(\s*["']([^"']+)["']`)},
}

var configRiskRules = []struct {
	label string
	re    *regexp.Regexp
}{
	{"Debug mode enabled", regexp.MustCompile(`(?i)\b(debug|development)\b\s*[:=]\s*(true|1|yes)`)},
	{"Wildcard CORS", regexp.MustCompile(`(?i)(access-control-allow-origin|cors|allowed_origins).*(\*|all)`)},
	{"Disabled TLS verification", regexp.MustCompile(`(?i)insecure_skip_verify\s*[:=]\s*(true|1|yes)`)},
	{"Disabled TLS verification", regexp.MustCompile(`(?i)(rejectUnauthorized|verify_ssl|ssl_verify)\s*[:=]\s*(false|0|no)`)},
	{"Permissive bind address", regexp.MustCompile(`(?i)(host|listen|bind)\s*[:=]\s*["']?(0\.0\.0\.0|\*)`)},
}

func Scan(cfg Config) (Result, error) {
	root, err := filepath.Abs(cfg.Path)
	if err != nil {
		return Result{}, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return Result{}, err
	}
	if !info.IsDir() {
		return Result{}, fmt.Errorf("%s is not a directory", root)
	}

	scanners := normalizeScanners(cfg.Scanners)
	res := Result{Root: root, BaseURL: cfg.BaseURL, Scanners: scanners}
	var findings []finding.Finding

	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if shouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if shouldSkipFile(path, d) {
			return nil
		}
		res.Files++
		rel := relPath(root, path)
		if scannerEnabled(scanners, "deps") {
			if manifest, ok := parseManifest(root, path); ok {
				res.Manifests = append(res.Manifests, manifest)
			}
		}
		if scannerEnabled(scanners, "secrets") || scannerEnabled(scanners, "config") || scannerEnabled(scanners, "routes") {
			data, readErr := readSmallText(path, 1<<20)
			if readErr != nil || data == "" {
				return nil
			}
			if scannerEnabled(scanners, "secrets") {
				findings = append(findings, scanSecrets(rel, data, cfg.ShowSecrets)...)
			}
			if scannerEnabled(scanners, "config") {
				findings = append(findings, scanConfig(rel, data)...)
			}
			if scannerEnabled(scanners, "routes") {
				res.Routes = append(res.Routes, scanRoutes(rel, data, cfg.BaseURL)...)
			}
		}
		return nil
	})
	if err != nil {
		return Result{}, err
	}

	if scannerEnabled(scanners, "deps") {
		findings = append(findings, dependencyFindings(res.Manifests)...)
	}
	if scannerEnabled(scanners, "routes") {
		findings = append(findings, routeFindings(res.Routes)...)
	}

	sort.Slice(res.Manifests, func(i, j int) bool { return res.Manifests[i].Path < res.Manifests[j].Path })
	sort.Slice(res.Routes, func(i, j int) bool {
		if res.Routes[i].File == res.Routes[j].File {
			return res.Routes[i].Line < res.Routes[j].Line
		}
		return res.Routes[i].File < res.Routes[j].File
	})
	res.Findings = finding.EnrichAndSort(findings)
	return res, nil
}

func normalizeScanners(in []string) []string {
	if len(in) == 0 {
		return []string{"secrets", "deps", "config", "routes"}
	}
	seen := map[string]bool{}
	var out []string
	for _, item := range in {
		for _, part := range strings.Split(item, ",") {
			name := strings.ToLower(strings.TrimSpace(part))
			if name == "" {
				continue
			}
			if name == "all" {
				return []string{"secrets", "deps", "config", "routes"}
			}
			if name == "dependencies" || name == "manifests" {
				name = "deps"
			}
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	if len(out) == 0 {
		return []string{"secrets", "deps", "config", "routes"}
	}
	return out
}

func scannerEnabled(scanners []string, name string) bool {
	for _, scanner := range scanners {
		if scanner == name || scanner == "all" {
			return true
		}
	}
	return false
}

func shouldSkipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", "dist", "build", ".next", ".nuxt", ".venv", "venv", "__pycache__", "coverage", "reports":
		return true
	default:
		return false
	}
}

func shouldSkipFile(path string, d os.DirEntry) bool {
	info, err := d.Info()
	if err != nil || info.Size() > 4<<20 {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".7z", ".tar", ".exe", ".dll", ".so", ".dylib", ".class", ".jar", ".mp4", ".mov":
		return true
	default:
		return false
	}
}

func readSmallText(path string, limit int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return "", err
	}
	if hasNUL(data) {
		return "", nil
	}
	return string(data), nil
}

func hasNUL(data []byte) bool {
	for _, b := range data {
		if b == 0 {
			return true
		}
	}
	return false
}

func scanSecrets(file, data string, showSecrets bool) []finding.Finding {
	var out []finding.Finding
	lines := lineStarts(data)
	for _, rule := range secretRules {
		matches := rule.re.FindAllStringIndex(data, -1)
		for _, match := range matches {
			raw := data[match[0]:match[1]]
			line := lineForOffset(lines, match[0])
			evidence := raw
			if !showSecrets {
				evidence = redactEvidence(raw)
			}
			out = append(out, finding.Finding{
				Type:               "repo-secret",
				Severity:           finding.High,
				Confidence:         finding.Likely,
				Title:              "Potential Secret in Source: " + rule.label,
				AffectedURL:        fmt.Sprintf("%s:%d", file, line),
				Evidence:           evidence,
				Reason:             "A source file contains a value matching a secret pattern.",
				Remediation:        "Rotate the secret if real, move it to a secret manager or deployment environment, and add a pre-commit scan.",
				ManualVerification: true,
			})
		}
	}
	return out
}

func scanConfig(file, data string) []finding.Finding {
	var out []finding.Finding
	lines := lineStarts(data)
	for _, rule := range configRiskRules {
		matches := rule.re.FindAllStringIndex(data, -1)
		for _, match := range matches {
			line := lineForOffset(lines, match[0])
			out = append(out, finding.Finding{
				Type:               "repo-config",
				Severity:           finding.Medium,
				Confidence:         finding.Possible,
				Title:              "Risky Configuration: " + rule.label,
				AffectedURL:        fmt.Sprintf("%s:%d", file, line),
				Evidence:           trimOneLine(data[match[0]:match[1]], 160),
				Reason:             "Configuration appears to weaken production safety or increase exposure.",
				Remediation:        "Review the setting for production and move environment-specific values into guarded deployment config.",
				ManualVerification: true,
			})
		}
	}
	return out
}

func scanRoutes(file, data, baseURL string) []Route {
	var routes []Route
	lines := lineStarts(data)
	for _, rule := range routeRules {
		for _, match := range rule.re.FindAllStringSubmatchIndex(data, -1) {
			method := ""
			pathIdx := 2
			if len(match) >= 6 && match[4] >= 0 {
				method = strings.ToUpper(data[match[2]:match[3]])
				pathIdx = 4
			}
			if len(match) <= pathIdx+1 || match[pathIdx] < 0 {
				continue
			}
			routePath := data[match[pathIdx]:match[pathIdx+1]]
			if routePath == "" {
				continue
			}
			line := lineForOffset(lines, match[0])
			routes = append(routes, Route{
				File:    file,
				Method:  method,
				Path:    routePath,
				Line:    line,
				Source:  rule.source,
				LiveURL: joinURL(baseURL, routePath),
			})
		}
	}
	return routes
}

func dependencyFindings(manifests []ManifestSummary) []finding.Finding {
	var out []finding.Finding
	for _, manifest := range manifests {
		if len(manifest.Dependencies) == 0 {
			continue
		}
		out = append(out, finding.Finding{
			Type:               "repo-deps",
			Severity:           finding.Info,
			Confidence:         finding.Confirmed,
			Title:              "Dependency Manifest Detected: " + manifest.Ecosystem,
			AffectedURL:        manifest.Path,
			Evidence:           fmt.Sprintf("%d dependencies parsed", len(manifest.Dependencies)),
			Reason:             "Dependency manifests define software supply-chain attack surface and should be scanned in CI.",
			Remediation:        "Run dependency/CVE scanning in CI and pin or update vulnerable packages.",
			ManualVerification: false,
		})
	}
	return out
}

func routeFindings(routes []Route) []finding.Finding {
	if len(routes) == 0 {
		return nil
	}
	return []finding.Finding{{
		Type:               "repo-routes",
		Severity:           finding.Info,
		Confidence:         finding.Confirmed,
		Title:              "Application Routes Discovered",
		AffectedURL:        "source routes",
		Evidence:           fmt.Sprintf("%d routes discovered from source", len(routes)),
		Reason:             "Source-aware route discovery can drive focused live testing against real endpoints.",
		Remediation:        "Review discovered route inventory and combine with authenticated active scans where authorized.",
		ManualVerification: false,
	}}
}

func parseManifest(root, path string) (ManifestSummary, bool) {
	name := strings.ToLower(filepath.Base(path))
	rel := relPath(root, path)
	switch name {
	case "package.json":
		return parsePackageJSON(rel, path)
	case "go.mod":
		return parseGoMod(rel, path)
	case "requirements.txt":
		return parseRequirements(rel, path)
	case "pyproject.toml":
		return ManifestSummary{Path: rel, Ecosystem: "python"}, true
	case "pom.xml":
		return ManifestSummary{Path: rel, Ecosystem: "maven"}, true
	case "build.gradle", "build.gradle.kts":
		return ManifestSummary{Path: rel, Ecosystem: "gradle"}, true
	case "gemfile":
		return ManifestSummary{Path: rel, Ecosystem: "ruby"}, true
	case "composer.json":
		return ManifestSummary{Path: rel, Ecosystem: "php"}, true
	default:
		return ManifestSummary{}, false
	}
}

func parsePackageJSON(rel, path string) (ManifestSummary, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ManifestSummary{}, false
	}
	var pkg struct {
		Name            string            `json:"name"`
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return ManifestSummary{Path: rel, Ecosystem: "npm"}, true
	}
	deps := make([]string, 0, len(pkg.Dependencies)+len(pkg.DevDependencies))
	for name, version := range pkg.Dependencies {
		deps = append(deps, name+"@"+version)
	}
	for name, version := range pkg.DevDependencies {
		deps = append(deps, name+"@"+version+" (dev)")
	}
	sort.Strings(deps)
	return ManifestSummary{Path: rel, Ecosystem: "npm", PackageName: pkg.Name, Dependencies: limitStrings(deps, 80)}, true
}

func parseGoMod(rel, path string) (ManifestSummary, bool) {
	f, err := os.Open(path)
	if err != nil {
		return ManifestSummary{}, false
	}
	defer f.Close()
	var module string
	var deps []string
	scanner := bufio.NewScanner(f)
	inRequireBlock := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "module ") {
			module = strings.TrimSpace(strings.TrimPrefix(line, "module "))
			continue
		}
		if strings.HasPrefix(line, "require (") {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}
		if strings.HasPrefix(line, "require ") {
			deps = append(deps, strings.TrimSpace(strings.TrimPrefix(line, "require ")))
		} else if inRequireBlock && line != "" && !strings.HasPrefix(line, "//") {
			deps = append(deps, line)
		}
	}
	return ManifestSummary{Path: rel, Ecosystem: "go", PackageName: module, Dependencies: limitStrings(deps, 80)}, true
}

func parseRequirements(rel, path string) (ManifestSummary, bool) {
	f, err := os.Open(path)
	if err != nil {
		return ManifestSummary{}, false
	}
	defer f.Close()
	var deps []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		deps = append(deps, line)
	}
	return ManifestSummary{Path: rel, Ecosystem: "python", Dependencies: limitStrings(deps, 80)}, true
}

func lineStarts(data string) []int {
	starts := []int{0}
	for i, r := range data {
		if r == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

func lineForOffset(starts []int, offset int) int {
	line := sort.Search(len(starts), func(i int) bool { return starts[i] > offset })
	if line == 0 {
		return 1
	}
	return line
}

func redactEvidence(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("[REDACTED len=%d sha256_12=%x]", len(value), sum[:6])
}

func trimOneLine(value string, max int) string {
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > max {
		return value[:max] + "..."
	}
	return value
}

func relPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}

func joinURL(baseURL, routePath string) string {
	if baseURL == "" {
		return ""
	}
	return strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(routePath, "/")
}

func limitStrings(in []string, max int) []string {
	if len(in) <= max {
		return in
	}
	out := make([]string, max)
	copy(out, in[:max])
	return out
}
