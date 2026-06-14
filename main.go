package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/bytezora/recon-x/internal/apiserver"
	"github.com/bytezora/recon-x/internal/baseline"
	"github.com/bytezora/recon-x/internal/config"
	"github.com/bytezora/recon-x/internal/diff"
	"github.com/bytezora/recon-x/internal/engine"
	"github.com/bytezora/recon-x/internal/evidence"
	"github.com/bytezora/recon-x/internal/finding"
	"github.com/bytezora/recon-x/internal/httpclient"
	"github.com/bytezora/recon-x/internal/output"
	"github.com/bytezora/recon-x/internal/report"
	"github.com/bytezora/recon-x/internal/sanitize"
	"github.com/bytezora/recon-x/internal/source"
	"github.com/bytezora/recon-x/internal/state"
	"github.com/bytezora/recon-x/internal/vulns"
	"github.com/bytezora/recon-x/internal/workspace"
	"github.com/bytezora/recon-x/ui"
)

var version = "2.1.0"
var quiet bool

const defaultPorts = "21,22,25,53,80,110,143,443,445,3306,5432,6379,8080,8443,8888,9000,27017"

const banner = `
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗      ██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║      ╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║       ╚███╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║       ██╔██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║      ██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝      ╚═╝  ╚═╝`

var (
	stylePurple = lipgloss.NewStyle().Foreground(lipgloss.Color("#7C3AED")).Bold(true)
	styleGreen  = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF87")).Bold(true)
	styleYellow = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFA502"))
	styleMuted  = lipgloss.NewStyle().Foreground(lipgloss.Color("#8B949E"))
	styleRed    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4757"))
)

var moduleNames = map[string]int{
	"passive": 0, "subdomain": 1, "port": 2, "http": 3, "dir": 4, "js": 5,
	"github": 6, "buckets": 7, "tls": 8, "redirect": 9, "axfr": 10, "whois": 11,
	"screenshot": 12, "takeover": 13, "cors": 14, "bypass": 15, "vhost": 16,
	"favicon": 17, "asn": 18, "graphql": 19, "email": 20, "admin": 21,
	"sqli": 22, "creds": 23, "ratelimit": 24, "templates": 25,
	"xss": 26, "ssrf": 27, "lfi": 28, "hostheader": 29, "jwt": 30,
	"wayback": 31, "shodan": 32, "xxe": 33, "cmdi": 34,
}

var profileModules = map[string][]string{
	"safe": {
		"passive", "subdomain", "port", "http", "tls", "whois", "email", "asn", "favicon", "wayback",
	},
	"standard": {
		"passive", "subdomain", "port", "http", "dir", "js", "github", "buckets", "tls", "axfr",
		"whois", "screenshot", "takeover", "cors", "vhost", "favicon", "asn", "graphql", "email",
		"admin", "ratelimit", "templates", "wayback", "shodan",
	},
	"active": {
		"passive", "subdomain", "port", "http", "dir", "js", "github", "buckets", "tls", "redirect",
		"axfr", "whois", "screenshot", "takeover", "cors", "bypass", "vhost", "favicon", "asn",
		"graphql", "email", "admin", "sqli", "creds", "ratelimit", "templates", "xss", "ssrf",
		"lfi", "hostheader", "jwt", "wayback", "shodan", "xxe", "cmdi",
	},
	"proof": {
		"passive", "subdomain", "port", "http", "dir", "js", "github", "buckets", "tls", "redirect",
		"axfr", "whois", "screenshot", "takeover", "cors", "bypass", "vhost", "favicon", "asn",
		"graphql", "email", "admin", "sqli", "creds", "ratelimit", "templates", "xss", "ssrf",
		"lfi", "hostheader", "jwt", "wayback", "shodan", "xxe", "cmdi",
	},
	"ci": {
		"passive", "subdomain", "port", "http", "dir", "js", "tls", "cors", "graphql", "email",
		"templates", "wayback",
	},
	"full": {"all"},
}

var scannerModules = map[string][]string{
	"dns":      {"passive", "subdomain", "axfr", "whois", "email"},
	"http":     {"http", "dir", "js", "admin", "ratelimit", "screenshot"},
	"tls":      {"tls"},
	"cve":      {"http", "templates"},
	"secrets":  {"js", "github"},
	"cloud":    {"buckets"},
	"osint":    {"passive", "github", "wayback", "shodan", "asn", "whois"},
	"takeover": {"takeover"},
	"web":      {"redirect", "cors", "bypass", "vhost", "graphql", "xss", "ssrf", "lfi", "hostheader", "jwt", "xxe", "cmdi"},
	"all":      {"all"},
}

func main() {
	normalizeModernCLI()
	cfg := parseFlags()
	quiet = cfg.Silent

	if cfg.TargetType == "repo" {
		runRepoScan(cfg)
		return
	}

	if cfg.Retries > 0 {
		httpclient.SetRetries(cfg.Retries)
	}
	if cfg.Rate > 0 {
		httpclient.SetRate(cfg.Rate)
	}

	if cfg.Proxy != "" {
		os.Setenv("HTTP_PROXY", cfg.Proxy)
		os.Setenv("HTTPS_PROXY", cfg.Proxy)
	}

	stateFile := "." + cfg.Target + ".recon-x-state.json"
	stateObj := &state.State{Target: cfg.Target, Version: version}
	if cfg.Resume {
		if loaded, err := state.Load(stateFile); err == nil {
			stateObj = loaded
		}
	}

	if !cfg.Silent && !cfg.NoTUI {
		fmt.Println(stylePurple.Render(banner))
		fmt.Printf("\n  %s  v%s  ·  by bytezora\n  %s\n\n",
			stylePurple.Render("recon-x"), version,
			styleMuted.Render("fast attack-surface collector · findings are indicators, not confirmed vulns · authorized targets only"))
	} else if !cfg.Silent {
		fmt.Printf("recon-x v%s scanning %s with profile=%s\n", version, cfg.Target, cfg.Profile)
	}

	start := time.Now()

	var res *engine.Results
	if cfg.NoTUI || cfg.Silent {
		res = engine.New(cfg).Run(func(tea.Msg) {}, stateObj, stateFile, buildModuleSet(cfg.Modules, cfg.Profile))
	} else {
		m := ui.New(cfg.Target)
		prog := tea.NewProgram(m, tea.WithAltScreen())

		go func() {
			res = engine.New(cfg).Run(prog.Send, stateObj, stateFile, buildModuleSet(cfg.Modules, cfg.Profile))
			prog.Send(ui.DoneMsg{})
		}()

		if _, err := prog.Run(); err != nil {
			fail("TUI error: %v", err)
			os.Exit(1)
		}
	}

	filterSummary, err := applyFindingFilters(res, cfg)
	if err != nil {
		fail("finding policy error: %v", err)
		os.Exit(1)
	}
	if filterSummary.BaselineSuppressed > 0 || filterSummary.AllowSuppressed > 0 {
		success("finding policy → %d active, %d baseline-suppressed, %d allowlisted",
			filterSummary.After, filterSummary.BaselineSuppressed, filterSummary.AllowSuppressed)
	}

	sanitize.Results(res, cfg.ShowSecrets, cfg.RedactPercent)

	if cfg.SARIF != "" {
		if err := output.WriteFindingsSARIF(cfg.SARIF, version, res.Findings); err != nil {
			fail("SARIF error: %v", err)
		} else {
			success("SARIF output → %s", styleYellow.Render(cfg.SARIF))
		}
	}

	if err := report.Generate(cfg.Target, res.Subs, res.Ports, res.HTTP,
		res.Fingerprints, res.CVEEnrichment, res.CVEFilter,
		res.Vulns, res.WAFs, res.Dirs, res.JS, res.GH, res.Buckets,
		res.TLS, res.Redirects, res.AXFR, res.WHOIS, res.Screenshots,
		res.Takeover, res.CORS, res.Bypass, res.VHosts,
		res.Favicons, res.ASN, res.GraphQL, res.EmailSec,
		res.AdminPanel, res.SQLi, res.DefaultCreds, res.RateLimit, res.Templates, res.Findings, cfg.Output); err != nil {
		fail("report error: %v", err)
		os.Exit(1)
	}
	success("HTML report → %s", styleYellow.Render(cfg.Output))

	if cfg.JSON != "" {
		if err := output.WriteJSON(cfg.JSON, cfg.Target, res.Subs, res.Ports, res.HTTP,
			res.Fingerprints, res.CVEEnrichment, res.CVEFilter,
			res.Vulns, res.WAFs, res.Dirs, res.JS, res.GH, res.Buckets,
			res.TLS, res.Redirects, res.AXFR, res.WHOIS, res.Screenshots,
			res.Takeover, res.CORS, res.Bypass, res.VHosts,
			res.Favicons, res.ASN, res.GraphQL, res.EmailSec,
			res.AdminPanel, res.SQLi, res.DefaultCreds, res.RateLimit, res.Templates,
			res.XSS, res.SSRF, res.LFI, res.HostHeader, res.JWT, res.Wayback, res.Shodan, res.XXE, res.CmdI,
			res.Findings); err != nil {
			fail("JSON error: %v", err)
		} else {
			success("JSON output → %s", styleYellow.Render(cfg.JSON))
			importScanToWorkspace(cfg, cfg.JSON)
		}
	}

	if cfg.MarkdownOut != "" {
		if err := output.WriteMarkdown(cfg.MarkdownOut, output.MarkdownData{
			Target: cfg.Target, Subdomains: res.Subs, Ports: res.Ports, HTTP: res.HTTP,
			Fingerprints:  res.Fingerprints,
			CVEEnrichment: res.CVEEnrichment,
			CVEFilter:     res.CVEFilter,
			Vulns:         res.Vulns, WAFs: res.WAFs, DirHits: res.Dirs, JSFindings: res.JS,
			GHFindings: res.GH, Buckets: res.Buckets, TLS: res.TLS, Redirects: res.Redirects,
			AXFR: res.AXFR, WHOIS: res.WHOIS, Screenshots: res.Screenshots,
			Takeover: res.Takeover, CORS: res.CORS, Bypass: res.Bypass, VHosts: res.VHosts,
			Favicons: res.Favicons, ASN: res.ASN, GraphQL: res.GraphQL, EmailSec: res.EmailSec,
			AdminPanel: res.AdminPanel, SQLi: res.SQLi, DefaultCreds: res.DefaultCreds,
			RateLimit: res.RateLimit, Templates: res.Templates,
			XSS: res.XSS, SSRF: res.SSRF, LFI: res.LFI, HostHeader: res.HostHeader,
			JWT: res.JWT, Wayback: res.Wayback, Shodan: res.Shodan, XXE: res.XXE, CmdI: res.CmdI,
		}); err != nil {
			fail("Markdown error: %v", err)
		} else {
			success("Markdown report → %s", styleYellow.Render(cfg.MarkdownOut))
		}
	}

	if cfg.DiffFile != "" && cfg.JSON != "" {
		dr, err := diff.Compare(cfg.DiffFile, cfg.JSON)
		if err != nil {
			fail("diff error: %v", err)
		} else {
			fmt.Printf("\n  %s  Diff vs %s\n", stylePurple.Render("◆"), cfg.DiffFile)
			fmt.Printf("  New subdomains: %d  Removed: %d\n", len(dr.NewSubdomains), len(dr.RemovedSubdomains))
			fmt.Printf("  New ports: %d  Removed: %d\n", len(dr.NewPorts), len(dr.RemovedPorts))
			fmt.Printf("  New CVEs: %d  Removed: %d\n\n", len(dr.NewFindings), len(dr.ResolvedFindings))
		}
	}

	exitCode := exitCodeForFindings(res.Findings, cfg.FailOn)
	if !cfg.Silent {
		fmt.Printf("\n  %s  Finished in %s\n\n",
			styleGreen.Render("◆"),
			styleGreen.Render(time.Since(start).Round(time.Second).String()))
	}
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func buildModuleSet(modules []string, profile string) map[int]bool {
	ms := make(map[int]bool)
	if len(modules) == 0 {
		modules = modulesForProfile(profile)
	}
	for _, m := range modules {
		name := strings.ToLower(strings.TrimSpace(m))
		if name == "" {
			continue
		}
		if name == "all" {
			for i := 0; i <= 34; i++ {
				ms[i] = true
			}
			return ms
		}
		if n, ok := moduleNames[name]; ok {
			ms[n] = true
		}
	}
	return ms
}

func modulesForProfile(profile string) []string {
	profile = normalizeProfile(profile)
	if modules, ok := profileModules[profile]; ok {
		return modules
	}
	return profileModules["standard"]
}

func modulesForScanners(scanners []string) []string {
	if len(scanners) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var modules []string
	for _, scanner := range scanners {
		for _, part := range strings.Split(scanner, ",") {
			name := strings.ToLower(strings.TrimSpace(part))
			if name == "" {
				continue
			}
			for _, module := range scannerModules[name] {
				if module == "all" {
					return []string{"all"}
				}
				if !seen[module] {
					seen[module] = true
					modules = append(modules, module)
				}
			}
		}
	}
	return modules
}

func normalizeProfile(profile string) string {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "", "default":
		return "standard"
	case "passive", "safe":
		return "safe"
	case "std", "standard":
		return "standard"
	case "aggressive", "active":
		return "active"
	case "proof", "prove":
		return "proof"
	case "ci", "cicd":
		return "ci"
	case "full", "all":
		return "full"
	default:
		return "standard"
	}
}

func normalizeModernCLI() {
	if len(os.Args) < 2 {
		return
	}
	switch os.Args[1] {
	case "profiles", "profile":
		os.Args = []string{os.Args[0], "-list-profiles"}
	case "scan":
		normalizeScanArgs()
	case "report":
		normalizeReportArgs()
	case "project", "projects":
		normalizeProjectArgs()
	case "api", "server":
		normalizeAPIArgs()
	}
}

func normalizeScanArgs() {
	rest := append([]string{}, os.Args[2:]...)
	if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
		fmt.Fprintln(os.Stderr, "usage: recon-x scan domain <target> [--profile safe|standard|active|proof|ci] [flags]")
		os.Exit(2)
	}

	targetIndex := 0
	switch rest[0] {
	case "domain", "url", "target":
		targetIndex = 1
	case "repo", "repository":
		if len(rest) < 2 || strings.HasPrefix(rest[1], "-") {
			fmt.Fprintln(os.Stderr, "usage: recon-x scan repo <path> [--url http://localhost:3000] [--scanners secrets,deps,config,routes]")
			os.Exit(2)
		}
		next := []string{os.Args[0], "-repo", rest[1]}
		next = append(next, rest[2:]...)
		os.Args = next
		return
	}
	if len(rest) <= targetIndex || strings.HasPrefix(rest[targetIndex], "-") {
		fmt.Fprintln(os.Stderr, "usage: recon-x scan domain <target> [--profile safe|standard|active|proof|ci] [flags]")
		os.Exit(2)
	}

	target := rest[targetIndex]
	next := []string{os.Args[0], "-target", target}
	next = append(next, rest[targetIndex+1:]...)
	os.Args = next
}

func normalizeReportArgs() {
	rest := append([]string{}, os.Args[2:]...)
	if len(rest) == 0 || rest[0] != "serve" {
		fmt.Fprintln(os.Stderr, "usage: recon-x report serve <report.html|scan.json> [--listen 127.0.0.1:8088]")
		os.Exit(2)
	}
	if len(rest) < 2 || strings.HasPrefix(rest[1], "-") {
		fmt.Fprintln(os.Stderr, "usage: recon-x report serve <report.html|scan.json> [--listen 127.0.0.1:8088]")
		os.Exit(2)
	}
	next := []string{os.Args[0], "-serve-report", rest[1]}
	next = append(next, rest[2:]...)
	os.Args = next
}

func normalizeProjectArgs() {
	rest := append([]string{}, os.Args[2:]...)
	if os.Args[1] == "projects" && len(rest) == 0 {
		rest = []string{"list"}
	}
	if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
		fmt.Fprintln(os.Stderr, "usage: recon-x project <init|list|show|import|export> [args] [--store-dir .reconx]")
		os.Exit(2)
	}
	cmd := strings.ToLower(rest[0])
	next := []string{os.Args[0], "-project-command", cmd}
	switch cmd {
	case "list", "ls":
		next[2] = "list"
		next = append(next, rest[1:]...)
	case "init":
		if len(rest) < 2 || strings.HasPrefix(rest[1], "-") {
			fmt.Fprintln(os.Stderr, "usage: recon-x project init <project-id> [--name \"Display Name\"]")
			os.Exit(2)
		}
		next = append(next, "-project", rest[1])
		next = append(next, rest[2:]...)
	case "show":
		if len(rest) < 2 || strings.HasPrefix(rest[1], "-") {
			fmt.Fprintln(os.Stderr, "usage: recon-x project show <project-id>")
			os.Exit(2)
		}
		next = append(next, "-project", rest[1])
		next = append(next, rest[2:]...)
	case "import":
		if len(rest) < 3 || strings.HasPrefix(rest[1], "-") || strings.HasPrefix(rest[2], "-") {
			fmt.Fprintln(os.Stderr, "usage: recon-x project import <project-id> <scan.json> [--name \"Display Name\"]")
			os.Exit(2)
		}
		next = append(next, "-project", rest[1], "-project-scan", rest[2])
		next = append(next, rest[3:]...)
	case "export":
		if len(rest) < 2 || strings.HasPrefix(rest[1], "-") {
			fmt.Fprintln(os.Stderr, "usage: recon-x project export <project-id> [--output project.json]")
			os.Exit(2)
		}
		next = append(next, "-project", rest[1])
		next = append(next, rest[2:]...)
	default:
		fmt.Fprintln(os.Stderr, "usage: recon-x project <init|list|show|import|export> [args] [--store-dir .reconx]")
		os.Exit(2)
	}
	os.Args = next
}

func normalizeAPIArgs() {
	rest := append([]string{}, os.Args[2:]...)
	if os.Args[1] == "server" {
		next := []string{os.Args[0], "-api-command", "serve"}
		next = append(next, rest...)
		os.Args = next
		return
	}
	if len(rest) == 0 || rest[0] != "serve" {
		fmt.Fprintln(os.Stderr, "usage: recon-x api serve --api-token token:role[:project1|project2|*] [--api-listen 127.0.0.1:8090]")
		os.Exit(2)
	}
	next := []string{os.Args[0], "-api-command", "serve"}
	next = append(next, rest[1:]...)
	os.Args = next
}

func printProfiles() {
	fmt.Println("recon-x profiles")
	fmt.Println()
	fmt.Println("  safe      passive/minimal attack-surface mapping: DNS, ports, HTTP, TLS, WHOIS, ASN, Wayback")
	fmt.Println("  standard  default recon workflow: safe + paths, JS, buckets, CORS, GraphQL, admin, templates")
	fmt.Println("  active    authorized active checks: SQLi, XSS, SSRF, LFI, XXE, CMDi, default creds, bypass")
	fmt.Println("  proof     active checks plus stricter CVE evidence policy for staging/lab proof runs")
	fmt.Println("  ci        deterministic no-TUI workflow with JSON/SARIF/Markdown defaults")
	fmt.Println("  full      explicit compatibility profile that enables every module")
}

func parseFlags() engine.Config {
	target := flag.String("target", "", "Target domain  (e.g. example.com)")
	repoPath := flag.String("repo", "", "Source repository path for source-aware scanning")
	baseURL := flag.String("url", "", "Base URL for source-aware route correlation")
	projectID := flag.String("project", "", "Project id for workspace inventory")
	projectName := flag.String("name", "", "Project display name")
	projectCommand := flag.String("project-command", "", "Project workspace command")
	projectScan := flag.String("project-scan", "", "Scan JSON path for project import")
	storeDir := flag.String("store-dir", workspace.DefaultDir, "Recon-x workspace directory")
	apiCommand := flag.String("api-command", "", "API server command")
	apiToken := flag.String("api-token", os.Getenv("RECONX_API_TOKEN"), "API bearer token spec: token:role[:project1|project2|*]")
	apiListen := flag.String("api-listen", "127.0.0.1:8090", "API listen address")
	out := flag.String("output", "report.html", "HTML report output path")
	jsonOut := flag.String("json", "", "JSON output path (optional)")
	wordlist := flag.String("wordlist", "", "Custom subdomain wordlist (default: embedded)")
	subdomainFile := flag.String("subdomain-file", "", "Exact subdomain seed file (one FQDN or label per line)")
	dirWordlist := flag.String("dir-wordlist", "", "Custom paths wordlist for dir brute (default: embedded)")
	ports := flag.String("ports", defaultPorts, "Comma-separated ports/ranges to scan (e.g. 80,443,8000-8100)")
	threads := flag.Int("threads", 50, "Number of concurrent goroutines")
	noPassive := flag.Bool("no-passive", false, "Skip crt.sh passive recon")
	githubToken := flag.String("github-token", "", "GitHub personal access token for dorking (optional)")
	proxy := flag.String("proxy", "", "HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080)")
	scopeFile := flag.String("scope-file", "", "Path to scope file (one entry per line: *.example.com, 10.0.0.0/8)")
	sarifOut := flag.String("sarif", "", "SARIF output path for CI/CD integration (optional)")
	notifySlack := flag.String("notify-slack", "", "Slack incoming webhook URL for critical finding alerts")
	notifyTelegram := flag.String("notify-telegram", "", "Telegram bot TOKEN@CHATID for critical alerts")
	resume := flag.Bool("resume", false, "Resume interrupted scan from state file")
	configFile := flag.String("config", "", "Path to YAML config file")
	baselinePath := flag.String("baseline", "", "Previous recon-x JSON report used to suppress known findings")
	allowlistPath := flag.String("allowlist", ".reconxignore", "Allowlist file for suppressing findings")
	failOn := flag.String("fail-on", "", "Exit with code 1 when findings at or above severity exist: critical, high, medium, low, info, none")
	profile := flag.String("profile", "standard", "Scan profile: safe, standard, active, proof, ci, full")
	activeShortcut := flag.Bool("active", false, "Shortcut for -profile active")
	proofShortcut := flag.Bool("proof", false, "Shortcut for -profile proof")
	ciShortcut := flag.Bool("ci", false, "Shortcut for -profile ci -no-tui")
	listProfiles := flag.Bool("list-profiles", false, "List scan profiles and exit")
	scannersFlag := flag.String("scanners", "", "Comma-separated scanner groups (domain: dns,http,tls,cve,secrets,cloud,osint,web; repo: secrets,deps,config,routes)")
	modulesFlag := flag.String("modules", "", "Comma-separated modules to run (overrides -profile); use all for every module")
	outputDir := flag.String("output-dir", "", "Directory for output files")
	retries := flag.Int("retries", 2, "Number of HTTP retries")
	rate := flag.Int("rate", 50, "Max HTTP requests per second")
	silent := flag.Bool("silent", false, "Suppress all non-critical output")
	noTUI := flag.Bool("no-tui", false, "Disable the interactive TUI; useful for CI and logs")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	showSecrets := flag.Bool("show-secrets", false, "Show raw secrets/default credentials in outputs (unsafe; redacted by default)")
	redactPercent := flag.Int("redact", 100, "Secret redaction percentage for outputs, 0-100")
	ver := flag.Bool("version", false, "Print version and exit")
	dbHash := flag.Bool("db-hash", false, "Print CVE database fingerprint and exit (for stamping integrity.go)")
	resolver := flag.String("resolver", "", "Custom DNS resolver address (e.g. 1.1.1.1:53)")
	shodanKey := flag.String("shodan-key", "", "Shodan API key for host enrichment (optional)")
	markdownOut := flag.String("markdown", "", "Markdown report output path (optional)")
	diffFile := flag.String("diff", "", "Previous JSON report to diff against (optional)")
	cveLive := flag.Bool("cve-live", false, "Enrich CVE matches from live NVD/CISA KEV/FIRST EPSS feeds")
	nvdAPIKey := flag.String("nvd-api-key", "", "NVD API key for higher CVE enrichment rate limits")
	cveTimeout := flag.Int("cve-timeout", 45, "Timeout in seconds for live CVE enrichment")
	nmapXML := flag.String("nmap-xml", "", "Import Nmap XML (-oX) service/version results")
	skipPortScan := flag.Bool("skip-portscan", false, "Skip built-in TCP scan (useful with -nmap-xml)")
	cveProfile := flag.String("cve-profile", "balanced", "CVE precision profile: balanced, strict, broad, kev")
	cveMinConfidence := flag.String("cve-min-confidence", "", "Minimum CVE confidence: low, medium, high, confirmed")
	cveRequireVersion := flag.Bool("cve-require-version", false, "Report CVEs only when product version evidence exists")
	cveOnlyKEV := flag.Bool("cve-only-kev", false, "Report only CISA KEV known-exploited CVEs")
	cveMinCVSS := flag.Float64("cve-min-cvss", 0, "Minimum CVSS for CVE reporting")
	cveEvidenceTruth := flag.String("cve-evidence", "", "Path to CVE ground-truth JSON; evaluates -cve-evidence-scan and exits")
	cveEvidenceScan := flag.String("cve-evidence-scan", "", "Recon-x JSON report to compare against -cve-evidence")
	cveEvidenceReport := flag.String("cve-evidence-report", "cve-evidence.json", "CVE evidence JSON output path")
	cveEvidenceMarkdown := flag.String("cve-evidence-markdown", "", "CVE evidence Markdown output path")
	cveEvidenceThreshold := flag.Float64("cve-evidence-threshold", 0.90, "Minimum precision and recall required for CVE evidence pass")
	cveAssuranceScan := flag.String("cve-assurance", "", "Recon-x JSON report to evaluate 90% CVE claim readiness for an authorized domain")
	cveAssuranceReport := flag.String("cve-assurance-report", "cve-assurance.json", "CVE assurance JSON output path")
	cveAssuranceMarkdown := flag.String("cve-assurance-markdown", "", "CVE assurance Markdown output path")
	cveAssuranceThreshold := flag.Float64("cve-assurance-threshold", 0.90, "Minimum evidence coverage required for public-service CVE assurance")
	serveReport := flag.String("serve-report", "", "Serve an existing HTML report locally and exit")
	listenAddr := flag.String("listen", "127.0.0.1:8088", "Listen address for -serve-report")
	flag.Parse()
	visited := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { visited[f.Name] = true })

	if *ver {
		fmt.Printf("recon-x v%s\n", version)
		os.Exit(0)
	}

	if *listProfiles {
		printProfiles()
		os.Exit(0)
	}

	if *serveReport != "" {
		if err := serveReportFile(*serveReport, *listenAddr); err != nil {
			fail("report serve error: %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *dbHash {
		fmt.Println(vulns.ComputeDBHash())
		os.Exit(0)
	}

	if *cveEvidenceTruth != "" {
		runCVEEvidence(*cveEvidenceScan, *cveEvidenceTruth, *cveEvidenceReport, *cveEvidenceMarkdown, *cveEvidenceThreshold)
	}
	if *cveAssuranceScan != "" {
		runCVEAssurance(*cveAssuranceScan, *cveAssuranceReport, *cveAssuranceMarkdown, *cveAssuranceThreshold)
	}

	cfg := engine.Config{
		Target:            *target,
		RepoPath:          *repoPath,
		BaseURL:           *baseURL,
		Project:           *projectID,
		ProjectName:       *projectName,
		ProjectCommand:    *projectCommand,
		ProjectScan:       *projectScan,
		StoreDir:          *storeDir,
		APICommand:        *apiCommand,
		APIToken:          *apiToken,
		APIListen:         *apiListen,
		Output:            *out,
		JSON:              *jsonOut,
		Wordlist:          *wordlist,
		SubdomainFile:     *subdomainFile,
		DirWordlist:       *dirWordlist,
		Ports:             *ports,
		Threads:           *threads,
		NoPassive:         *noPassive,
		GitHubToken:       *githubToken,
		Proxy:             *proxy,
		ScopeFile:         *scopeFile,
		SARIF:             *sarifOut,
		NotifySlack:       *notifySlack,
		NotifyTelegram:    *notifyTelegram,
		Resume:            *resume,
		ConfigFile:        *configFile,
		TargetType:        "domain",
		Profile:           normalizeProfile(*profile),
		OutputDir:         *outputDir,
		Baseline:          *baselinePath,
		Allowlist:         *allowlistPath,
		FailOn:            normalizeFailOn(*failOn),
		Retries:           *retries,
		Rate:              *rate,
		Silent:            *silent,
		NoTUI:             *noTUI,
		Verbose:           *verbose,
		ShowSecrets:       *showSecrets,
		RedactPercent:     clampPercent(*redactPercent),
		Resolver:          *resolver,
		ShodanKey:         *shodanKey,
		MarkdownOut:       *markdownOut,
		DiffFile:          *diffFile,
		CVELive:           *cveLive || *nvdAPIKey != "",
		NVDAPIKey:         *nvdAPIKey,
		CVETimeout:        *cveTimeout,
		NmapXML:           *nmapXML,
		SkipPortScan:      *skipPortScan,
		CVEProfile:        *cveProfile,
		CVEMinConfidence:  *cveMinConfidence,
		CVERequireVersion: *cveRequireVersion,
		CVEOnlyKEV:        *cveOnlyKEV,
		CVEMinCVSS:        *cveMinCVSS,
	}
	if cfg.RepoPath != "" {
		cfg.TargetType = "repo"
		if cfg.Target == "" {
			cfg.Target = "repo:" + cfg.RepoPath
		}
	}
	if cfg.APICommand != "" && visited["listen"] {
		cfg.APIListen = *listenAddr
	}

	if *modulesFlag != "" {
		cfg.Modules = strings.Split(*modulesFlag, ",")
	}
	if *scannersFlag != "" {
		cfg.Scanners = strings.Split(*scannersFlag, ",")
		if cfg.TargetType == "domain" && *modulesFlag == "" {
			cfg.Modules = modulesForScanners(cfg.Scanners)
		}
	}

	if *configFile != "" {
		fileCfg, err := config.Load(*configFile)
		if err == nil {
			if fileCfg.Threads > 0 && *threads == 50 {
				cfg.Threads = fileCfg.Threads
			}
			if fileCfg.Rate > 0 && *rate == 50 {
				cfg.Rate = fileCfg.Rate
			}
			if fileCfg.Retries > 0 && *retries == 2 {
				cfg.Retries = fileCfg.Retries
			}
			if fileCfg.OutputDir != "" && *outputDir == "" {
				cfg.OutputDir = fileCfg.OutputDir
			}
			if fileCfg.TargetType != "" {
				cfg.TargetType = fileCfg.TargetType
			}
			if fileCfg.RepoPath != "" && !visited["repo"] {
				cfg.RepoPath = fileCfg.RepoPath
				cfg.TargetType = "repo"
			}
			if fileCfg.BaseURL != "" && !visited["url"] {
				cfg.BaseURL = fileCfg.BaseURL
			}
			if fileCfg.Project != "" && !visited["project"] {
				cfg.Project = fileCfg.Project
			}
			if fileCfg.ProjectName != "" && !visited["name"] {
				cfg.ProjectName = fileCfg.ProjectName
			}
			if fileCfg.StoreDir != "" && !visited["store-dir"] {
				cfg.StoreDir = fileCfg.StoreDir
			}
			if fileCfg.Baseline != "" && !visited["baseline"] {
				cfg.Baseline = fileCfg.Baseline
			}
			if fileCfg.Allowlist != "" && !visited["allowlist"] {
				cfg.Allowlist = fileCfg.Allowlist
			}
			if fileCfg.FailOn != "" && !visited["fail-on"] {
				cfg.FailOn = normalizeFailOn(fileCfg.FailOn)
			}
			if fileCfg.GithubToken != "" && *githubToken == "" {
				cfg.GitHubToken = fileCfg.GithubToken
			}
			if fileCfg.Profile != "" && !visited["profile"] {
				cfg.Profile = normalizeProfile(fileCfg.Profile)
			}
			if len(fileCfg.Scanners) > 0 && !visited["scanners"] {
				cfg.Scanners = fileCfg.Scanners
				if cfg.TargetType == "domain" && *modulesFlag == "" {
					cfg.Modules = modulesForScanners(cfg.Scanners)
				}
			}
			if len(fileCfg.Modules) > 0 && *modulesFlag == "" {
				cfg.Modules = fileCfg.Modules
			}
			if fileCfg.SubdomainFile != "" && *subdomainFile == "" {
				cfg.SubdomainFile = fileCfg.SubdomainFile
			}
			if len(fileCfg.Templates) > 0 {
				cfg.TemplatePaths = fileCfg.Templates
			}
			if fileCfg.Silent {
				cfg.Silent = true
			}
			if fileCfg.NoTUI && !visited["no-tui"] {
				cfg.NoTUI = true
			}
			if fileCfg.Verbose {
				cfg.Verbose = true
			}
			if fileCfg.ShowSecrets && !visited["show-secrets"] {
				cfg.ShowSecrets = true
			}
			if fileCfg.RedactPercent > 0 && !visited["redact"] {
				cfg.RedactPercent = clampPercent(fileCfg.RedactPercent)
			}
			if cfg.Target == "" && len(fileCfg.Targets) > 0 {
				cfg.Target = fileCfg.Targets[0]
			}
			if fileCfg.Resolver != "" && *resolver == "" {
				cfg.Resolver = fileCfg.Resolver
			}
			if fileCfg.CVELive && !*cveLive {
				cfg.CVELive = true
			}
			if fileCfg.NVDAPIKey != "" && *nvdAPIKey == "" {
				cfg.NVDAPIKey = fileCfg.NVDAPIKey
				cfg.CVELive = true
			}
			if fileCfg.CVETimeout > 0 && *cveTimeout == 45 {
				cfg.CVETimeout = fileCfg.CVETimeout
			}
			if fileCfg.NmapXML != "" && *nmapXML == "" {
				cfg.NmapXML = fileCfg.NmapXML
			}
			if fileCfg.SkipPortScan && !*skipPortScan {
				cfg.SkipPortScan = true
			}
			if fileCfg.CVEProfile != "" && *cveProfile == "balanced" {
				cfg.CVEProfile = fileCfg.CVEProfile
			}
			if fileCfg.CVEMinConfidence != "" && *cveMinConfidence == "" {
				cfg.CVEMinConfidence = fileCfg.CVEMinConfidence
			}
			if fileCfg.CVERequireVersion && !*cveRequireVersion {
				cfg.CVERequireVersion = true
			}
			if fileCfg.CVEOnlyKEV && !*cveOnlyKEV {
				cfg.CVEOnlyKEV = true
			}
			if fileCfg.CVEMinCVSS > 0 && *cveMinCVSS == 0 {
				cfg.CVEMinCVSS = fileCfg.CVEMinCVSS
			}
		}
	}

	if cfg.APICommand != "" {
		runAPICommand(cfg)
		os.Exit(0)
	}

	if cfg.ProjectCommand != "" {
		runProjectCommand(cfg, visited["output"])
		os.Exit(0)
	}

	if *activeShortcut {
		cfg.Profile = "active"
	}
	if *proofShortcut {
		cfg.Profile = "proof"
	}
	if *ciShortcut {
		cfg.Profile = "ci"
	}
	applyProfileDefaults(&cfg, *cveProfile == "balanced", *cveMinConfidence == "", !*cveRequireVersion, !visited["fail-on"])
	if cfg.RepoPath != "" {
		cfg.TargetType = "repo"
		if cfg.Target == "" || strings.HasPrefix(cfg.Target, "repo:") {
			cfg.Target = "repo:" + cfg.RepoPath
		}
	} else if cfg.TargetType == "" {
		cfg.TargetType = "domain"
	}

	if cfg.OutputDir != "" {
		if err := os.MkdirAll(cfg.OutputDir, 0755); err == nil {
			cfg.Output = filepath.Join(cfg.OutputDir, filepath.Base(cfg.Output))
			if cfg.JSON != "" {
				cfg.JSON = filepath.Join(cfg.OutputDir, filepath.Base(cfg.JSON))
			}
			if cfg.SARIF != "" {
				cfg.SARIF = filepath.Join(cfg.OutputDir, filepath.Base(cfg.SARIF))
			}
			if cfg.MarkdownOut != "" {
				cfg.MarkdownOut = filepath.Join(cfg.OutputDir, filepath.Base(cfg.MarkdownOut))
			}
		}
	}

	if cfg.Target == "" && cfg.RepoPath == "" {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			cfg.Target = strings.TrimSpace(scanner.Text())
		}
	}

	if cfg.Target == "" && cfg.RepoPath == "" {
		fail("no target specified. Usage: recon-x -target <domain>")
		flag.Usage()
		os.Exit(1)
	}

	return cfg
}

func applyProfileDefaults(cfg *engine.Config, cveProfileDefault, cveMinConfidenceDefault, cveRequireVersionDefault, failOnDefault bool) {
	cfg.Profile = normalizeProfile(cfg.Profile)
	if cfg.Profile == "ci" {
		cfg.NoTUI = true
		if cfg.FailOn == "" && failOnDefault {
			cfg.FailOn = "high"
		}
		if cfg.JSON == "" {
			cfg.JSON = "scan.json"
		}
		if cfg.SARIF == "" {
			cfg.SARIF = "scan.sarif"
		}
		if cfg.MarkdownOut == "" {
			cfg.MarkdownOut = "report.md"
		}
	}
	if cfg.Project != "" && cfg.JSON == "" {
		cfg.JSON = "scan.json"
	}
	if cfg.Profile == "proof" {
		if cveProfileDefault {
			cfg.CVEProfile = "strict"
		}
		if cveMinConfidenceDefault {
			cfg.CVEMinConfidence = "high"
		}
		if cveRequireVersionDefault {
			cfg.CVERequireVersion = true
		}
	}
}

func runRepoScan(cfg engine.Config) {
	quiet = cfg.Silent
	start := time.Now()
	src, err := source.Scan(source.Config{
		Path:        cfg.RepoPath,
		BaseURL:     cfg.BaseURL,
		Scanners:    cfg.Scanners,
		ShowSecrets: cfg.ShowSecrets,
	})
	if err != nil {
		fail("repo scan error: %v", err)
		os.Exit(1)
	}
	cfg.Target = "repo:" + src.Root
	res := &engine.Results{Findings: src.Findings}

	filterSummary, err := applyFindingFilters(res, cfg)
	if err != nil {
		fail("finding policy error: %v", err)
		os.Exit(1)
	}
	src.Findings = res.Findings
	if filterSummary.BaselineSuppressed > 0 || filterSummary.AllowSuppressed > 0 {
		success("finding policy → %d active, %d baseline-suppressed, %d allowlisted",
			filterSummary.After, filterSummary.BaselineSuppressed, filterSummary.AllowSuppressed)
	}
	if !cfg.Silent {
		fmt.Printf("recon-x v%s source scan %s scanners=%s\n", version, src.Root, strings.Join(src.Scanners, ","))
	}

	if cfg.SARIF != "" {
		if err := output.WriteFindingsSARIF(cfg.SARIF, version, res.Findings); err != nil {
			fail("SARIF error: %v", err)
		} else {
			success("SARIF output → %s", styleYellow.Render(cfg.SARIF))
		}
	}
	if err := report.Generate(cfg.Target, nil, nil, nil,
		nil, vulns.EnrichReport{}, vulns.FilterReport{},
		nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil,
		nil, nil, nil, nil,
		nil, nil, nil, nil, res.Findings, cfg.Output); err != nil {
		fail("report error: %v", err)
		os.Exit(1)
	}
	success("HTML report → %s", styleYellow.Render(cfg.Output))

	if cfg.JSON != "" {
		if err := output.WriteSourceJSON(cfg.JSON, cfg.Target, src); err != nil {
			fail("JSON error: %v", err)
		} else {
			success("JSON output → %s", styleYellow.Render(cfg.JSON))
			importScanToWorkspace(cfg, cfg.JSON)
		}
	}
	if cfg.MarkdownOut != "" {
		if err := output.WriteSourceMarkdown(cfg.MarkdownOut, cfg.Target, src); err != nil {
			fail("Markdown error: %v", err)
		} else {
			success("Markdown report → %s", styleYellow.Render(cfg.MarkdownOut))
		}
	}

	exitCode := exitCodeForFindings(res.Findings, cfg.FailOn)
	if !cfg.Silent {
		fmt.Printf("\n  %s  Finished in %s\n\n",
			styleGreen.Render("◆"),
			styleGreen.Render(time.Since(start).Round(time.Second).String()))
	}
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func importScanToWorkspace(cfg engine.Config, scanPath string) {
	if strings.TrimSpace(cfg.Project) == "" {
		return
	}
	meta, err := workspace.ImportScan(cfg.StoreDir, cfg.Project, scanPath, workspace.ImportOptions{
		Name:    cfg.ProjectName,
		Profile: cfg.Profile,
	})
	if err != nil {
		fail("workspace import error: %v", err)
		return
	}
	success("workspace import → project=%s scan=%s findings=%d", cfg.Project, meta.ID, meta.Findings)
}

func runAPICommand(cfg engine.Config) {
	if strings.ToLower(strings.TrimSpace(cfg.APICommand)) != "serve" {
		fail("unknown api command %q", cfg.APICommand)
		os.Exit(2)
	}
	tokens, err := apiserver.ParseTokenSpecs(cfg.APIToken)
	if err != nil {
		fail("api token error: %v", err)
		os.Exit(1)
	}
	if len(tokens) == 0 {
		fail("api serve requires --api-token token:role[:project1|project2|*] or RECONX_API_TOKEN")
		os.Exit(2)
	}
	fmt.Printf("Serving recon-x API at http://%s  store=%s\n", cfg.APIListen, workspacePath(cfg.StoreDir))
	if err := apiserver.ListenAndServe(cfg.APIListen, apiserver.Config{
		StoreDir: cfg.StoreDir,
		Version:  version,
		Tokens:   tokens,
	}); err != nil {
		fail("api server error: %v", err)
		os.Exit(1)
	}
}

func runProjectCommand(cfg engine.Config, outputSet bool) {
	cmd := strings.ToLower(strings.TrimSpace(cfg.ProjectCommand))
	switch cmd {
	case "init":
		requireProjectID(cfg.Project)
		pf, err := workspace.InitProject(cfg.StoreDir, cfg.Project, cfg.ProjectName)
		if err != nil {
			fail("project init error: %v", err)
			os.Exit(1)
		}
		success("project initialized → %s (%s)", pf.Project.ID, workspacePath(cfg.StoreDir))
	case "list":
		projects, err := workspace.ListProjects(cfg.StoreDir)
		if err != nil {
			fail("project list error: %v", err)
			os.Exit(1)
		}
		printProjectList(projects)
	case "show":
		requireProjectID(cfg.Project)
		pf, err := workspace.LoadProject(cfg.StoreDir, cfg.Project)
		if err != nil {
			fail("project show error: %v", err)
			os.Exit(1)
		}
		printProjectShow(pf)
	case "import":
		requireProjectID(cfg.Project)
		if strings.TrimSpace(cfg.ProjectScan) == "" {
			fail("project import requires a scan JSON path")
			os.Exit(2)
		}
		meta, err := workspace.ImportScan(cfg.StoreDir, cfg.Project, cfg.ProjectScan, workspace.ImportOptions{
			Name:    cfg.ProjectName,
			Profile: cfg.Profile,
		})
		if err != nil {
			fail("project import error: %v", err)
			os.Exit(1)
		}
		success("project import → project=%s scan=%s findings=%d", cfg.Project, meta.ID, meta.Findings)
	case "export":
		requireProjectID(cfg.Project)
		out := ""
		if outputSet {
			out = cfg.Output
		}
		ex, err := workspace.WriteExport(cfg.StoreDir, cfg.Project, out)
		if err != nil {
			fail("project export error: %v", err)
			os.Exit(1)
		}
		if out == "" {
			data, _ := json.MarshalIndent(ex, "", "  ")
			fmt.Println(string(data))
		} else {
			success("project export → %s", out)
		}
	default:
		fail("unknown project command %q", cfg.ProjectCommand)
		os.Exit(2)
	}
}

func requireProjectID(id string) {
	if strings.TrimSpace(id) == "" {
		fail("project id is required")
		os.Exit(2)
	}
	if !workspace.ValidProjectID(strings.ToLower(strings.TrimSpace(id))) {
		fail("invalid project id %q; use lowercase letters, numbers, dots, dashes or underscores", id)
		os.Exit(2)
	}
}

func printProjectList(projects []workspace.Project) {
	if len(projects) == 0 {
		fmt.Println("No recon-x projects yet. Create one with: recon-x project init <project-id>")
		return
	}
	fmt.Printf("%-22s %-24s %5s %5s %5s %5s %5s %s\n", "PROJECT", "NAME", "SCANS", "CRIT", "HIGH", "MED", "LOW", "LATEST")
	for _, p := range projects {
		fmt.Printf("%-22s %-24s %5d %5d %5d %5d %5d %s\n",
			p.ID, trimTable(p.Name, 24), p.ScanCount,
			p.SeverityCounts["critical"], p.SeverityCounts["high"], p.SeverityCounts["medium"], p.SeverityCounts["low"], p.LastScanAt)
	}
}

func printProjectShow(pf workspace.ProjectFile) {
	p := pf.Project
	fmt.Printf("Project: %s\n", p.ID)
	fmt.Printf("Name: %s\n", p.Name)
	fmt.Printf("Workspace scans: %d\n", p.ScanCount)
	fmt.Printf("Latest target: %s (%s)\n", p.LastTarget, p.LastTargetType)
	fmt.Printf("Latest findings: %d  critical=%d high=%d medium=%d low=%d info=%d\n",
		p.LatestFindings,
		p.SeverityCounts["critical"], p.SeverityCounts["high"], p.SeverityCounts["medium"], p.SeverityCounts["low"], p.SeverityCounts["info"])
	fmt.Printf("Source ready: %t  Domain ready: %t\n", p.SourceReady, p.DomainReady)
	if p.RBACReadyHint != "" {
		fmt.Printf("RBAC hint: %s\n", p.RBACReadyHint)
	}
	if len(pf.Scans) == 0 {
		return
	}
	fmt.Println()
	fmt.Printf("%-24s %-7s %-8s %5s %5s %5s %5s %s\n", "SCAN", "TYPE", "PROFILE", "CRIT", "HIGH", "MED", "LOW", "TARGET")
	limit := len(pf.Scans)
	if limit > 10 {
		limit = 10
	}
	for _, s := range pf.Scans[:limit] {
		fmt.Printf("%-24s %-7s %-8s %5d %5d %5d %5d %s\n",
			s.ID, s.TargetType, s.Profile,
			s.SeverityCounts["critical"], s.SeverityCounts["high"], s.SeverityCounts["medium"], s.SeverityCounts["low"], trimTable(s.Target, 48))
	}
}

func workspacePath(root string) string {
	if strings.TrimSpace(root) == "" {
		root = workspace.DefaultDir
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return root
	}
	return abs
}

func trimTable(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

func applyFindingFilters(res *engine.Results, cfg engine.Config) (baseline.Summary, error) {
	if res == nil {
		return baseline.Summary{}, nil
	}
	base, err := baseline.LoadFingerprints(cfg.Baseline)
	if err != nil {
		return baseline.Summary{}, err
	}
	rules, err := baseline.LoadRules(cfg.Allowlist)
	if err != nil {
		return baseline.Summary{}, err
	}
	filtered, summary := baseline.Apply(res.Findings, base, rules)
	res.Findings = filtered
	return summary, nil
}

func normalizeFailOn(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "none", "off", "false":
		return ""
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(level))
	default:
		return "high"
	}
}

func exitCodeForFindings(findings []finding.Finding, failOn string) int {
	failOn = normalizeFailOn(failOn)
	if failOn == "" {
		return 0
	}
	for _, item := range findings {
		if severityAtLeast(item.Severity, failOn) {
			fail("fail-on=%s matched %s finding %s (%s)", failOn, item.Severity, item.Fingerprint, item.Title)
			return 1
		}
	}
	return 0
}

func severityAtLeast(sev finding.Severity, threshold string) bool {
	return severityRank(string(sev)) >= severityRank(threshold)
}

func severityRank(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func serveReportFile(path, listen string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if info, err := os.Stat(abs); err != nil {
		return err
	} else if info.IsDir() {
		return fmt.Errorf("%s is a directory, expected an HTML report file", abs)
	}
	if strings.EqualFold(filepath.Ext(abs), ".json") {
		return serveJSONReportFile(abs, listen)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/report.html" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeFile(w, r, abs)
	})
	fmt.Printf("Serving %s at http://%s\n", abs, listen)
	return http.ListenAndServe(listen, mux)
}

func serveJSONReportFile(abs, listen string) error {
	raw, err := os.ReadFile(abs)
	if err != nil {
		return err
	}
	view := buildJSONReportView(raw)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/report" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, view)
	})
	mux.HandleFunc("/scan.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw)
	})
	fmt.Printf("Serving %s at http://%s\n", abs, listen)
	return http.ListenAndServe(listen, mux)
}

func buildJSONReportView(raw []byte) string {
	var doc struct {
		Target   string            `json:"target"`
		Findings []finding.Finding `json:"findings"`
		Source   struct {
			Files     int                      `json:"files"`
			Findings  []finding.Finding        `json:"findings"`
			Routes    []source.Route           `json:"routes"`
			Manifests []source.ManifestSummary `json:"manifests"`
		} `json:"source"`
	}
	_ = json.Unmarshal(raw, &doc)
	findings := doc.Findings
	if len(findings) == 0 && len(doc.Source.Findings) > 0 {
		findings = doc.Source.Findings
	}
	target := doc.Target
	if target == "" {
		target = "recon-x scan"
	}
	title := "recon-x report"
	meta := `recon-x JSON dashboard · <a href="/scan.json">raw scan.json</a>`
	if doc.Source.Files > 0 || len(doc.Source.Findings) > 0 || len(doc.Source.Routes) > 0 || len(doc.Source.Manifests) > 0 {
		title = "recon-x Source Report"
		meta = `recon-x Source Report · <a href="/scan.json">raw scan.json</a>`
	}
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>` + html.EscapeString(title) + `</title><style>body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#0b0f14;color:#d9e2ec;margin:0}header{padding:24px 32px;border-bottom:1px solid #233142;background:#111923}h1{margin:0;font-size:24px}.meta{color:#8aa0b4;margin-top:6px}.cards{display:flex;gap:12px;padding:20px 32px;flex-wrap:wrap}.card{border:1px solid #233142;background:#111923;padding:14px 16px;border-radius:8px;min-width:130px}.num{font-size:28px;font-weight:700}.label{color:#8aa0b4;font-size:12px;text-transform:uppercase;letter-spacing:.08em}main{padding:0 32px 32px}table{width:100%;border-collapse:collapse;border:1px solid #233142;background:#0f1720}th,td{padding:10px;border-top:1px solid #233142;text-align:left;vertical-align:top}th{color:#8aa0b4;font-size:12px;text-transform:uppercase;background:#111923}code{color:#7ee787}.sev-critical,.sev-high{color:#ff7b72}.sev-medium{color:#d29922}.sev-low,.sev-info{color:#79c0ff}a{color:#7ee787}</style></head><body>`)
	b.WriteString("<header><h1>" + html.EscapeString(target) + "</h1><div class=\"meta\">" + meta + "</div></header>")
	b.WriteString("<section class=\"cards\">")
	b.WriteString(fmt.Sprintf("<div class=\"card\"><div class=\"num\">%d</div><div class=\"label\">Findings</div></div>", len(findings)))
	b.WriteString(fmt.Sprintf("<div class=\"card\"><div class=\"num\">%d</div><div class=\"label\">Files</div></div>", doc.Source.Files))
	b.WriteString(fmt.Sprintf("<div class=\"card\"><div class=\"num\">%d</div><div class=\"label\">Routes</div></div>", len(doc.Source.Routes)))
	b.WriteString(fmt.Sprintf("<div class=\"card\"><div class=\"num\">%d</div><div class=\"label\">Manifests</div></div>", len(doc.Source.Manifests)))
	b.WriteString("</section><main><table><thead><tr><th>Priority</th><th>Severity</th><th>Type</th><th>Fingerprint</th><th>Affected</th><th>Title</th><th>Evidence</th></tr></thead><tbody>")
	for _, f := range findings {
		b.WriteString("<tr>")
		b.WriteString("<td>" + html.EscapeString(f.Priority) + "</td>")
		b.WriteString("<td class=\"sev-" + html.EscapeString(string(f.Severity)) + "\">" + html.EscapeString(string(f.Severity)) + "</td>")
		b.WriteString("<td>" + html.EscapeString(f.Type) + "</td>")
		b.WriteString("<td><code>" + html.EscapeString(f.Fingerprint) + "</code></td>")
		b.WriteString("<td>" + html.EscapeString(f.AffectedURL) + "</td>")
		b.WriteString("<td>" + html.EscapeString(f.Title) + "</td>")
		b.WriteString("<td><code>" + html.EscapeString(f.Evidence) + "</code></td>")
		b.WriteString("</tr>")
	}
	if len(findings) == 0 {
		b.WriteString(`<tr><td colspan="7">No active findings.</td></tr>`)
	}
	b.WriteString("</tbody></table></main></body></html>")
	return b.String()
}

func clampPercent(n int) int {
	if n < 0 {
		return 0
	}
	if n > 100 {
		return 100
	}
	return n
}

func runCVEEvidence(scanPath, truthPath, reportPath, markdownPath string, threshold float64) {
	if scanPath == "" {
		fail("-cve-evidence-scan is required with -cve-evidence")
		os.Exit(1)
	}
	if reportPath == "" {
		reportPath = "cve-evidence.json"
	}
	ev, err := evidence.EvaluateFiles(scanPath, truthPath, version, threshold)
	if err != nil {
		fail("CVE evidence error: %v", err)
		os.Exit(1)
	}
	if err := evidence.WriteJSON(reportPath, ev); err != nil {
		fail("CVE evidence report error: %v", err)
		os.Exit(1)
	}
	if markdownPath != "" {
		if err := evidence.WriteMarkdown(markdownPath, ev); err != nil {
			fail("CVE evidence markdown error: %v", err)
			os.Exit(1)
		}
	}

	status := styleRed.Render("FAIL")
	exitCode := 2
	if ev.Passed {
		status = styleGreen.Render("PASS")
		exitCode = 0
	}
	fmt.Printf("CVE evidence %s\n", status)
	fmt.Printf("Precision: %.2f%%  Recall: %.2f%%  F1: %.2f%%\n",
		ev.Totals.Precision*100, ev.Totals.Recall*100, ev.Totals.F1*100)
	fmt.Printf("TP/FP/FN: %d/%d/%d  threshold: %.2f%%\n",
		ev.Totals.TruePositive, ev.Totals.FalsePositive, ev.Totals.FalseNegative, ev.Threshold*100)
	fmt.Printf("Evidence JSON: %s\n", reportPath)
	if markdownPath != "" {
		fmt.Printf("Evidence Markdown: %s\n", markdownPath)
	}
	os.Exit(exitCode)
}

func runCVEAssurance(scanPath, reportPath, markdownPath string, threshold float64) {
	if reportPath == "" {
		reportPath = "cve-assurance.json"
	}
	ar, err := evidence.EvaluateAssuranceFile(scanPath, version, threshold)
	if err != nil {
		fail("CVE assurance error: %v", err)
		os.Exit(1)
	}
	if err := evidence.WriteAssuranceJSON(reportPath, ar); err != nil {
		fail("CVE assurance report error: %v", err)
		os.Exit(1)
	}
	if markdownPath != "" {
		if err := evidence.WriteAssuranceMarkdown(markdownPath, ar); err != nil {
			fail("CVE assurance markdown error: %v", err)
			os.Exit(1)
		}
	}

	status := styleRed.Render("FAIL")
	exitCode := 2
	if ar.PublicServiceClaimEligible {
		status = styleGreen.Render("PASS")
		exitCode = 0
	}
	fmt.Printf("CVE public-service assurance %s\n", status)
	fmt.Printf("Evidence readiness: %.2f%%  threshold: %.2f%%\n", ar.EvidenceReadinessScore*100, ar.Threshold*100)
	fmt.Printf("Whole-domain all-CVE 90%% claim: %s\n", passText(ar.WholeDomainClaimEligible))
	fmt.Printf("Assurance JSON: %s\n", reportPath)
	if markdownPath != "" {
		fmt.Printf("Assurance Markdown: %s\n", markdownPath)
	}
	os.Exit(exitCode)
}

func passText(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

func success(format string, a ...any) {
	if quiet {
		return
	}
	fmt.Printf("[%s] %s\n", styleGreen.Render("✓"), fmt.Sprintf(format, a...))
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[%s] %s\n", styleRed.Render("✗"), fmt.Sprintf(format, a...))
}

func parsePortList(s string) []int {
	parts := strings.Split(s, ",")
	ports := make([]int, 0, len(parts))
	seen := make(map[int]bool)
	add := func(n int) {
		if n > 0 && n < 65536 && !seen[n] {
			seen[n] = true
			ports = append(ports, n)
		}
	}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			bounds := strings.SplitN(p, "-", 2)
			start, startErr := strconv.Atoi(strings.TrimSpace(bounds[0]))
			end, endErr := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if startErr != nil || endErr != nil || start > end {
				continue
			}
			for n := start; n <= end; n++ {
				add(n)
			}
			continue
		}
		n, err := strconv.Atoi(p)
		if err == nil {
			add(n)
		}
	}
	return ports
}

func statusBadge(code int) string {
	s := fmt.Sprintf("%d", code)
	switch {
	case code == 200:
		return styleGreen.Render(s)
	case code == 403 || code == 401:
		return styleRed.Render(s)
	default:
		return styleYellow.Render(s)
	}
}
