package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/bytezora/recon-x/internal/config"
	"github.com/bytezora/recon-x/internal/diff"
	"github.com/bytezora/recon-x/internal/engine"
	"github.com/bytezora/recon-x/internal/evidence"
	"github.com/bytezora/recon-x/internal/httpclient"
	"github.com/bytezora/recon-x/internal/output"
	"github.com/bytezora/recon-x/internal/report"
	"github.com/bytezora/recon-x/internal/state"
	"github.com/bytezora/recon-x/internal/vulns"
	"github.com/bytezora/recon-x/ui"
)

var version = "2.1.0"

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

func main() {
	cfg := parseFlags()

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

	fmt.Println(stylePurple.Render(banner))
	fmt.Printf("\n  %s  v%s  ·  by bytezora\n  %s\n\n",
		stylePurple.Render("recon-x"), version,
		styleMuted.Render("fast attack-surface collector · findings are indicators, not confirmed vulns · authorized targets only"))

	start := time.Now()

	m := ui.New(cfg.Target)
	prog := tea.NewProgram(m, tea.WithAltScreen())

	var res *engine.Results
	go func() {
		res = engine.New(cfg).Run(prog.Send, stateObj, stateFile, buildModuleSet(cfg.Modules))
		prog.Send(ui.DoneMsg{})
	}()

	if _, err := prog.Run(); err != nil {
		fail("TUI error: %v", err)
		os.Exit(1)
	}

	if cfg.SARIF != "" {
		if err := output.WriteSARIF(cfg.SARIF, res.Vulns, res.SQLi, res.Takeover, res.CORS, res.DefaultCreds, res.Templates); err != nil {
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

	fmt.Printf("\n  %s  Finished in %s\n\n",
		styleGreen.Render("◆"),
		styleGreen.Render(time.Since(start).Round(time.Second).String()))
}

func buildModuleSet(modules []string) map[int]bool {
	ms := make(map[int]bool)
	if len(modules) == 0 {
		for i := 0; i <= 34; i++ {
			ms[i] = true
		}
		return ms
	}
	for _, m := range modules {
		if n, ok := moduleNames[strings.TrimSpace(m)]; ok {
			ms[n] = true
		}
	}
	return ms
}

func parseFlags() engine.Config {
	target := flag.String("target", "", "Target domain  (e.g. example.com)")
	out := flag.String("output", "report.html", "HTML report output path")
	jsonOut := flag.String("json", "", "JSON output path (optional)")
	wordlist := flag.String("wordlist", "", "Custom subdomain wordlist (default: embedded)")
	dirWordlist := flag.String("dir-wordlist", "", "Custom paths wordlist for dir brute (default: embedded)")
	ports := flag.String("ports", defaultPorts, "Comma-separated ports to scan")
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
	modulesFlag := flag.String("modules", "", "Comma-separated modules to run (default: all)")
	outputDir := flag.String("output-dir", "", "Directory for output files")
	retries := flag.Int("retries", 2, "Number of HTTP retries")
	rate := flag.Int("rate", 50, "Max HTTP requests per second")
	silent := flag.Bool("silent", false, "Suppress all non-critical output")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
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
	flag.Parse()

	if *ver {
		fmt.Printf("recon-x v%s\n", version)
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
		Output:            *out,
		JSON:              *jsonOut,
		Wordlist:          *wordlist,
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
		OutputDir:         *outputDir,
		Retries:           *retries,
		Rate:              *rate,
		Silent:            *silent,
		Verbose:           *verbose,
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

	if *modulesFlag != "" {
		cfg.Modules = strings.Split(*modulesFlag, ",")
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
			if fileCfg.GithubToken != "" && *githubToken == "" {
				cfg.GitHubToken = fileCfg.GithubToken
			}
			if len(fileCfg.Modules) > 0 && *modulesFlag == "" {
				cfg.Modules = fileCfg.Modules
			}
			if len(fileCfg.Templates) > 0 {
				cfg.TemplatePaths = fileCfg.Templates
			}
			if fileCfg.Silent {
				cfg.Silent = true
			}
			if fileCfg.Verbose {
				cfg.Verbose = true
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

	if cfg.Target == "" {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			cfg.Target = strings.TrimSpace(scanner.Text())
		}
	}

	if cfg.Target == "" {
		fail("no target specified. Usage: recon-x -target <domain>")
		flag.Usage()
		os.Exit(1)
	}

	return cfg
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
	fmt.Printf("[%s] %s\n", styleGreen.Render("✓"), fmt.Sprintf(format, a...))
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[%s] %s\n", styleRed.Render("✗"), fmt.Sprintf(format, a...))
}

func parsePortList(s string) []int {
	parts := strings.Split(s, ",")
	ports := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err == nil && n > 0 && n < 65536 {
			ports = append(ports, n)
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
