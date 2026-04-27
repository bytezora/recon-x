package main

import (
"flag"
"fmt"
"os"
"strconv"
"strings"
"time"

tea "github.com/charmbracelet/bubbletea"
"github.com/charmbracelet/lipgloss"

"github.com/bytezora/recon-x/internal/config"
"github.com/bytezora/recon-x/internal/engine"
"github.com/bytezora/recon-x/internal/httpclient"
"github.com/bytezora/recon-x/internal/output"
"github.com/bytezora/recon-x/internal/report"
"github.com/bytezora/recon-x/internal/state"
"github.com/bytezora/recon-x/internal/vulns"
"github.com/bytezora/recon-x/ui"
)

const (
version      = "2.0.0"
defaultPorts = "21,22,25,53,80,110,143,443,445,3306,5432,6379,8080,8443,8888,9000,27017"
)

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
fmt.Printf("\n  %s  v%s  ·  by bytezora  ·  for authorized testing only\n\n",
stylePurple.Render("recon-x"), version)

start := time.Now()

m    := ui.New(cfg.Target)
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
res.Vulns, res.WAFs, res.Dirs, res.JS, res.GH, res.Buckets,
res.TLS, res.Redirects, res.AXFR, res.WHOIS, res.Screenshots,
res.Takeover, res.CORS, res.Bypass, res.VHosts,
res.Favicons, res.ASN, res.GraphQL, res.EmailSec,
res.AdminPanel, res.SQLi, res.DefaultCreds, res.RateLimit, res.Templates, cfg.Output); err != nil {
fail("report error: %v", err)
os.Exit(1)
}
success("HTML report → %s", styleYellow.Render(cfg.Output))

if cfg.JSON != "" {
if err := output.WriteJSON(cfg.JSON, cfg.Target, res.Subs, res.Ports, res.HTTP,
res.Vulns, res.WAFs, res.Dirs, res.JS, res.GH, res.Buckets,
res.TLS, res.Redirects, res.AXFR, res.WHOIS, res.Screenshots,
res.Takeover, res.CORS, res.Bypass, res.VHosts,
res.Favicons, res.ASN, res.GraphQL, res.EmailSec,
res.AdminPanel, res.SQLi, res.DefaultCreds, res.RateLimit, res.Templates); err != nil {
fail("JSON error: %v", err)
} else {
success("JSON output → %s", styleYellow.Render(cfg.JSON))
}
}

fmt.Printf("\n  %s  Finished in %s\n\n",
styleGreen.Render("◆"),
styleGreen.Render(time.Since(start).Round(time.Second).String()))
}

func buildModuleSet(modules []string) map[int]bool {
ms := make(map[int]bool)
if len(modules) == 0 {
for i := 0; i <= 25; i++ {
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
target         := flag.String("target",          "",            "Target domain  (e.g. example.com)")
out            := flag.String("output",          "report.html", "HTML report output path")
jsonOut        := flag.String("json",            "",            "JSON output path (optional)")
wordlist       := flag.String("wordlist",        "",            "Custom subdomain wordlist (default: embedded)")
dirWordlist    := flag.String("dir-wordlist",    "",            "Custom paths wordlist for dir brute (default: embedded)")
ports          := flag.String("ports",           defaultPorts,  "Comma-separated ports to scan")
threads        := flag.Int("threads",            50,            "Number of concurrent goroutines")
noPassive      := flag.Bool("no-passive",        false,         "Skip crt.sh passive recon")
githubToken    := flag.String("github-token",    "",            "GitHub personal access token for dorking (optional)")
proxy          := flag.String("proxy",           "",            "HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080)")
scopeFile      := flag.String("scope-file",      "",            "Path to scope file (one entry per line: *.example.com, 10.0.0.0/8)")
sarifOut       := flag.String("sarif",           "",            "SARIF output path for CI/CD integration (optional)")
notifySlack    := flag.String("notify-slack",    "",            "Slack incoming webhook URL for critical finding alerts")
notifyTelegram := flag.String("notify-telegram", "",            "Telegram bot TOKEN@CHATID for critical alerts")
resume         := flag.Bool("resume",            false,         "Resume interrupted scan from state file")
configFile     := flag.String("config",          "",            "Path to YAML config file")
modulesFlag    := flag.String("modules",         "",            "Comma-separated modules to run (default: all)")
outputDir      := flag.String("output-dir",      "",            "Directory for output files")
retries        := flag.Int("retries",            2,             "Number of HTTP retries")
rate           := flag.Int("rate",               50,            "Max HTTP requests per second")
silent         := flag.Bool("silent",            false,         "Suppress all non-critical output")
verbose        := flag.Bool("verbose",           false,         "Enable verbose output")
ver            := flag.Bool("version",           false,         "Print version and exit")
dbHash         := flag.Bool("db-hash",           false,         "Print CVE database fingerprint and exit (for stamping integrity.go)")
resolver       := flag.String("resolver",        "",            "Custom DNS resolver address (e.g. 1.1.1.1:53)")
flag.Parse()

if *ver {
fmt.Printf("recon-x v%s\n", version)
os.Exit(0)
}

if *dbHash {
fmt.Println(vulns.ComputeDBHash())
os.Exit(0)
}

cfg := engine.Config{
Target:         *target,
Output:         *out,
JSON:           *jsonOut,
Wordlist:       *wordlist,
DirWordlist:    *dirWordlist,
Ports:          *ports,
Threads:        *threads,
NoPassive:      *noPassive,
GitHubToken:    *githubToken,
Proxy:          *proxy,
ScopeFile:      *scopeFile,
SARIF:          *sarifOut,
NotifySlack:    *notifySlack,
NotifyTelegram: *notifyTelegram,
Resume:         *resume,
ConfigFile:     *configFile,
OutputDir:      *outputDir,
Retries:        *retries,
Rate:           *rate,
Silent:         *silent,
Verbose:        *verbose,
Resolver:       *resolver,
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
}
}

if cfg.OutputDir != "" {
if err := os.MkdirAll(cfg.OutputDir, 0755); err == nil {
if cfg.Output == "report.html" {
cfg.Output = cfg.OutputDir + "/report.html"
}
if cfg.JSON != "" {
cfg.JSON = cfg.OutputDir + "/report.json"
}
if cfg.SARIF != "" {
cfg.SARIF = cfg.OutputDir + "/report.sarif"
}
}
}

if cfg.Target == "" {
fail("no target specified. Usage: recon-x -target <domain>")
flag.Usage()
os.Exit(1)
}

return cfg
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