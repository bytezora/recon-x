// recon-x — all-in-one web reconnaissance tool
// https://github.com/bytezora/recon-x
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

	"github.com/bytezora/recon-x/internal/crtsh"
	"github.com/bytezora/recon-x/internal/dirbust"
	"github.com/bytezora/recon-x/internal/httpcheck"
	"github.com/bytezora/recon-x/internal/jsscan"
	"github.com/bytezora/recon-x/internal/output"
	"github.com/bytezora/recon-x/internal/portscan"
	"github.com/bytezora/recon-x/internal/report"
	"github.com/bytezora/recon-x/internal/subdomain"
	"github.com/bytezora/recon-x/internal/vulns"
	"github.com/bytezora/recon-x/internal/waf"
	"github.com/bytezora/recon-x/ui"
)

const (
	version      = "1.2.1"
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

// ── Config ────────────────────────────────────────────────────────────────────

type Config struct {
	Target      string
	Output      string
	JSON        string
	Wordlist    string
	DirWordlist string
	Ports       string
	Threads     int
	NoPassive   bool
}

// ── Entry point ───────────────────────────────────────────────────────────────

func main() {
	cfg := parseFlags()

	fmt.Println(stylePurple.Render(banner))
	fmt.Printf("\n  %s  v%s  ·  by bytezora  ·  for authorized testing only\n\n",
		stylePurple.Render("recon-x"), version)

	start := time.Now()

	m    := ui.New(cfg.Target)
	prog := tea.NewProgram(m, tea.WithAltScreen())

	var (
		finalSubs   []subdomain.Result
		finalPorts  []portscan.Result
		finalHTTP   []httpcheck.Result
		finalVulns  []vulns.Match
		finalWAFs   []waf.Result
		finalDirs   []dirbust.Hit
		finalJS     []jsscan.Finding
	)

	go func() {
		runScans(cfg, prog,
			&finalSubs, &finalPorts, &finalHTTP,
			&finalVulns, &finalWAFs, &finalDirs, &finalJS,
		)
		prog.Send(ui.DoneMsg{})
	}()

	if _, err := prog.Run(); err != nil {
		fail("TUI error: %v", err)
		os.Exit(1)
	}

	// ── Post-scan output ───────────────────────────────────────────────────
	if err := report.Generate(cfg.Target, finalSubs, finalPorts, finalHTTP,
		finalVulns, finalWAFs, finalDirs, finalJS, cfg.Output); err != nil {
		fail("report error: %v", err)
		os.Exit(1)
	}
	success("HTML report → %s", styleYellow.Render(cfg.Output))

	if cfg.JSON != "" {
		if err := output.WriteJSON(cfg.JSON, cfg.Target, finalSubs, finalPorts, finalHTTP,
			finalVulns, finalWAFs, finalDirs, finalJS); err != nil {
			fail("JSON error: %v", err)
		} else {
			success("JSON output → %s", styleYellow.Render(cfg.JSON))
		}
	}

	fmt.Printf("\n  %s  Finished in %s\n\n",
		styleGreen.Render("◆"),
		styleGreen.Render(time.Since(start).Round(time.Second).String()))
}

// ── Scan pipeline ─────────────────────────────────────────────────────────────

func runScans(
	cfg   Config,
	prog  *tea.Program,
	subs  *[]subdomain.Result,
	ports *[]portscan.Result,
	http  *[]httpcheck.Result,
	vs    *[]vulns.Match,
	wafs  *[]waf.Result,
	dirs  *[]dirbust.Hit,
	jsf   *[]jsscan.Finding,
) {
	// Step 0: Passive recon via crt.sh
	prog.Send(ui.StepStartMsg(0))
	var passiveNames []string
	if !cfg.NoPassive {
		names, err := crtsh.Lookup(cfg.Target)
		if err == nil {
			passiveNames = names
		}
	}
	prog.Send(ui.StepDoneMsg{Step: 0, Count: len(passiveNames)})

	// Step 1: DNS brute-force
	prog.Send(ui.StepStartMsg(1))
	*subs = subdomain.Enumerate(cfg.Target, cfg.Threads, cfg.Wordlist, func(r subdomain.Result) {
		prog.Send(ui.ItemMsg{
			Icon: styleGreen.Render("↳"),
			Text: styleMuted.Render(r.Subdomain) + "  " + styleMuted.Render(strings.Join(r.IPs, ", ")),
		})
	})
	*subs = subdomain.AddPassive(*subs, passiveNames, func(r subdomain.Result) {
		prog.Send(ui.ItemMsg{
			Icon: stylePurple.Render("↳"),
			Text: styleMuted.Render("[crt.sh] " + r.Subdomain),
		})
	})
	prog.Send(ui.StepDoneMsg{Step: 1, Count: len(*subs)})

	// Step 2: Port scan + vuln matching
	prog.Send(ui.StepStartMsg(2))
	portList := parsePortList(cfg.Ports)
	*ports = portscan.Scan(*subs, portList, cfg.Threads, func(r portscan.Result) {
		bannerText := ""
		if r.Banner != "" {
			bannerText = "  " + styleMuted.Render(r.Banner)
		}
		prog.Send(ui.ItemMsg{
			Icon: styleYellow.Render("⬡"),
			Text: fmt.Sprintf("%s:%s%s",
				styleMuted.Render(r.Host),
				styleGreen.Render(fmt.Sprintf("%d", r.Port)),
				bannerText,
			),
		})
	})
	// CVE matching on banners
	for _, p := range *ports {
		if p.Banner == "" {
			continue
		}
		if matches := vulns.CheckBanner(p.Host, p.Port, p.Banner); len(matches) > 0 {
			*vs = append(*vs, matches...)
			for _, m := range matches {
				prog.Send(ui.ItemMsg{
					Icon: styleRed.Render("⚠"),
					Text: styleRed.Render(m.CVE) + "  " + styleMuted.Render(m.Description),
				})
			}
		}
	}
	prog.Send(ui.StepDoneMsg{Step: 2, Count: len(*ports)})

	// Step 3: HTTP fingerprint + WAF detection
	prog.Send(ui.StepStartMsg(3))
	*http = httpcheck.Check(*ports, cfg.Threads)
	for _, h := range *http {
		if detected := waf.Detect(h.Host, h.URL, h.Headers, h.Body); len(detected) > 0 {
			*wafs = append(*wafs, detected...)
			for _, r := range detected {
				prog.Send(ui.ItemMsg{
					Icon: styleYellow.Render("🛡"),
					Text: styleMuted.Render(h.Host) + "  " + styleYellow.Render(r.WAF),
				})
			}
		}
		// CVE detection from HTTP Server / X-Powered-By headers
		if matches := vulns.CheckHTTPFull(h.Host, h.Port, h.Headers, h.Body); len(matches) > 0 {
			*vs = append(*vs, matches...)
			for _, m := range matches {
				prog.Send(ui.ItemMsg{
					Icon: styleRed.Render("⚠"),
					Text: styleRed.Render(m.CVE) + "  " + styleMuted.Render(m.Description),
				})
			}
		}
		// Probe version disclosure endpoints (Spring actuator, GitLab API, Solr admin, etc.)
		{
			scheme := "http"
			if h.Port == 443 || h.Port == 8443 {
				scheme = "https"
			}
			if probeMatches := vulns.ProbeVersionEndpoints(scheme, h.Host, h.Port); len(probeMatches) > 0 {
				*vs = append(*vs, probeMatches...)
				for _, m := range probeMatches {
					prog.Send(ui.ItemMsg{
						Icon: styleRed.Render("⚠"),
						Text: styleRed.Render(m.CVE) + "  " + styleMuted.Render(m.Description),
					})
				}
			}
		}
	}
	prog.Send(ui.StepDoneMsg{Step: 3, Count: len(*http)})

	// Step 4: Directory brute-force
	prog.Send(ui.StepStartMsg(4))
	baseURLs := make([]string, 0, len(*http))
	for _, h := range *http {
		baseURLs = append(baseURLs, h.URL)
	}
	*dirs = dirbust.Bust(baseURLs, cfg.DirWordlist, cfg.Threads, func(h dirbust.Hit) {
		prog.Send(ui.ItemMsg{
			Icon: stylePurple.Render("📁"),
			Text: fmt.Sprintf("%s  %s",
				styleMuted.Render(h.Path),
				statusBadge(h.StatusCode),
			),
		})
	})
	prog.Send(ui.StepDoneMsg{Step: 4, Count: len(*dirs)})

	// Step 5: JS scraping
	prog.Send(ui.StepStartMsg(5))
	pages := make(map[string]string, len(*http))
	for _, h := range *http {
		if h.Body != "" {
			pages[h.URL] = h.Body
		}
	}
	*jsf = jsscan.Scan(pages, cfg.Threads, func(f jsscan.Finding) {
		icon := styleGreen.Render("⚙")
		if f.Kind == "secret" {
			icon = styleRed.Render("🔑")
		}
		prog.Send(ui.ItemMsg{
			Icon: icon,
			Text: styleMuted.Render("["+f.Label+"]") + "  " + f.Value,
		})
	})
	prog.Send(ui.StepDoneMsg{Step: 5, Count: len(*jsf)})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func parseFlags() Config {
	target      := flag.String("target",       "",            "Target domain  (e.g. example.com)")
	out         := flag.String("output",       "report.html", "HTML report output path")
	jsonOut     := flag.String("json",         "",            "JSON output path (optional)")
	wordlist    := flag.String("wordlist",     "",            "Custom subdomain wordlist (default: embedded)")
	dirWordlist := flag.String("dir-wordlist", "",            "Custom paths wordlist for dir brute (default: embedded)")
	ports       := flag.String("ports",        defaultPorts,  "Comma-separated ports to scan")
	threads     := flag.Int("threads",         50,            "Number of concurrent goroutines")
	noPassive   := flag.Bool("no-passive",     false,         "Skip crt.sh passive recon")
	ver         := flag.Bool("version",        false,         "Print version and exit")
	dbHash      := flag.Bool("db-hash",        false,         "Print CVE database fingerprint and exit (for stamping integrity.go)")
	flag.Parse()

	if *ver {
		fmt.Printf("recon-x v%s\n", version)
		os.Exit(0)
	}

	if *dbHash {
		fmt.Println(vulns.ComputeDBHash())
		os.Exit(0)
	}

	if *target == "" {
		fail("no target specified. Usage: recon-x -target <domain>")
		flag.Usage()
		os.Exit(1)
	}

	return Config{
		Target:      *target,
		Output:      *out,
		JSON:        *jsonOut,
		Wordlist:    *wordlist,
		DirWordlist: *dirWordlist,
		Ports:       *ports,
		Threads:     *threads,
		NoPassive:   *noPassive,
	}
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
