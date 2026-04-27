package engine

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/bytezora/recon-x/internal/adminpanel"
	"github.com/bytezora/recon-x/internal/asn"
	"github.com/bytezora/recon-x/internal/axfr"
	"github.com/bytezora/recon-x/internal/buckets"
	"github.com/bytezora/recon-x/internal/bypass"
	"github.com/bytezora/recon-x/internal/cors"
	"github.com/bytezora/recon-x/internal/crtsh"
	"github.com/bytezora/recon-x/internal/defaultcreds"
	"github.com/bytezora/recon-x/internal/dirbust"
	"github.com/bytezora/recon-x/internal/emailsec"
	"github.com/bytezora/recon-x/internal/favicon"
	"github.com/bytezora/recon-x/internal/ghsearch"
	"github.com/bytezora/recon-x/internal/graphql"
	"github.com/bytezora/recon-x/internal/httpcheck"
	"github.com/bytezora/recon-x/internal/jsscan"
	"github.com/bytezora/recon-x/internal/notify"
	"github.com/bytezora/recon-x/internal/openredirect"
	"github.com/bytezora/recon-x/internal/portscan"
	"github.com/bytezora/recon-x/internal/ratelimit"
	"github.com/bytezora/recon-x/internal/scope"
	"github.com/bytezora/recon-x/internal/screenshot"
	"github.com/bytezora/recon-x/internal/sqli"
	"github.com/bytezora/recon-x/internal/state"
	"github.com/bytezora/recon-x/internal/subdomain"
	"github.com/bytezora/recon-x/internal/takeover"
	"github.com/bytezora/recon-x/internal/templates"
	"github.com/bytezora/recon-x/internal/tlscheck"
	"github.com/bytezora/recon-x/internal/vhost"
	"github.com/bytezora/recon-x/internal/vulns"
	"github.com/bytezora/recon-x/internal/waf"
	"github.com/bytezora/recon-x/internal/whois"
	"github.com/bytezora/recon-x/ui"
)

var (
	stylePurple = lipgloss.NewStyle().Foreground(lipgloss.Color("#7C3AED")).Bold(true)
	styleGreen  = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF87")).Bold(true)
	styleYellow = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFA502"))
	styleMuted  = lipgloss.NewStyle().Foreground(lipgloss.Color("#8B949E"))
	styleRed    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4757"))
)

type Config struct {
	Target         string
	Output         string
	JSON           string
	Wordlist       string
	DirWordlist    string
	Ports          string
	Threads        int
	NoPassive      bool
	GitHubToken    string
	Proxy          string
	ScopeFile      string
	SARIF          string
	NotifySlack    string
	NotifyTelegram string
	Resume         bool
	ConfigFile     string
	Modules        []string
	OutputDir      string
	Retries        int
	Rate           int
	Silent         bool
	Verbose        bool
	TemplatePaths  []string
	Resolver       string
}

type Results struct {
	Subs         []subdomain.Result
	Ports        []portscan.Result
	HTTP         []httpcheck.Result
	Vulns        []vulns.Match
	WAFs         []waf.Result
	Dirs         []dirbust.Hit
	JS           []jsscan.Finding
	GH           []ghsearch.Finding
	Buckets      []buckets.Result
	TLS          []tlscheck.Result
	Redirects    []openredirect.Result
	AXFR         []axfr.Result
	WHOIS        *whois.Result
	Screenshots  []screenshot.Result
	Takeover     []takeover.Result
	CORS         []cors.Result
	Bypass       []bypass.Result
	VHosts       []vhost.Result
	Favicons     []favicon.Result
	ASN          []asn.Result
	GraphQL      []graphql.Result
	EmailSec     *emailsec.Result
	AdminPanel   []adminpanel.Result
	SQLi         []sqli.Result
	DefaultCreds []defaultcreds.Result
	RateLimit    []ratelimit.Result
	Templates    []templates.Match
}

type Engine struct {
	cfg Config
}

func New(cfg Config) *Engine {
	return &Engine{cfg: cfg}
}

func (e *Engine) Run(send func(tea.Msg), stateObj *state.State, stateFile string, ms map[int]bool) *Results {
	_ = ms

	res := &Results{}

	ntfyCfg := notify.Config{SlackWebhook: e.cfg.NotifySlack}
	if e.cfg.NotifyTelegram != "" {
		parts := strings.SplitN(e.cfg.NotifyTelegram, "@", 2)
		if len(parts) == 2 {
			ntfyCfg.TelegramToken = parts[0]
			ntfyCfg.TelegramChatID = parts[1]
		}
	}

	send(ui.StepStartMsg(0))
	var passiveNames []string
	if !stateObj.Done(0) {
		if !e.cfg.NoPassive {
			names, err := crtsh.Lookup(e.cfg.Target)
			if err == nil {
				passiveNames = names
			}
		}
		stateObj.Mark(0)
		state.Save(stateFile, stateObj)
	}
	send(ui.StepDoneMsg{Step: 0, Count: len(passiveNames)})

	send(ui.StepStartMsg(1))
	if !stateObj.Done(1) {
		res.Subs = subdomain.Enumerate(e.cfg.Target, e.cfg.Threads, e.cfg.Wordlist, e.cfg.Resolver, func(r subdomain.Result) {
			send(ui.ItemMsg{
				Icon: styleGreen.Render("↳"),
				Text: styleMuted.Render(r.Subdomain) + "  " + styleMuted.Render(strings.Join(r.IPs, ", ")),
			})
		})
		res.Subs = subdomain.AddPassive(res.Subs, passiveNames, e.cfg.Resolver, func(r subdomain.Result) {
			send(ui.ItemMsg{
				Icon: stylePurple.Render("↳"),
				Text: styleMuted.Render("[crt.sh] " + r.Subdomain),
			})
		})
		if e.cfg.ScopeFile != "" {
			sc, err := scope.Load(e.cfg.ScopeFile)
			if err == nil {
				filtered := res.Subs[:0]
				for _, s := range res.Subs {
					if sc.InScope(s.Subdomain) {
						filtered = append(filtered, s)
					}
				}
				res.Subs = filtered
			}
		}
		stateObj.Mark(1)
		state.Save(stateFile, stateObj)
	}
	send(ui.StepDoneMsg{Step: 1, Count: len(res.Subs)})

	send(ui.StepStartMsg(2))
	if !stateObj.Done(2) {
		portList := parsePortList(e.cfg.Ports)
		res.Ports = portscan.Scan(res.Subs, portList, e.cfg.Threads, func(r portscan.Result) {
			bannerText := ""
			if r.Banner != "" {
				bannerText = "  " + styleMuted.Render(r.Banner)
			}
			send(ui.ItemMsg{
				Icon: styleYellow.Render("⬡"),
				Text: fmt.Sprintf("%s:%s%s",
					styleMuted.Render(r.Host),
					styleGreen.Render(fmt.Sprintf("%d", r.Port)),
					bannerText,
				),
			})
		})
		stateObj.Mark(2)
		state.Save(stateFile, stateObj)
	}
	send(ui.StepDoneMsg{Step: 2, Count: len(res.Ports)})

	send(ui.StepStartMsg(3))
	if !stateObj.Done(3) {
		res.HTTP = httpcheck.Check(res.Ports, e.cfg.Threads)
		seenCVE := make(map[string]bool)
		addVuln := func(matches []vulns.Match) {
			for _, m := range matches {
				key := m.Host + ":" + fmt.Sprintf("%d", m.Port) + ":" + m.CVE
				if seenCVE[key] {
					continue
				}
				seenCVE[key] = true
				res.Vulns = append(res.Vulns, m)
				send(ui.ItemMsg{
					Icon: styleRed.Render("⚠"),
					Text: styleRed.Render(m.CVE) + "  " + styleMuted.Render(m.Description),
				})
			}
		}
		for _, p := range res.Ports {
			if p.Banner != "" {
				addVuln(vulns.CheckBanner(p.Host, p.Port, p.Banner))
			}
		}
		for _, h := range res.HTTP {
			if detected := waf.Detect(h.Host, h.URL, h.Headers, h.Body); len(detected) > 0 {
				res.WAFs = append(res.WAFs, detected...)
				for _, r := range detected {
					send(ui.ItemMsg{
						Icon: styleYellow.Render("🛡"),
						Text: styleMuted.Render(h.Host) + "  " + styleYellow.Render(r.WAF),
					})
				}
			}
			addVuln(vulns.CheckHTTPFull(h.Host, h.Port, h.Headers, h.Body))
			scheme := strings.SplitN(h.URL, "://", 2)[0]
			addVuln(vulns.ProbeVersionEndpoints(scheme, h.Host, h.Port))
		}
		stateObj.Mark(3)
		state.Save(stateFile, stateObj)
	}
	if ntfyCfg.Enabled() {
		for _, v := range res.Vulns {
			if v.Severity == "CRITICAL" || v.Severity == "HIGH" {
				ntfyCfg.Send("🚨 CVE Found — "+e.cfg.Target, fmt.Sprintf("%s (CVSS %.1f) on %s:%d\n%s", v.CVE, v.CVSS, v.Host, v.Port, v.Description))
				break
			}
		}
	}
	send(ui.StepDoneMsg{Step: 3, Count: len(res.HTTP)})

	baseURLs := make([]string, 0, len(res.HTTP))
	for _, h := range res.HTTP {
		baseURLs = append(baseURLs, h.URL)
	}

	send(ui.StepStartMsg(4))
	if !stateObj.Done(4) {
		res.Dirs = dirbust.Bust(baseURLs, e.cfg.DirWordlist, e.cfg.Threads, func(h dirbust.Hit) {
			send(ui.ItemMsg{
				Icon: stylePurple.Render("📁"),
				Text: fmt.Sprintf("%s  %s",
					styleMuted.Render(h.Path),
					statusBadge(h.StatusCode),
				),
			})
		})
		stateObj.Mark(4)
		state.Save(stateFile, stateObj)
	}
	send(ui.StepDoneMsg{Step: 4, Count: len(res.Dirs)})

	send(ui.StepStartMsg(5))
	if !stateObj.Done(5) {
		pages := make(map[string]string, len(res.HTTP))
		for _, h := range res.HTTP {
			if h.Body != "" {
				pages[h.URL] = h.Body
			}
		}
		res.JS = jsscan.Scan(pages, e.cfg.Threads, func(f jsscan.Finding) {
			icon := styleGreen.Render("⚙")
			if f.Kind == "secret" {
				icon = styleRed.Render("🔑")
			}
			send(ui.ItemMsg{
				Icon: icon,
				Text: styleMuted.Render("["+f.Label+"]") + "  " + f.Value,
			})
		})
		stateObj.Mark(5)
		state.Save(stateFile, stateObj)
	}
	send(ui.StepDoneMsg{Step: 5, Count: len(res.JS)})

	send(ui.StepStartMsg(6))
	if !stateObj.Done(6) {
		res.GH = ghsearch.Search(e.cfg.Target, e.cfg.GitHubToken, func(f ghsearch.Finding) {
			send(ui.ItemMsg{
				Icon: styleYellow.Render("⚑"),
				Text: styleMuted.Render(f.Repo) + "  " + styleYellow.Render(f.Keyword) + "  " + styleMuted.Render(f.Path),
			})
		})
		stateObj.Mark(6)
		state.Save(stateFile, stateObj)
	}
	send(ui.StepDoneMsg{Step: 6, Count: len(res.GH)})

	send(ui.StepStartMsg(7))
	if !stateObj.Done(7) {
		res.Buckets = buckets.Enum(e.cfg.Target, e.cfg.Threads, func(r buckets.Result) {
			icon := styleMuted.Render("▣")
			if r.Status == "public" {
				icon = styleRed.Render("▣")
			}
			send(ui.ItemMsg{
				Icon: icon,
				Text: styleYellow.Render(r.Provider) + "  " + styleMuted.Render(r.Bucket) + "  " + styleGreen.Render(r.Status),
			})
		})
		stateObj.Mark(7)
		state.Save(stateFile, stateObj)
	}
	send(ui.StepDoneMsg{Step: 7, Count: len(res.Buckets)})

	send(ui.StepStartMsg(8))
	if !stateObj.Done(8) {
		var tlsTargets []tlscheck.Target
		seenTLS := make(map[string]bool)
		for _, h := range res.HTTP {
			if h.Port == 443 || h.Port == 8443 || h.Port == 4443 || h.Port == 7443 {
				key := fmt.Sprintf("%s:%d", h.Host, h.Port)
				if !seenTLS[key] {
					seenTLS[key] = true
					tlsTargets = append(tlsTargets, tlscheck.Target{Host: h.Host, Port: h.Port})
				}
			}
		}
		res.TLS = tlscheck.Check(tlsTargets, e.cfg.Threads, func(r tlscheck.Result) {
			icon := styleGreen.Render("🔒")
			if len(r.Issues) > 0 {
				icon = styleRed.Render("🔓")
			}
			send(ui.ItemMsg{
				Icon: icon,
				Text: styleMuted.Render(fmt.Sprintf("%s:%d", r.Host, r.Port)) + "  " +
					styleYellow.Render(r.Proto) + "  " +
					styleMuted.Render(r.Expiry),
			})
		})
		stateObj.Mark(8)
		state.Save(stateFile, stateObj)
	}
	send(ui.StepDoneMsg{Step: 8, Count: len(res.TLS)})

	send(ui.StepStartMsg(9))
	if !stateObj.Done(9) {
		res.Redirects = openredirect.Check(baseURLs, e.cfg.Threads, func(r openredirect.Result) {
			send(ui.ItemMsg{
				Icon: styleRed.Render("↪"),
				Text: styleMuted.Render(r.BaseURL) + "  " + styleYellow.Render("?"+r.Param) + "  " + styleMuted.Render(r.Location),
			})
		})
		stateObj.Mark(9)
		state.Save(stateFile, stateObj)
	}
	send(ui.StepDoneMsg{Step: 9, Count: len(res.Redirects)})

	send(ui.StepStartMsg(10))
	var axfrTotal int
	if !stateObj.Done(10) {
		res.AXFR = axfr.Transfer(e.cfg.Target)
		for _, r := range res.AXFR {
			if r.Success {
				axfrTotal += len(r.Records)
				send(ui.ItemMsg{
					Icon: styleRed.Render("⚠"),
					Text: styleRed.Render("AXFR success") + "  " + styleMuted.Render(r.NS) + "  " +
						styleMuted.Render(fmt.Sprintf("%d records", len(r.Records))),
				})
			}
		}
		stateObj.Mark(10)
		state.Save(stateFile, stateObj)
	}
	send(ui.StepDoneMsg{Step: 10, Count: axfrTotal})

	send(ui.StepStartMsg(11))
	if !stateObj.Done(11) {
		if w, err := whois.Lookup(e.cfg.Target); err == nil {
			res.WHOIS = w
			send(ui.ItemMsg{
				Icon: stylePurple.Render("◈"),
				Text: styleMuted.Render(w.Registrar) + "  " + styleYellow.Render(w.Country),
			})
		}
		stateObj.Mark(11)
		state.Save(stateFile, stateObj)
	}
	send(ui.StepDoneMsg{Step: 11, Count: func() int {
		if res.WHOIS != nil {
			return 1
		}
		return 0
	}()})

	send(ui.StepStartMsg(12))
	if !stateObj.Done(12) {
		res.Screenshots = screenshot.Capture(baseURLs, e.cfg.Threads, func(r screenshot.Result) {
			send(ui.ItemMsg{
				Icon: styleGreen.Render("📷"),
				Text: styleMuted.Render(r.URL),
			})
		})
		stateObj.Mark(12)
		state.Save(stateFile, stateObj)
	}
	send(ui.StepDoneMsg{Step: 12, Count: len(res.Screenshots)})

	send(ui.StepStartMsg(13))
	if !stateObj.Done(13) {
		var subList []string
		for _, s := range res.Subs {
			subList = append(subList, s.Subdomain)
		}
		res.Takeover = takeover.Check(subList, e.cfg.Threads, func(r takeover.Result) {
			if r.Vulnerable {
				send(ui.ItemMsg{
					Icon: styleRed.Render("⚠"),
					Text: styleRed.Render(r.Subdomain) + "  " + styleMuted.Render(r.CNAME) + "  " + styleYellow.Render(r.Service),
				})
			}
		})
		stateObj.Mark(13)
		state.Save(stateFile, stateObj)
	}
	if ntfyCfg.Enabled() {
		for _, t := range res.Takeover {
			if t.Vulnerable {
				ntfyCfg.Send("🚨 Subdomain Takeover — "+e.cfg.Target, fmt.Sprintf("%s → %s (%s)", t.Subdomain, t.CNAME, t.Service))
			}
		}
	}
	send(ui.StepDoneMsg{Step: 13, Count: func() int {
		n := 0
		for _, r := range res.Takeover {
			if r.Vulnerable {
				n++
			}
		}
		return n
	}()})

	send(ui.StepStartMsg(14))
	if !stateObj.Done(14) {
		res.CORS = cors.Scan(baseURLs, e.cfg.Threads, func(r cors.Result) {
			send(ui.ItemMsg{
				Icon: styleYellow.Render("↺"),
				Text: styleMuted.Render(r.URL) + "  " + styleYellow.Render(r.Origin),
			})
		})
		stateObj.Mark(14)
		state.Save(stateFile, stateObj)
	}
	send(ui.StepDoneMsg{Step: 14, Count: len(res.CORS)})

	send(ui.StepStartMsg(15))
	if !stateObj.Done(15) {
		var forbiddenURLs []string
		for _, d := range res.Dirs {
			if d.StatusCode == 403 {
				forbiddenURLs = append(forbiddenURLs, d.URL)
			}
		}
		res.Bypass = bypass.Check(forbiddenURLs, e.cfg.Threads, func(r bypass.Result) {
			if r.Bypassed {
				send(ui.ItemMsg{
					Icon: styleGreen.Render("✓"),
					Text: styleMuted.Render(r.URL) + "  " + styleYellow.Render(r.Technique),
				})
			}
		})
		stateObj.Mark(15)
		state.Save(stateFile, stateObj)
	}
	send(ui.StepDoneMsg{Step: 15, Count: func() int {
		n := 0
		for _, r := range res.Bypass {
			if r.Bypassed {
				n++
			}
		}
		return n
	}()})

	send(ui.StepStartMsg(16))
	if !stateObj.Done(16) {
		res.VHosts = vhost.Discover(res.HTTP, e.cfg.Threads, func(r vhost.Result) {
			send(ui.ItemMsg{
				Icon: stylePurple.Render("◈"),
				Text: styleMuted.Render(r.IP) + "  " + styleYellow.Render(r.VHost) + "  " + styleMuted.Render(fmt.Sprintf("%d", r.Status)),
			})
		})
		stateObj.Mark(16)
		state.Save(stateFile, stateObj)
	}
	send(ui.StepDoneMsg{Step: 16, Count: len(res.VHosts)})

	send(ui.StepStartMsg(17))
	if !stateObj.Done(17) {
		res.Favicons = favicon.Scan(baseURLs, e.cfg.Threads, func(r favicon.Result) {
			send(ui.ItemMsg{
				Icon: styleMuted.Render("⬡"),
				Text: styleMuted.Render(r.URL) + "  " + styleYellow.Render(fmt.Sprintf("%d", r.Hash)),
			})
		})
		stateObj.Mark(17)
		state.Save(stateFile, stateObj)
	}
	send(ui.StepDoneMsg{Step: 17, Count: len(res.Favicons)})

	send(ui.StepStartMsg(18))
	if !stateObj.Done(18) {
		seenIP := map[string]bool{}
		var ips []string
		for _, p := range res.Ports {
			if !seenIP[p.IP] && p.IP != "" {
				seenIP[p.IP] = true
				ips = append(ips, p.IP)
			}
		}
		res.ASN = asn.Lookup(ips, e.cfg.Threads, func(r asn.Result) {
			send(ui.ItemMsg{
				Icon: styleMuted.Render("◈"),
				Text: styleMuted.Render(r.IP) + "  " + styleYellow.Render(r.ASN) + "  " + styleMuted.Render(r.Org),
			})
		})
		stateObj.Mark(18)
		state.Save(stateFile, stateObj)
	}
	send(ui.StepDoneMsg{Step: 18, Count: len(res.ASN)})

	send(ui.StepStartMsg(19))
	if !stateObj.Done(19) {
		res.GraphQL = graphql.Probe(baseURLs, e.cfg.Threads, func(r graphql.Result) {
			send(ui.ItemMsg{
				Icon: styleGreen.Render("⬡"),
				Text: styleMuted.Render(r.Endpoint) + "  " + styleYellow.Render(fmt.Sprintf("introspection:%v", r.Introspection)),
			})
		})
		stateObj.Mark(19)
		state.Save(stateFile, stateObj)
	}
	send(ui.StepDoneMsg{Step: 19, Count: len(res.GraphQL)})

	send(ui.StepStartMsg(20))
	if !stateObj.Done(20) {
		if esResult, err := emailsec.Check(e.cfg.Target); err == nil {
			res.EmailSec = esResult
			spoofable := ""
			if esResult.Spoofable {
				spoofable = " ⚠ SPOOFABLE"
			}
			send(ui.ItemMsg{
				Icon: stylePurple.Render("✉"),
				Text: styleMuted.Render(e.cfg.Target) + styleRed.Render(spoofable),
			})
		}
		stateObj.Mark(20)
		state.Save(stateFile, stateObj)
	}
	send(ui.StepDoneMsg{Step: 20, Count: func() int {
		if res.EmailSec != nil {
			return 1
		}
		return 0
	}()})

	send(ui.StepStartMsg(21))
	if !stateObj.Done(21) {
		res.AdminPanel = adminpanel.Discover(res.HTTP, e.cfg.Threads, func(r adminpanel.Result) {
			send(ui.ItemMsg{
				Icon: stylePurple.Render("🔍"),
				Text: styleMuted.Render(r.URL) + styleYellow.Render(r.Path),
			})
		})
		stateObj.Mark(21)
		state.Save(stateFile, stateObj)
	}
	send(ui.StepDoneMsg{Step: 21, Count: len(res.AdminPanel)})

	send(ui.StepStartMsg(22))
	if !stateObj.Done(22) {
		httpURLs := make([]string, 0, len(res.HTTP))
		for _, h := range res.HTTP {
			httpURLs = append(httpURLs, h.URL)
		}
		res.SQLi = sqli.Detect(httpURLs, e.cfg.Threads, func(r sqli.Result) {
			send(ui.ItemMsg{
				Icon: stylePurple.Render("⚡"),
				Text: styleMuted.Render(r.URL) + styleRed.Render(" "+r.Param),
			})
		})
		stateObj.Mark(22)
		state.Save(stateFile, stateObj)
	}
	if ntfyCfg.Enabled() {
		for _, s := range res.SQLi {
			if s.Detected {
				ntfyCfg.Send("🚨 SQLi Detected — "+e.cfg.Target, fmt.Sprintf("Param: %s at %s\nEvidence: %s", s.Param, s.URL, s.Evidence))
				break
			}
		}
	}
	send(ui.StepDoneMsg{Step: 22, Count: len(res.SQLi)})

	send(ui.StepStartMsg(23))
	if !stateObj.Done(23) {
		loginURLs := make([]string, 0)
		for _, a := range res.AdminPanel {
			if a.StatusCode == 200 || a.StatusCode == 302 {
				loginURLs = append(loginURLs, a.URL+a.Path)
			}
		}
		if len(loginURLs) == 0 {
			for _, h := range res.HTTP {
				loginURLs = append(loginURLs, h.URL+"/login")
			}
		}
		res.DefaultCreds = defaultcreds.Check(loginURLs, func(r defaultcreds.Result) {
			send(ui.ItemMsg{
				Icon: stylePurple.Render("🔑"),
				Text: styleMuted.Render(r.URL) + styleRed.Render(" "+r.Username+":"+r.Password),
			})
		})
		stateObj.Mark(23)
		state.Save(stateFile, stateObj)
	}
	if ntfyCfg.Enabled() {
		for _, c := range res.DefaultCreds {
			if c.Found {
				ntfyCfg.Send("🚨 Default Credentials — "+e.cfg.Target, fmt.Sprintf("%s:%s at %s", c.Username, c.Password, c.URL))
			}
		}
	}
	send(ui.StepDoneMsg{Step: 23, Count: func() int {
		c := 0
		for _, r := range res.DefaultCreds {
			if r.Found {
				c++
			}
		}
		return c
	}()})

	send(ui.StepStartMsg(24))
	if !stateObj.Done(24) {
		res.RateLimit = ratelimit.Detect(res.HTTP)
		stateObj.Mark(24)
		state.Save(stateFile, stateObj)
	}
	send(ui.StepDoneMsg{Step: 24, Count: len(res.RateLimit)})

	send(ui.StepStartMsg(25))
	if !stateObj.Done(25) {
		tmpls, err := templates.LoadBuiltins()
		if err == nil && len(e.cfg.TemplatePaths) > 0 {
			custom, cerr := templates.LoadCustom(e.cfg.TemplatePaths)
			if cerr == nil {
				tmpls = append(tmpls, custom...)
			}
		}
		if err == nil {
			res.Templates = templates.Run(tmpls, baseURLs, e.cfg.Threads, func(m templates.Match) {
				send(ui.ItemMsg{
					Icon: styleYellow.Render("⬡"),
					Text: styleMuted.Render("["+m.TemplateID+"]") + "  " + styleYellow.Render(m.Name) + "  " + styleMuted.Render(m.URL),
				})
			})
		}
		stateObj.Mark(25)
		state.Save(stateFile, stateObj)
	}
	send(ui.StepDoneMsg{Step: 25, Count: len(res.Templates)})

	return res
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
