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

"github.com/bytezora/recon-x/internal/adminpanel"
"github.com/bytezora/recon-x/internal/axfr"
"github.com/bytezora/recon-x/internal/buckets"
"github.com/bytezora/recon-x/internal/crtsh"
"github.com/bytezora/recon-x/internal/dirbust"
"github.com/bytezora/recon-x/internal/ghsearch"
"github.com/bytezora/recon-x/internal/httpcheck"
"github.com/bytezora/recon-x/internal/jsscan"
"github.com/bytezora/recon-x/internal/notify"
"github.com/bytezora/recon-x/internal/openredirect"
"github.com/bytezora/recon-x/internal/output"
"github.com/bytezora/recon-x/internal/portscan"
"github.com/bytezora/recon-x/internal/ratelimit"
"github.com/bytezora/recon-x/internal/report"
"github.com/bytezora/recon-x/internal/scope"
"github.com/bytezora/recon-x/internal/screenshot"
"github.com/bytezora/recon-x/internal/sqli"
"github.com/bytezora/recon-x/internal/state"
"github.com/bytezora/recon-x/internal/subdomain"
"github.com/bytezora/recon-x/internal/tlscheck"
"github.com/bytezora/recon-x/internal/vulns"
"github.com/bytezora/recon-x/internal/waf"
"github.com/bytezora/recon-x/internal/whois"
"github.com/bytezora/recon-x/internal/asn"
"github.com/bytezora/recon-x/internal/bypass"
"github.com/bytezora/recon-x/internal/cors"
"github.com/bytezora/recon-x/internal/defaultcreds"
"github.com/bytezora/recon-x/internal/emailsec"
"github.com/bytezora/recon-x/internal/favicon"
"github.com/bytezora/recon-x/internal/graphql"
"github.com/bytezora/recon-x/internal/takeover"
"github.com/bytezora/recon-x/internal/vhost"
"github.com/bytezora/recon-x/ui"
)

const (
version      = "1.6.0"
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
}

func main() {
cfg := parseFlags()

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

ntfyCfg := notify.Config{SlackWebhook: cfg.NotifySlack}
if cfg.NotifyTelegram != "" {
parts := strings.SplitN(cfg.NotifyTelegram, "@", 2)
if len(parts) == 2 {
ntfyCfg.TelegramToken = parts[0]
ntfyCfg.TelegramChatID = parts[1]
}
}

fmt.Println(stylePurple.Render(banner))
fmt.Printf("\n  %s  v%s  ·  by bytezora  ·  for authorized testing only\n\n",
stylePurple.Render("recon-x"), version)

start := time.Now()

m    := ui.New(cfg.Target)
prog := tea.NewProgram(m, tea.WithAltScreen())

var (
finalSubs         []subdomain.Result
finalPorts        []portscan.Result
finalHTTP         []httpcheck.Result
finalVulns        []vulns.Match
finalWAFs         []waf.Result
finalDirs         []dirbust.Hit
finalJS           []jsscan.Finding
finalGH           []ghsearch.Finding
finalBuckets      []buckets.Result
finalTLS          []tlscheck.Result
finalRedirects    []openredirect.Result
finalAXFR         []axfr.Result
finalWHOIS        *whois.Result
finalShots        []screenshot.Result
finalTakeover     []takeover.Result
finalCORS         []cors.Result
finalBypass       []bypass.Result
finalVHosts       []vhost.Result
finalFavicons     []favicon.Result
finalASN          []asn.Result
finalGraphQL      []graphql.Result
finalEmailSec     *emailsec.Result
finalAdminPanel   []adminpanel.Result
finalSQLi         []sqli.Result
finalDefaultCreds []defaultcreds.Result
finalRateLimit    []ratelimit.Result
)

go func() {
runScans(cfg, prog,
&finalSubs, &finalPorts, &finalHTTP,
&finalVulns, &finalWAFs, &finalDirs, &finalJS,
&finalGH, &finalBuckets,
&finalTLS, &finalRedirects, &finalAXFR, &finalWHOIS, &finalShots,
&finalTakeover, &finalCORS, &finalBypass, &finalVHosts,
&finalFavicons, &finalASN, &finalGraphQL, &finalEmailSec,
&finalAdminPanel, &finalSQLi, &finalDefaultCreds, &finalRateLimit,
ntfyCfg, stateObj, stateFile,
)
prog.Send(ui.DoneMsg{})
}()

if _, err := prog.Run(); err != nil {
fail("TUI error: %v", err)
os.Exit(1)
}

if cfg.SARIF != "" {
if err := output.WriteSARIF(cfg.SARIF, finalVulns, finalSQLi, finalTakeover, finalCORS, finalDefaultCreds); err != nil {
fail("SARIF error: %v", err)
} else {
success("SARIF output → %s", styleYellow.Render(cfg.SARIF))
}
}

if err := report.Generate(cfg.Target, finalSubs, finalPorts, finalHTTP,
finalVulns, finalWAFs, finalDirs, finalJS, finalGH, finalBuckets,
finalTLS, finalRedirects, finalAXFR, finalWHOIS, finalShots,
finalTakeover, finalCORS, finalBypass, finalVHosts,
finalFavicons, finalASN, finalGraphQL, finalEmailSec,
finalAdminPanel, finalSQLi, finalDefaultCreds, finalRateLimit, cfg.Output); err != nil {
fail("report error: %v", err)
os.Exit(1)
}
success("HTML report → %s", styleYellow.Render(cfg.Output))

if cfg.JSON != "" {
if err := output.WriteJSON(cfg.JSON, cfg.Target, finalSubs, finalPorts, finalHTTP,
finalVulns, finalWAFs, finalDirs, finalJS, finalGH, finalBuckets,
finalTLS, finalRedirects, finalAXFR, finalWHOIS, finalShots,
finalTakeover, finalCORS, finalBypass, finalVHosts,
finalFavicons, finalASN, finalGraphQL, finalEmailSec,
finalAdminPanel, finalSQLi, finalDefaultCreds, finalRateLimit); err != nil {
fail("JSON error: %v", err)
} else {
success("JSON output → %s", styleYellow.Render(cfg.JSON))
}
}

fmt.Printf("\n  %s  Finished in %s\n\n",
styleGreen.Render("◆"),
styleGreen.Render(time.Since(start).Round(time.Second).String()))
}

func runScans(
cfg      Config,
prog     *tea.Program,
subs     *[]subdomain.Result,
ports    *[]portscan.Result,
httpR    *[]httpcheck.Result,
vs       *[]vulns.Match,
wafs     *[]waf.Result,
dirs     *[]dirbust.Hit,
jsf      *[]jsscan.Finding,
ghf      *[]ghsearch.Finding,
bkts     *[]buckets.Result,
tlsr     *[]tlscheck.Result,
redir    *[]openredirect.Result,
axfrr    *[]axfr.Result,
who      **whois.Result,
shots    *[]screenshot.Result,
tkover   *[]takeover.Result,
corsR    *[]cors.Result,
bypassR  *[]bypass.Result,
vhosts   *[]vhost.Result,
favicons *[]favicon.Result,
asnR     *[]asn.Result,
gqlR     *[]graphql.Result,
emailR   **emailsec.Result,
adminR   *[]adminpanel.Result,
sqliR    *[]sqli.Result,
credsR   *[]defaultcreds.Result,
rateLimR *[]ratelimit.Result,
ntfyCfg  notify.Config,
stateObj *state.State,
stateFile string,
) {
prog.Send(ui.StepStartMsg(0))
var passiveNames []string
if !stateObj.Done(0) {
if !cfg.NoPassive {
names, err := crtsh.Lookup(cfg.Target)
if err == nil {
passiveNames = names
}
}
stateObj.Mark(0)
state.Save(stateFile, stateObj)
}
prog.Send(ui.StepDoneMsg{Step: 0, Count: len(passiveNames)})

prog.Send(ui.StepStartMsg(1))
if !stateObj.Done(1) {
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
if cfg.ScopeFile != "" {
sc, err := scope.Load(cfg.ScopeFile)
if err == nil {
filtered := (*subs)[:0]
for _, s := range *subs {
if sc.InScope(s.Subdomain) {
filtered = append(filtered, s)
}
}
*subs = filtered
}
}
stateObj.Mark(1)
state.Save(stateFile, stateObj)
}
prog.Send(ui.StepDoneMsg{Step: 1, Count: len(*subs)})

prog.Send(ui.StepStartMsg(2))
if !stateObj.Done(2) {
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
stateObj.Mark(2)
state.Save(stateFile, stateObj)
}
prog.Send(ui.StepDoneMsg{Step: 2, Count: len(*ports)})

prog.Send(ui.StepStartMsg(3))
if !stateObj.Done(3) {
*httpR = httpcheck.Check(*ports, cfg.Threads)
seenCVE := make(map[string]bool)
addVuln := func(matches []vulns.Match) {
for _, m := range matches {
key := m.Host + ":" + fmt.Sprintf("%d", m.Port) + ":" + m.CVE
if seenCVE[key] {
continue
}
seenCVE[key] = true
*vs = append(*vs, m)
prog.Send(ui.ItemMsg{
Icon: styleRed.Render("⚠"),
Text: styleRed.Render(m.CVE) + "  " + styleMuted.Render(m.Description),
})
}
}
for _, p := range *ports {
if p.Banner != "" {
addVuln(vulns.CheckBanner(p.Host, p.Port, p.Banner))
}
}
for _, h := range *httpR {
if detected := waf.Detect(h.Host, h.URL, h.Headers, h.Body); len(detected) > 0 {
*wafs = append(*wafs, detected...)
for _, r := range detected {
prog.Send(ui.ItemMsg{
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
for _, v := range *vs {
if v.Severity == "CRITICAL" || v.Severity == "HIGH" {
ntfyCfg.Send("🚨 CVE Found — "+cfg.Target, fmt.Sprintf("%s (CVSS %.1f) on %s:%d\n%s", v.CVE, v.CVSS, v.Host, v.Port, v.Description))
break
}
}
}
prog.Send(ui.StepDoneMsg{Step: 3, Count: len(*httpR)})

baseURLs := make([]string, 0, len(*httpR))
for _, h := range *httpR {
baseURLs = append(baseURLs, h.URL)
}

prog.Send(ui.StepStartMsg(4))
if !stateObj.Done(4) {
*dirs = dirbust.Bust(baseURLs, cfg.DirWordlist, cfg.Threads, func(h dirbust.Hit) {
prog.Send(ui.ItemMsg{
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
prog.Send(ui.StepDoneMsg{Step: 4, Count: len(*dirs)})

prog.Send(ui.StepStartMsg(5))
if !stateObj.Done(5) {
pages := make(map[string]string, len(*httpR))
for _, h := range *httpR {
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
stateObj.Mark(5)
state.Save(stateFile, stateObj)
}
prog.Send(ui.StepDoneMsg{Step: 5, Count: len(*jsf)})

prog.Send(ui.StepStartMsg(6))
if !stateObj.Done(6) {
*ghf = ghsearch.Search(cfg.Target, cfg.GitHubToken, func(f ghsearch.Finding) {
prog.Send(ui.ItemMsg{
Icon: styleYellow.Render("⚑"),
Text: styleMuted.Render(f.Repo) + "  " + styleYellow.Render(f.Keyword) + "  " + styleMuted.Render(f.Path),
})
})
stateObj.Mark(6)
state.Save(stateFile, stateObj)
}
prog.Send(ui.StepDoneMsg{Step: 6, Count: len(*ghf)})

prog.Send(ui.StepStartMsg(7))
if !stateObj.Done(7) {
*bkts = buckets.Enum(cfg.Target, cfg.Threads, func(r buckets.Result) {
icon := styleMuted.Render("▣")
if r.Status == "public" {
icon = styleRed.Render("▣")
}
prog.Send(ui.ItemMsg{
Icon: icon,
Text: styleYellow.Render(r.Provider) + "  " + styleMuted.Render(r.Bucket) + "  " + styleGreen.Render(r.Status),
})
})
stateObj.Mark(7)
state.Save(stateFile, stateObj)
}
prog.Send(ui.StepDoneMsg{Step: 7, Count: len(*bkts)})

prog.Send(ui.StepStartMsg(8))
if !stateObj.Done(8) {
var tlsTargets []tlscheck.Target
seenTLS := make(map[string]bool)
for _, h := range *httpR {
if h.Port == 443 || h.Port == 8443 || h.Port == 4443 || h.Port == 7443 {
key := fmt.Sprintf("%s:%d", h.Host, h.Port)
if !seenTLS[key] {
seenTLS[key] = true
tlsTargets = append(tlsTargets, tlscheck.Target{Host: h.Host, Port: h.Port})
}
}
}
*tlsr = tlscheck.Check(tlsTargets, cfg.Threads, func(r tlscheck.Result) {
icon := styleGreen.Render("🔒")
if len(r.Issues) > 0 {
icon = styleRed.Render("🔓")
}
prog.Send(ui.ItemMsg{
Icon: icon,
Text: styleMuted.Render(fmt.Sprintf("%s:%d", r.Host, r.Port)) + "  " +
styleYellow.Render(r.Proto) + "  " +
styleMuted.Render(r.Expiry),
})
})
stateObj.Mark(8)
state.Save(stateFile, stateObj)
}
prog.Send(ui.StepDoneMsg{Step: 8, Count: len(*tlsr)})

prog.Send(ui.StepStartMsg(9))
if !stateObj.Done(9) {
*redir = openredirect.Check(baseURLs, cfg.Threads, func(r openredirect.Result) {
prog.Send(ui.ItemMsg{
Icon: styleRed.Render("↪"),
Text: styleMuted.Render(r.BaseURL) + "  " + styleYellow.Render("?"+r.Param) + "  " + styleMuted.Render(r.Location),
})
})
stateObj.Mark(9)
state.Save(stateFile, stateObj)
}
prog.Send(ui.StepDoneMsg{Step: 9, Count: len(*redir)})

prog.Send(ui.StepStartMsg(10))
var axfrTotal int
if !stateObj.Done(10) {
*axfrr = axfr.Transfer(cfg.Target)
for _, r := range *axfrr {
if r.Success {
axfrTotal += len(r.Records)
prog.Send(ui.ItemMsg{
Icon: styleRed.Render("⚠"),
Text: styleRed.Render("AXFR success") + "  " + styleMuted.Render(r.NS) + "  " +
styleMuted.Render(fmt.Sprintf("%d records", len(r.Records))),
})
}
}
stateObj.Mark(10)
state.Save(stateFile, stateObj)
}
prog.Send(ui.StepDoneMsg{Step: 10, Count: axfrTotal})

prog.Send(ui.StepStartMsg(11))
if !stateObj.Done(11) {
if w, err := whois.Lookup(cfg.Target); err == nil {
*who = w
prog.Send(ui.ItemMsg{
Icon: stylePurple.Render("◈"),
Text: styleMuted.Render(w.Registrar) + "  " + styleYellow.Render(w.Country),
})
}
stateObj.Mark(11)
state.Save(stateFile, stateObj)
}
prog.Send(ui.StepDoneMsg{Step: 11, Count: func() int {
if *who != nil {
return 1
}
return 0
}()})

prog.Send(ui.StepStartMsg(12))
if !stateObj.Done(12) {
*shots = screenshot.Capture(baseURLs, cfg.Threads, func(r screenshot.Result) {
prog.Send(ui.ItemMsg{
Icon: styleGreen.Render("📷"),
Text: styleMuted.Render(r.URL),
})
})
stateObj.Mark(12)
state.Save(stateFile, stateObj)
}
prog.Send(ui.StepDoneMsg{Step: 12, Count: len(*shots)})

prog.Send(ui.StepStartMsg(13))
if !stateObj.Done(13) {
var subList []string
for _, s := range *subs {
subList = append(subList, s.Subdomain)
}
*tkover = takeover.Check(subList, cfg.Threads, func(r takeover.Result) {
if r.Vulnerable {
prog.Send(ui.ItemMsg{
Icon: styleRed.Render("⚠"),
Text: styleRed.Render(r.Subdomain) + "  " + styleMuted.Render(r.CNAME) + "  " + styleYellow.Render(r.Service),
})
}
})
stateObj.Mark(13)
state.Save(stateFile, stateObj)
}
if ntfyCfg.Enabled() {
for _, t := range *tkover {
if t.Vulnerable {
ntfyCfg.Send("🚨 Subdomain Takeover — "+cfg.Target, fmt.Sprintf("%s → %s (%s)", t.Subdomain, t.CNAME, t.Service))
}
}
}
prog.Send(ui.StepDoneMsg{Step: 13, Count: func() int {
n := 0
for _, r := range *tkover {
if r.Vulnerable {
n++
}
}
return n
}()})

prog.Send(ui.StepStartMsg(14))
if !stateObj.Done(14) {
*corsR = cors.Scan(baseURLs, cfg.Threads, func(r cors.Result) {
prog.Send(ui.ItemMsg{
Icon: styleYellow.Render("↺"),
Text: styleMuted.Render(r.URL) + "  " + styleYellow.Render(r.Origin),
})
})
stateObj.Mark(14)
state.Save(stateFile, stateObj)
}
prog.Send(ui.StepDoneMsg{Step: 14, Count: len(*corsR)})

prog.Send(ui.StepStartMsg(15))
if !stateObj.Done(15) {
var forbiddenURLs []string
for _, d := range *dirs {
if d.StatusCode == 403 {
forbiddenURLs = append(forbiddenURLs, d.URL)
}
}
*bypassR = bypass.Check(forbiddenURLs, cfg.Threads, func(r bypass.Result) {
if r.Bypassed {
prog.Send(ui.ItemMsg{
Icon: styleGreen.Render("✓"),
Text: styleMuted.Render(r.URL) + "  " + styleYellow.Render(r.Technique),
})
}
})
stateObj.Mark(15)
state.Save(stateFile, stateObj)
}
prog.Send(ui.StepDoneMsg{Step: 15, Count: func() int {
n := 0
for _, r := range *bypassR {
if r.Bypassed {
n++
}
}
return n
}()})

prog.Send(ui.StepStartMsg(16))
if !stateObj.Done(16) {
*vhosts = vhost.Discover(*httpR, cfg.Threads, func(r vhost.Result) {
prog.Send(ui.ItemMsg{
Icon: stylePurple.Render("◈"),
Text: styleMuted.Render(r.IP) + "  " + styleYellow.Render(r.VHost) + "  " + styleMuted.Render(fmt.Sprintf("%d", r.Status)),
})
})
stateObj.Mark(16)
state.Save(stateFile, stateObj)
}
prog.Send(ui.StepDoneMsg{Step: 16, Count: len(*vhosts)})

prog.Send(ui.StepStartMsg(17))
if !stateObj.Done(17) {
*favicons = favicon.Scan(baseURLs, cfg.Threads, func(r favicon.Result) {
prog.Send(ui.ItemMsg{
Icon: styleMuted.Render("⬡"),
Text: styleMuted.Render(r.URL) + "  " + styleYellow.Render(fmt.Sprintf("%d", r.Hash)),
})
})
stateObj.Mark(17)
state.Save(stateFile, stateObj)
}
prog.Send(ui.StepDoneMsg{Step: 17, Count: len(*favicons)})

prog.Send(ui.StepStartMsg(18))
if !stateObj.Done(18) {
seenIP := map[string]bool{}
var ips []string
for _, p := range *ports {
if !seenIP[p.IP] && p.IP != "" {
seenIP[p.IP] = true
ips = append(ips, p.IP)
}
}
*asnR = asn.Lookup(ips, cfg.Threads, func(r asn.Result) {
prog.Send(ui.ItemMsg{
Icon: styleMuted.Render("◈"),
Text: styleMuted.Render(r.IP) + "  " + styleYellow.Render(r.ASN) + "  " + styleMuted.Render(r.Org),
})
})
stateObj.Mark(18)
state.Save(stateFile, stateObj)
}
prog.Send(ui.StepDoneMsg{Step: 18, Count: len(*asnR)})

prog.Send(ui.StepStartMsg(19))
if !stateObj.Done(19) {
*gqlR = graphql.Probe(baseURLs, cfg.Threads, func(r graphql.Result) {
prog.Send(ui.ItemMsg{
Icon: styleGreen.Render("⬡"),
Text: styleMuted.Render(r.Endpoint) + "  " + styleYellow.Render(fmt.Sprintf("introspection:%v", r.Introspection)),
})
})
stateObj.Mark(19)
state.Save(stateFile, stateObj)
}
prog.Send(ui.StepDoneMsg{Step: 19, Count: len(*gqlR)})

prog.Send(ui.StepStartMsg(20))
if !stateObj.Done(20) {
if esResult, err := emailsec.Check(cfg.Target); err == nil {
*emailR = esResult
spoofable := ""
if esResult.Spoofable {
spoofable = " ⚠ SPOOFABLE"
}
prog.Send(ui.ItemMsg{
Icon: stylePurple.Render("✉"),
Text: styleMuted.Render(cfg.Target) + styleRed.Render(spoofable),
})
}
stateObj.Mark(20)
state.Save(stateFile, stateObj)
}
prog.Send(ui.StepDoneMsg{Step: 20, Count: func() int {
if *emailR != nil {
return 1
}
return 0
}()})

prog.Send(ui.StepStartMsg(21))
if !stateObj.Done(21) {
*adminR = adminpanel.Discover(*httpR, cfg.Threads, func(r adminpanel.Result) {
prog.Send(ui.ItemMsg{
Icon: stylePurple.Render("🔍"),
Text: styleMuted.Render(r.URL) + styleYellow.Render(r.Path),
})
})
stateObj.Mark(21)
state.Save(stateFile, stateObj)
}
prog.Send(ui.StepDoneMsg{Step: 21, Count: len(*adminR)})

prog.Send(ui.StepStartMsg(22))
if !stateObj.Done(22) {
httpURLs := make([]string, 0, len(*httpR))
for _, h := range *httpR {
httpURLs = append(httpURLs, h.URL)
}
*sqliR = sqli.Detect(httpURLs, cfg.Threads, func(r sqli.Result) {
prog.Send(ui.ItemMsg{
Icon: stylePurple.Render("⚡"),
Text: styleMuted.Render(r.URL) + styleRed.Render(" "+r.Param),
})
})
stateObj.Mark(22)
state.Save(stateFile, stateObj)
}
if ntfyCfg.Enabled() {
for _, s := range *sqliR {
if s.Detected {
ntfyCfg.Send("🚨 SQLi Detected — "+cfg.Target, fmt.Sprintf("Param: %s at %s\nEvidence: %s", s.Param, s.URL, s.Evidence))
break
}
}
}
prog.Send(ui.StepDoneMsg{Step: 22, Count: len(*sqliR)})

prog.Send(ui.StepStartMsg(23))
if !stateObj.Done(23) {
loginURLs := make([]string, 0)
for _, a := range *adminR {
if a.StatusCode == 200 || a.StatusCode == 302 {
loginURLs = append(loginURLs, a.URL+a.Path)
}
}
if len(loginURLs) == 0 {
for _, h := range *httpR {
loginURLs = append(loginURLs, h.URL+"/login")
}
}
*credsR = defaultcreds.Check(loginURLs, func(r defaultcreds.Result) {
prog.Send(ui.ItemMsg{
Icon: stylePurple.Render("��"),
Text: styleMuted.Render(r.URL) + styleRed.Render(" "+r.Username+":"+r.Password),
})
})
stateObj.Mark(23)
state.Save(stateFile, stateObj)
}
if ntfyCfg.Enabled() {
for _, c := range *credsR {
if c.Found {
ntfyCfg.Send("🚨 Default Credentials — "+cfg.Target, fmt.Sprintf("%s:%s at %s", c.Username, c.Password, c.URL))
}
}
}
prog.Send(ui.StepDoneMsg{Step: 23, Count: func() int {
c := 0
for _, r := range *credsR {
if r.Found {
c++
}
}
return c
}()})

prog.Send(ui.StepStartMsg(24))
if !stateObj.Done(24) {
*rateLimR = ratelimit.Detect(*httpR)
stateObj.Mark(24)
state.Save(stateFile, stateObj)
}
prog.Send(ui.StepDoneMsg{Step: 24, Count: len(*rateLimR)})
}

func parseFlags() Config {
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
ver            := flag.Bool("version",           false,         "Print version and exit")
dbHash         := flag.Bool("db-hash",           false,         "Print CVE database fingerprint and exit (for stamping integrity.go)")
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
