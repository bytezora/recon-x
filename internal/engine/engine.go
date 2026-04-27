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
"github.com/bytezora/recon-x/internal/finding"
"github.com/bytezora/recon-x/internal/ghsearch"
"github.com/bytezora/recon-x/internal/graphql"
"github.com/bytezora/recon-x/internal/httpcheck"
"github.com/bytezora/recon-x/internal/jsscan"
"github.com/bytezora/recon-x/internal/notify"
"github.com/bytezora/recon-x/internal/openredirect"
"github.com/bytezora/recon-x/internal/passive"
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
Findings     []finding.Finding
PassiveNames []string
}

type Engine struct {
cfg Config
}

func New(cfg Config) *Engine {
return &Engine{cfg: cfg}
}

type StepFunc func(e *Engine, res *Results, send func(tea.Msg))

func step0(e *Engine, res *Results, send func(tea.Msg)) {
if !e.cfg.NoPassive {
crtNames, err := crtsh.Lookup(e.cfg.Target)
if err == nil {
res.PassiveNames = append(res.PassiveNames, crtNames...)
}
moreNames := passive.Gather(e.cfg.Target)
res.PassiveNames = append(res.PassiveNames, moreNames...)
seen := make(map[string]bool)
deduped := res.PassiveNames[:0]
for _, n := range res.PassiveNames {
if !seen[n] {
seen[n] = true
deduped = append(deduped, n)
}
}
res.PassiveNames = deduped
}
}

func step1(e *Engine, res *Results, send func(tea.Msg)) {
res.Subs = subdomain.Enumerate(e.cfg.Target, e.cfg.Threads, e.cfg.Wordlist, e.cfg.Resolver, func(r subdomain.Result) {
send(ui.ItemMsg{
Icon: styleGreen.Render("↳"),
Text: styleMuted.Render(r.Subdomain) + "  " + styleMuted.Render(strings.Join(r.IPs, ", ")),
})
})
res.Subs = subdomain.AddPassive(res.Subs, res.PassiveNames, e.cfg.Resolver, func(r subdomain.Result) {
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
}

func step2(e *Engine, res *Results, send func(tea.Msg)) {
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
}

func step3(e *Engine, res *Results, send func(tea.Msg)) {
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
if e.cfg.Target != "" {
for _, h := range res.HTTP {
scheme := strings.SplitN(h.URL, "://", 2)[0]
verified := vulns.ActiveVerify(scheme, h.Host, h.Port)
for _, vr := range verified {
if vr.Confirmed {
res.Vulns = append(res.Vulns, vulns.Match{
Host:        h.Host,
Port:        h.Port,
CVE:         vr.CVE,
CVSS:        9.8,
Severity:    "CRITICAL",
Description: "CONFIRMED: " + vr.Evidence,
Link:        "https://nvd.nist.gov/vuln/detail/" + vr.CVE,
Confidence:  "confirmed",
})
send(ui.ItemMsg{Icon: "🔴", Text: "CONFIRMED CVE: " + vr.CVE + " on " + h.Host})
}
}
}
}
}

func step4(e *Engine, res *Results, send func(tea.Msg)) {
res.Dirs = dirbust.Bust(baseURLs(res), e.cfg.DirWordlist, e.cfg.Threads, func(h dirbust.Hit) {
send(ui.ItemMsg{
Icon: stylePurple.Render("📁"),
Text: fmt.Sprintf("%s  %s",
styleMuted.Render(h.Path),
statusBadge(h.StatusCode),
),
})
})
}

func step5(e *Engine, res *Results, send func(tea.Msg)) {
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
}

func step6(e *Engine, res *Results, send func(tea.Msg)) {
res.GH = ghsearch.Search(e.cfg.Target, e.cfg.GitHubToken, func(f ghsearch.Finding) {
send(ui.ItemMsg{
Icon: styleYellow.Render("⚑"),
Text: styleMuted.Render(f.Repo) + "  " + styleYellow.Render(f.Keyword) + "  " + styleMuted.Render(f.Path),
})
})
}

func step7(e *Engine, res *Results, send func(tea.Msg)) {
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
}

func step8(e *Engine, res *Results, send func(tea.Msg)) {
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
}

func step9(e *Engine, res *Results, send func(tea.Msg)) {
res.Redirects = openredirect.Check(baseURLs(res), e.cfg.Threads, func(r openredirect.Result) {
send(ui.ItemMsg{
Icon: styleRed.Render("↪"),
Text: styleMuted.Render(r.BaseURL) + "  " + styleYellow.Render("?"+r.Param) + "  " + styleMuted.Render(r.Location),
})
})
}

func step10(e *Engine, res *Results, send func(tea.Msg)) {
res.AXFR = axfr.Transfer(e.cfg.Target)
for _, r := range res.AXFR {
if r.Success {
send(ui.ItemMsg{
Icon: styleRed.Render("⚠"),
Text: styleRed.Render("AXFR success") + "  " + styleMuted.Render(r.NS) + "  " +
styleMuted.Render(fmt.Sprintf("%d records", len(r.Records))),
})
}
}
}

func step11(e *Engine, res *Results, send func(tea.Msg)) {
if w, err := whois.Lookup(e.cfg.Target); err == nil {
res.WHOIS = w
send(ui.ItemMsg{
Icon: stylePurple.Render("◈"),
Text: styleMuted.Render(w.Registrar) + "  " + styleYellow.Render(w.Country),
})
}
}

func step12(e *Engine, res *Results, send func(tea.Msg)) {
res.Screenshots = screenshot.Capture(baseURLs(res), e.cfg.Threads, func(r screenshot.Result) {
send(ui.ItemMsg{
Icon: styleGreen.Render("📷"),
Text: styleMuted.Render(r.URL),
})
})
}

func step13(e *Engine, res *Results, send func(tea.Msg)) {
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
}

func step14(e *Engine, res *Results, send func(tea.Msg)) {
res.CORS = cors.Scan(baseURLs(res), e.cfg.Threads, func(r cors.Result) {
send(ui.ItemMsg{
Icon: styleYellow.Render("↺"),
Text: styleMuted.Render(r.URL) + "  " + styleYellow.Render(r.Origin),
})
})
}

func step15(e *Engine, res *Results, send func(tea.Msg)) {
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
}

func step16(e *Engine, res *Results, send func(tea.Msg)) {
res.VHosts = vhost.Discover(res.HTTP, e.cfg.Threads, func(r vhost.Result) {
send(ui.ItemMsg{
Icon: stylePurple.Render("◈"),
Text: styleMuted.Render(r.IP) + "  " + styleYellow.Render(r.VHost) + "  " + styleMuted.Render(fmt.Sprintf("%d", r.Status)),
})
})
}

func step17(e *Engine, res *Results, send func(tea.Msg)) {
res.Favicons = favicon.Scan(baseURLs(res), e.cfg.Threads, func(r favicon.Result) {
send(ui.ItemMsg{
Icon: styleMuted.Render("⬡"),
Text: styleMuted.Render(r.URL) + "  " + styleYellow.Render(fmt.Sprintf("%d", r.Hash)),
})
})
}

func step18(e *Engine, res *Results, send func(tea.Msg)) {
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
}

func step19(e *Engine, res *Results, send func(tea.Msg)) {
res.GraphQL = graphql.Probe(baseURLs(res), e.cfg.Threads, func(r graphql.Result) {
send(ui.ItemMsg{
Icon: styleGreen.Render("⬡"),
Text: styleMuted.Render(r.Endpoint) + "  " + styleYellow.Render(fmt.Sprintf("introspection:%v", r.Introspection)),
})
})
}

func step20(e *Engine, res *Results, send func(tea.Msg)) {
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
}

func step21(e *Engine, res *Results, send func(tea.Msg)) {
res.AdminPanel = adminpanel.Discover(res.HTTP, e.cfg.Threads, func(r adminpanel.Result) {
send(ui.ItemMsg{
Icon: stylePurple.Render("🔍"),
Text: styleMuted.Render(r.URL) + styleYellow.Render(r.Path),
})
})
}

func step22(e *Engine, res *Results, send func(tea.Msg)) {
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
}

func step23(e *Engine, res *Results, send func(tea.Msg)) {
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
}

func step24(e *Engine, res *Results, send func(tea.Msg)) {
res.RateLimit = ratelimit.Detect(res.HTTP)
}

func step25(e *Engine, res *Results, send func(tea.Msg)) {
tmpls, err := templates.LoadBuiltins()
if err == nil && len(e.cfg.TemplatePaths) > 0 {
custom, cerr := templates.LoadCustom(e.cfg.TemplatePaths)
if cerr == nil {
tmpls = append(tmpls, custom...)
}
}
if err == nil {
res.Templates = templates.Run(tmpls, baseURLs(res), e.cfg.Threads, func(m templates.Match) {
send(ui.ItemMsg{
Icon: styleYellow.Render("⬡"),
Text: styleMuted.Render("["+m.TemplateID+"]") + "  " + styleYellow.Render(m.Name) + "  " + styleMuted.Render(m.URL),
})
})
}
}

var steps = []StepFunc{
step0, step1, step2, step3, step4, step5,
step6, step7, step8, step9, step10, step11,
step12, step13, step14, step15, step16, step17,
step18, step19, step20, step21, step22, step23,
step24, step25,
}

func (e *Engine) Run(send func(tea.Msg), stateObj *state.State, stateFile string, ms map[int]bool) *Results {
res := &Results{}
for i, fn := range steps {
send(ui.StepStartMsg(i))
if !ms[i] || stateObj.Done(i) {
send(ui.StepDoneMsg{Step: i, Count: 0})
continue
}
fn(e, res, send)
stateObj.Mark(i)
state.Save(stateFile, stateObj)
send(ui.StepDoneMsg{Step: i, Count: stepCount(i, res)})
}
if e.cfg.NotifyTelegram != "" || e.cfg.NotifySlack != "" {
sendNotifications(e, res)
}
res.Findings = buildFindings(res)
return res
}

func stepCount(i int, res *Results) int {
switch i {
case 0:
return 0
case 1:
return len(res.Subs)
case 2:
return len(res.Ports)
case 3:
return len(res.HTTP)
case 4:
return len(res.Dirs)
case 5:
return len(res.JS)
case 6:
return len(res.GH)
case 7:
return len(res.Buckets)
case 8:
return len(res.TLS)
case 9:
return len(res.Redirects)
case 10:
n := 0
for _, r := range res.AXFR {
if r.Success {
n += len(r.Records)
}
}
return n
case 11:
if res.WHOIS != nil {
return 1
}
return 0
case 12:
return len(res.Screenshots)
case 13:
n := 0
for _, r := range res.Takeover {
if r.Vulnerable {
n++
}
}
return n
case 14:
return len(res.CORS)
case 15:
n := 0
for _, r := range res.Bypass {
if r.Bypassed {
n++
}
}
return n
case 16:
return len(res.VHosts)
case 17:
return len(res.Favicons)
case 18:
return len(res.ASN)
case 19:
return len(res.GraphQL)
case 20:
if res.EmailSec != nil {
return 1
}
return 0
case 21:
return len(res.AdminPanel)
case 22:
return len(res.SQLi)
case 23:
n := 0
for _, r := range res.DefaultCreds {
if r.Found {
n++
}
}
return n
case 24:
return len(res.RateLimit)
case 25:
return len(res.Templates)
}
return 0
}

func sendNotifications(e *Engine, res *Results) {
ntfyCfg := e.ntfyCfg()
if !ntfyCfg.Enabled() {
return
}
for _, v := range res.Vulns {
if v.Severity == "CRITICAL" || v.Severity == "HIGH" {
ntfyCfg.Send("🚨 CVE Found — "+e.cfg.Target, fmt.Sprintf("%s (CVSS %.1f) on %s:%d\n%s", v.CVE, v.CVSS, v.Host, v.Port, v.Description))
break
}
}
for _, t := range res.Takeover {
if t.Vulnerable {
ntfyCfg.Send("🚨 Subdomain Takeover — "+e.cfg.Target, fmt.Sprintf("%s → %s (%s)", t.Subdomain, t.CNAME, t.Service))
}
}
for _, s := range res.SQLi {
if s.Detected {
ntfyCfg.Send("🚨 SQLi Detected — "+e.cfg.Target, fmt.Sprintf("Param: %s at %s\nEvidence: %s", s.Param, s.URL, s.Evidence))
break
}
}
for _, c := range res.DefaultCreds {
if c.Found {
ntfyCfg.Send("🚨 Default Credentials — "+e.cfg.Target, fmt.Sprintf("%s:%s at %s", c.Username, c.Password, c.URL))
}
}
}

func (e *Engine) ntfyCfg() notify.Config {
nc := notify.Config{SlackWebhook: e.cfg.NotifySlack}
if e.cfg.NotifyTelegram != "" {
parts := strings.SplitN(e.cfg.NotifyTelegram, "@", 2)
if len(parts) == 2 {
nc.TelegramToken = parts[0]
nc.TelegramChatID = parts[1]
}
}
return nc
}

func baseURLs(res *Results) []string {
urls := make([]string, 0, len(res.HTTP))
for _, h := range res.HTTP {
urls = append(urls, h.URL)
}
return urls
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

func buildFindings(res *Results) []finding.Finding {
var out []finding.Finding
for _, v := range res.Vulns {
out = append(out, v.ToFinding())
}
for _, s := range res.SQLi {
if s.Detected {
out = append(out, s.ToFinding())
}
}
for _, c := range res.CORS {
if c.Vulnerable {
out = append(out, c.ToFinding())
}
}
for _, t := range res.Takeover {
if t.Vulnerable {
out = append(out, t.ToFinding())
}
}
for _, d := range res.DefaultCreds {
if d.Found {
out = append(out, d.ToFinding())
}
}
return out
}
