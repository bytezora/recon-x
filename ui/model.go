package ui

import (
"fmt"
"strings"

"github.com/charmbracelet/bubbles/spinner"
tea "github.com/charmbracelet/bubbletea"
"github.com/charmbracelet/lipgloss"
)

var (
stylePurple   = lipgloss.NewStyle().Foreground(lipgloss.Color("#7C3AED")).Bold(true)
styleGreen    = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF87")).Bold(true)
styleGreenDim = lipgloss.NewStyle().Foreground(lipgloss.Color("#00CC70"))
styleYellow   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFA502")).Bold(true)
styleCyan     = lipgloss.NewStyle().Foreground(lipgloss.Color("#00B4D8")).Bold(true)
styleMuted    = lipgloss.NewStyle().Foreground(lipgloss.Color("#8B949E"))
styleDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("#3D4450"))
styleWhite    = lipgloss.NewStyle().Foreground(lipgloss.Color("#E6EDF3")).Bold(true)
styleBox      = lipgloss.NewStyle().
Border(lipgloss.RoundedBorder()).
BorderForeground(lipgloss.Color("#7C3AED")).
Padding(0, 1)
styleColLeft = lipgloss.NewStyle().Width(54)
)

type ItemMsg struct {
Icon string
Text string
}

type StepStartMsg int
type StepDoneMsg struct {
Step  int
Count int
}
type DoneMsg struct{}

type stepState int

const (
stepPending stepState = iota
stepRunning
stepDone
)

type step struct {
name  string
desc  string
state stepState
count int
}

const maxItems = 10

type Model struct {
target  string
steps   []step
items   []string
spinner spinner.Model
done    bool
width   int
}

func New(target string) Model {
sp := spinner.New()
sp.Spinner = spinner.Dot
sp.Style = stylePurple

return Model{
target: target,
steps: []step{
{name: "passive", desc: "crt.sh + certspotter + alienvault"},
{name: "subdomain", desc: "dns brute-force"},
{name: "port", desc: "tcp scan + banner grab"},
{name: "http", desc: "fingerprint + waf + cve match"},
{name: "dir", desc: "path brute-force"},
{name: "js", desc: "endpoint & secret extraction"},
{name: "github", desc: "code search dorking"},
{name: "buckets", desc: "s3 / gcs / azure exposure"},
{name: "tls", desc: "cert expiry + cipher check"},
{name: "redirect", desc: "open redirect (22 params)"},
{name: "axfr", desc: "dns zone transfer"},
{name: "whois", desc: "registrar + org lookup"},
{name: "screenshot", desc: "headless capture"},
{name: "takeover", desc: "dangling cname check"},
{name: "cors", desc: "origin reflection"},
{name: "bypass", desc: "403 path + header tricks"},
{name: "vhost", desc: "host header brute-force"},
{name: "favicon", desc: "murmurhash3 fingerprint"},
{name: "asn", desc: "bgp prefix lookup"},
{name: "graphql", desc: "introspection probe"},
{name: "email", desc: "spf / dmarc / dkim"},
{name: "admin", desc: "panel path discovery"},
{name: "sqli", desc: "error-based + time-based"},
{name: "creds", desc: "default credential check"},
{name: "ratelimit", desc: "header detection"},
{name: "templates", desc: "54 built-in + custom yaml"},
},
spinner: sp,
width:   80,
}
}

func (m Model) Init() tea.Cmd {
return m.spinner.Tick
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
switch msg := msg.(type) {

case tea.WindowSizeMsg:
m.width = msg.Width

case tea.KeyMsg:
if msg.String() == "q" || msg.String() == "ctrl+c" {
return m, tea.Quit
}

case spinner.TickMsg:
var cmd tea.Cmd
m.spinner, cmd = m.spinner.Update(msg)
return m, cmd

case StepStartMsg:
idx := int(msg)
if idx < len(m.steps) {
m.steps[idx].state = stepRunning
}

case StepDoneMsg:
if msg.Step < len(m.steps) {
m.steps[msg.Step].state = stepDone
m.steps[msg.Step].count = msg.Count
}

case ItemMsg:
line := msg.Icon + " " + msg.Text
m.items = append(m.items, line)
if len(m.items) > maxItems {
m.items = m.items[len(m.items)-maxItems:]
}

case DoneMsg:
m.done = true
return m, tea.Quit
}

return m, nil
}

func (m Model) View() string {
var b strings.Builder

done := 0
for _, s := range m.steps {
if s.state == stepDone {
done++
}
}
total := len(m.steps)

b.WriteString("\n")

bar := renderBar(done, total, 18)
progress := bar + "  " +
styleCyan.Render(fmt.Sprintf("%d", done)) +
styleMuted.Render(fmt.Sprintf("/%d", total))

sep := styleDim.Render("────")
b.WriteString(
"  " + stylePurple.Render("◆") + "  " +
styleWhite.Render("recon-x") + "  " +
sep + "  " +
styleYellow.Render(m.target) + "  " +
sep + "  " +
progress + "\n",
)
b.WriteString("  " + styleDim.Render(strings.Repeat("─", 72)) + "\n\n")

half := (total + 1) / 2
div := styleDim.Render("│")

for i := 0; i < half; i++ {
leftLine := renderStep(m.steps[i], i, m.spinner)
left := styleColLeft.Render(leftLine)

j := i + half
if j < total {
rightLine := renderStep(m.steps[j], j, m.spinner)
b.WriteString("  " + left + " " + div + "  " + rightLine + "\n")
} else {
b.WriteString("  " + leftLine + "\n")
}
}

b.WriteString("\n")

if len(m.items) > 0 {
lines := make([]string, len(m.items))
for i, item := range m.items {
lines[i] = "  " + item
}
b.WriteString(styleBox.Render(strings.Join(lines, "\n")))
b.WriteString("\n")
}

if m.done {
b.WriteString("\n  " + stylePurple.Render("◆") + "  " +
styleGreen.Render("scan complete") + "  " +
styleMuted.Render("·") + "  " +
styleMuted.Render("report saved") + "\n")
} else {
b.WriteString("\n  " + styleDim.Render("ctrl+c to quit") + "\n")
}

return b.String()
}

func renderBar(done, total, width int) string {
if total == 0 {
return ""
}
filled := int(float64(done) / float64(total) * float64(width))
if filled > width {
filled = width
}
f := styleGreen.Render(strings.Repeat("█", filled))
e := styleDim.Render(strings.Repeat("░", width-filled))
return styleDim.Render("[") + f + e + styleDim.Render("]")
}

func renderStep(s step, idx int, sp spinner.Model) string {
num := styleCyan.Render(fmt.Sprintf("%02d", idx+1))

switch s.state {
case stepRunning:
return sp.View() + "  " + num + "  " +
styleCyan.Render(s.name) + "  " +
styleCyan.Render(s.desc)

case stepDone:
cnt := ""
if s.count > 0 {
cnt = "  " + styleGreenDim.Render(fmt.Sprintf("·%d", s.count))
}
return styleGreen.Render("✓") + "  " + num + "  " +
styleGreen.Render(s.name) + "  " +
styleMuted.Render(s.desc) + cnt

default:
return styleDim.Render("·") + "  " + num + "  " +
styleYellow.Render(s.name) + "  " +
styleMuted.Render(s.desc)
}
}
