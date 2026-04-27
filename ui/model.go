package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	stylePurple = lipgloss.NewStyle().Foreground(lipgloss.Color("#7C3AED")).Bold(true)
	styleGreen  = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF87")).Bold(true)
	styleYellow = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFA502")).Bold(true)
	styleCyan   = lipgloss.NewStyle().Foreground(lipgloss.Color("#00B4D8")).Bold(true)
	styleMuted  = lipgloss.NewStyle().Foreground(lipgloss.Color("#8B949E"))
	styleWhite  = lipgloss.NewStyle().Foreground(lipgloss.Color("#E6EDF3")).Bold(true)
	styleBox    = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#30363D")).
			Padding(0, 1)
	styleColLeft = lipgloss.NewStyle().Width(52)
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

const maxItems = 12

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

	b.WriteString("\n")
	b.WriteString(
		"  " +
			stylePurple.Render("◆") + " " +
			styleWhite.Render("recon-x") +
			styleMuted.Render(" — ") +
			styleYellow.Render(m.target),
	)
	b.WriteString("\n\n")

	total := len(m.steps)
	half := (total + 1) / 2

	for i := 0; i < half; i++ {
		leftLine := renderStep(m.steps[i], i, m.spinner)
		left := styleColLeft.Render(leftLine)

		j := i + half
		if j < total {
			rightLine := renderStep(m.steps[j], j, m.spinner)
			b.WriteString("  " + left + "  " + rightLine + "\n")
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
		b.WriteString("\n  " + styleGreen.Render("◆  done") + "\n")
	} else {
		b.WriteString("\n  " + styleMuted.Render("ctrl+c to quit") + "\n")
	}

	return b.String()
}

func renderStep(s step, idx int, sp spinner.Model) string {
	num := styleCyan.Render(fmt.Sprintf("%02d", idx+1))
	cnt := ""
	if s.state == stepDone && s.count > 0 {
		cnt = styleMuted.Render(fmt.Sprintf(" [%d]", s.count))
	}

	switch s.state {
	case stepRunning:
		return sp.View() + "  " + num + "  " +
			styleCyan.Render(s.name) + "  " +
			styleCyan.Render(s.desc)
	case stepDone:
		return styleGreen.Render("✓") + "  " + num + "  " +
			styleGreen.Render(s.name) + "  " +
			styleMuted.Render(s.desc) + cnt
	default:
		return styleMuted.Render("·") + "  " + num + "  " +
			styleYellow.Render(s.name) + "  " +
			styleMuted.Render(s.desc)
	}
}
