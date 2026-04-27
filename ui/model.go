// Package ui provides the bubbletea TUI for recon-x.
package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	stylePurple  = lipgloss.NewStyle().Foreground(lipgloss.Color("#7C3AED")).Bold(true)
	styleGreen   = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF87")).Bold(true)
	styleYellow  = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFA502"))
	styleCyan= lipgloss.NewStyle().Foreground(lipgloss.Color("#00B4D8")).Bold(true)
	styleMuted   = lipgloss.NewStyle().Foreground(lipgloss.Color("#8B949E"))
	styleBox     = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#30363D")).
			Padding(0, 1)
	styleHeader  = lipgloss.NewStyle().
			Background(lipgloss.Color("#161B22")).
			Foreground(lipgloss.Color("#7C3AED")).
			Bold(true).
			Padding(0, 2)
)

type ItemMsg struct {
	Icon string
	Text string
}

type StepStartMsg int
type StepDoneMsg  struct{ Step int; Count int }
type DoneMsg      struct{}

type stepState int

const (
	stepPending stepState = iota
	stepRunning
	stepDone
)

type step struct {
	label string
	state stepState
	count int
}

const maxItems = 12

// Model is the bubbletea model for the recon-x TUI.
type Model struct {
	target  string
	steps   []step
	items   []string // recent found items (capped at maxItems)
	spinner spinner.Model
	done    bool
	width   int
}

// New creates a new TUI model for the given target.
func New(target string) Model {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = stylePurple

	return Model{
		target: target,
		steps: []step{
			{label: "Passive recon    (crt.sh)"},
			{label: "DNS brute-force  (wordlist)"},
			{label: "Port scan        (TCP + CVE)"},
			{label: "HTTP fingerprint (WAF detect)"},
			{label: "Directory brute  (path enum)"},
			{label: "JS scraping      (secrets)"},
			{label: "GitHub dorking   (secrets)"},
			{label: "Cloud buckets    (S3/GCS/Azure)"},
			{label: "TLS analysis     (certs)"},
			{label: "Open redirect    (params)"},
			{label: "DNS zone AXFR    (nameservers)"},
			{label: "WHOIS lookup     (registrar)"},
			{label: "Screenshots      (headless)"},
			{label: "Subdomain takeover (CNAME check)"},
			{label: "CORS scan        (origin reflect)"},
			{label: "403 bypass       (path/header tricks)"},
			{label: "Vhost discovery  (Host brute)"},
			{label: "Favicon hash     (Shodan MurmurHash3)"},
			{label: "ASN lookup       (IP ranges)"},
			{label: "GraphQL probe    (introspection)"},
			{label: "Email security   (SPF/DMARC/DKIM)"},
			{label: "Admin panel      (path discovery)"},
			{label: "SQLi detection   (error-based)"},
			{label: "Default creds    (15 pairs)"},
			{label: "Rate limit       (header detect)"},
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

	b.WriteString(styleHeader.Render(
		fmt.Sprintf(" recon-x  ·  %s ", styleYellow.Render(m.target)),
	))
	b.WriteString("\n\n")

	for i, s := range m.steps {
		var icon, label string
		switch s.state {
		case stepPending:
			icon  = styleMuted.Render("○")
			label = styleMuted.Render(s.label)
		case stepRunning:
			icon  = m.spinner.View()
			label = styleCyan.Render(s.label)
		case stepDone:
			icon  = styleGreen.Render("✓")
			label = styleGreen.Render(s.label)
		}

		count := ""
		if s.state == stepDone {
			count = styleMuted.Render(fmt.Sprintf("  %d found", s.count))
		}

		b.WriteString(fmt.Sprintf("  %s  %02d. %s%s\n", icon, i+1, label, count))
	}

	b.WriteString("\n")

	if len(m.items) > 0 {
		lines := make([]string, len(m.items))
		for i, item := range m.items {
			lines[i] = "  " + item
		}
		content := strings.Join(lines, "\n")
		b.WriteString(styleBox.Render(content))
		b.WriteString("\n")
	}

	if m.done {
		b.WriteString("\n  " + styleGreen.Render("◆  Scan complete") + "\n")
	} else {
		b.WriteString("\n  " + styleMuted.Render("q / ctrl+c to quit") + "\n")
	}

	return b.String()
}
