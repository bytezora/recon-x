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
	styleYellow = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFA502"))
	styleCyan   = lipgloss.NewStyle().Foreground(lipgloss.Color("#00B4D8")).Bold(true)
	styleMuted  = lipgloss.NewStyle().Foreground(lipgloss.Color("#8B949E"))
	styleBox    = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#30363D")).
			Padding(0, 1)
	styleHeader = lipgloss.NewStyle().
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
type StepDoneMsg struct{ Step int; Count int }
type DoneMsg struct{}

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
			{label: "passive      crt.sh + certspotter + alienvault"},
			{label: "subdomain    dns brute-force"},
			{label: "port         tcp scan + banner grab"},
			{label: "http         fingerprint + waf + cve match"},
			{label: "dir          path brute-force"},
			{label: "js           endpoint & secret extraction"},
			{label: "github       code search dorking"},
			{label: "buckets      s3 / gcs / azure exposure"},
			{label: "tls          cert expiry + cipher check"},
			{label: "redirect     open redirect (22 params)"},
			{label: "axfr         dns zone transfer"},
			{label: "whois        registrar + org lookup"},
			{label: "screenshot   headless capture"},
			{label: "takeover     dangling cname check"},
			{label: "cors         origin reflection"},
			{label: "bypass       403 path + header tricks"},
			{label: "vhost        host header brute-force"},
			{label: "favicon      murmurhash3 fingerprint"},
			{label: "asn          bgp prefix lookup"},
			{label: "graphql      introspection probe"},
			{label: "email        spf / dmarc / dkim"},
			{label: "admin        panel path discovery"},
			{label: "sqli         error-based + time-based"},
			{label: "creds        default credential check"},
			{label: "ratelimit    header detection"},
			{label: "templates    54 built-in + custom yaml"},
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
	b.WriteString(styleHeader.Render(
		fmt.Sprintf(" ◈ recon-x  ─  %s ", styleYellow.Render(m.target)),
	))
	b.WriteString("\n\n")

	cols := 2
	total := len(m.steps)
	half := (total + 1) / 2

	for i := 0; i < half; i++ {
		left := m.steps[i]
		leftIcon, leftLabel := stepDisplay(left, i, m.spinner)
		leftCount := ""
		if left.state == stepDone {
			leftCount = styleMuted.Render(fmt.Sprintf(" [%d]", left.count))
		}

		line := fmt.Sprintf("  %s  %02d  %s%s", leftIcon, i+1, leftLabel, leftCount)

		j := i + half
		if j < total {
			right := m.steps[j]
			rightIcon, rightLabel := stepDisplay(right, j, m.spinner)
			rightCount := ""
			if right.state == stepDone {
				rightCount = styleMuted.Render(fmt.Sprintf(" [%d]", right.count))
			}
			rightPart := fmt.Sprintf("  %s  %02d  %s%s", rightIcon, j+1, rightLabel, rightCount)
			_ = cols
			b.WriteString(fmt.Sprintf("%-54s%s\n", line, rightPart))
		} else {
			b.WriteString(line + "\n")
		}
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
		b.WriteString("\n  " + styleGreen.Render("◆  done") + "\n")
	} else {
		b.WriteString("\n  " + styleMuted.Render("ctrl+c to quit") + "\n")
	}

	return b.String()
}

func stepDisplay(s step, _ int, sp spinner.Model) (icon, label string) {
	switch s.state {
	case stepPending:
		return styleMuted.Render("·"), styleMuted.Render(s.label)
	case stepRunning:
		return sp.View(), styleCyan.Render(s.label)
	case stepDone:
		return styleGreen.Render("✓"), styleGreen.Render(s.label)
	}
	return styleMuted.Render("·"), styleMuted.Render(s.label)
}
