// Package bundle consolidates the individually gathered diagnostic signals
// into a single report (CLI-1576). The rendered report is the core MVP
// deliverable: it must be useful to a human (Support ticket attachment) on
// its own, and the same rendering (without color) is what gets handed to
// the LLM for the diagnosis pass — the aligned console layout is both
// copy-paste friendly and cheaper in tokens than JSON.
//
// The visual language mirrors the CLI's finding templates
// (internal/presenters/templates): bold section titles, ` ✗ [KIND] Title`
// blocks with indented "Label: value" properties, blank lines between
// blocks.
package bundle

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

type Event struct {
	Line    int
	Kind    string
	Message string // normalized message used for grouping and display
}

type SignalStatus string

const (
	SignalOK     SignalStatus = "ok"
	SignalFailed SignalStatus = "failed"
)

// Signal records the outcome of one live check. Failures are recorded,
// never fatal: a failing check is itself one of the strongest diagnostic
// signals.
type Signal struct {
	Status  SignalStatus
	Summary string // value for the check's main property, e.g. the username
	Detail  string // optional error text when the check failed
}

// HostFailureGroup collects hosts that failed the same way; when the proxy
// or firewall is the problem, all 16 endpoints fail identically and one
// line tells the story.
type HostFailureGroup struct {
	Status string // "BLOCKED", "TIMEOUT", ...
	Hosts  []string
}

// Warning is a WARN/FAIL item from the check's TODO list, deduplicated
// across hosts.
type Warning struct {
	Message string
	Similar int // additional near-identical warnings folded into this one
}

// ConnectivitySummary is the doctor-owned digest of the connectivity-check
// result: reachable-host counts and exceptions instead of the full table.
type ConnectivitySummary struct {
	Failed      bool   // the check itself could not run
	FailureText string // why, when Failed

	Proxy         string // human line, e.g. "none detected"
	HostsOK       int
	HostsTotal    int
	FailureGroups []HostFailureGroup
	TokenPresent  bool
	OrgCount      int
	Organizations []string // display lines, capped by the gatherer; default first
	Warnings      []Warning
}

type DiagnosticBundle struct {
	Header       string
	Footer       string
	Events       []Event
	WhoAmI       Signal
	Connectivity ConnectivitySummary
}

// Styles carries the color treatments; identity functions when color is off
// so the layout is byte-identical with and without color.
type Styles struct {
	Bold func(string) string
	Dim  func(string) string
	Bad  func(string) string
	Good func(string) string
	Warn func(string) string
}

func NewStyles(color bool) Styles {
	if !color {
		identity := func(s string) string { return s }
		return Styles{Bold: identity, Dim: identity, Bad: identity, Good: identity, Warn: identity}
	}
	return Styles{
		Bold: styleFunc(lipgloss.NewStyle().Bold(true)),
		Dim:  styleFunc(lipgloss.NewStyle().Foreground(lipgloss.Color("8"))),
		Bad:  styleFunc(lipgloss.NewStyle().Foreground(lipgloss.Color("1"))),
		Good: styleFunc(lipgloss.NewStyle().Foreground(lipgloss.Color("2"))),
		Warn: styleFunc(lipgloss.NewStyle().Foreground(lipgloss.Color("3"))),
	}
}

func styleFunc(style lipgloss.Style) func(string) string {
	return func(s string) string { return style.Render(s) }
}

const wrapWidth = 100

// Section starts a new titled section: bold title, blank line, like the
// finding templates' "Open Issues" / "Test Summary" headings.
func Section(sb *strings.Builder, title string, st Styles) {
	fmt.Fprintf(sb, "\n\n%s\n\n", st.Bold(title))
}

// Property is one "Label: value" row of a block.
type Property struct {
	Label string
	Value string
}

// WriteBlockHeader writes the ` ✗ [KIND] Title` line of a finding-style block.
func WriteBlockHeader(sb *strings.Builder, mark, kind, title string, st Styles) {
	fmt.Fprintf(sb, " %s %s %s\n", mark, kind, st.Bold(title))
}

// WriteProperties writes aligned "Label: value" rows indented under a block
// header, padding labels to the widest like the finding presenter does.
func WriteProperties(sb *strings.Builder, properties []Property, st Styles) {
	width := 0
	for _, p := range properties {
		if len(p.Label)+1 > width {
			width = len(p.Label) + 1
		}
	}
	for _, p := range properties {
		fmt.Fprintf(sb, "   %-*s %s\n", width, p.Label+":", p.Value)
	}
}

// WriteWrapped emits text word-wrapped at the package width, with the first
// line prefixed and continuation lines aligned under it.
func WriteWrapped(sb *strings.Builder, text, firstPrefix, contPrefix string) {
	line, lineLen, started := firstPrefix, len(firstPrefix), false
	for _, word := range strings.Fields(text) {
		if started && lineLen+len(word)+1 > wrapWidth {
			sb.WriteString(line + "\n")
			line, lineLen, started = contPrefix, len(contPrefix), false
		}
		if started {
			line += " "
			lineLen++
		}
		line += word
		lineLen += len(word)
		started = true
	}
	sb.WriteString(line + "\n")
}

// Render produces the consolidated report in the CLI console style. The
// color=false rendering is the LLM input and the ticket-attachable form.
func (b *DiagnosticBundle) Render(color bool) string {
	st := NewStyles(color)
	var sb strings.Builder

	fmt.Fprintf(&sb, "%s\n", st.Bold("Snyk Doctor Diagnostic Report"))

	Section(&sb, "Environment", st)
	writeBlock(&sb, b.Header, "not found in the provided log")

	Section(&sb, "Notable Events", st)
	b.writeEvents(&sb, st)

	Section(&sb, "Result", st)
	writeBlock(&sb, b.Footer, "not found in the provided log")

	Section(&sb, "Live Checks", st)
	b.writeLiveChecks(&sb, st)

	return sb.String()
}

// RenderLiveChecks renders only the live-checks digest; used in diagnosis
// mode, where the full report is omitted from the terminal output.
func (b *DiagnosticBundle) RenderLiveChecks(color bool) string {
	st := NewStyles(color)
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s\n\n", st.Bold("Live Checks"))
	b.writeLiveChecks(&sb, st)
	return sb.String()
}

func (b *DiagnosticBundle) writeLiveChecks(sb *strings.Builder, st Styles) {
	writeWhoAmI(sb, b.WhoAmI, st)
	sb.WriteString("\n")
	writeConnectivity(sb, b.Connectivity, st)
}

func writeBlock(sb *strings.Builder, content, emptyNote string) {
	if content == "" {
		fmt.Fprintf(sb, "  (%s)\n", emptyNote)
		return
	}
	for _, line := range strings.Split(content, "\n") {
		fmt.Fprintf(sb, "  %s\n", strings.TrimRight(line, " "))
	}
}

type eventGroup struct {
	Event
	count     int
	firstLine int
	lastLine  int
}

// groupEvents collapses identical normalized messages (retry storms produce
// dozens of identical 401 triplets) into one entry with an occurrence count.
func groupEvents(events []Event) []*eventGroup {
	var groups []*eventGroup
	index := map[string]*eventGroup{}
	for _, e := range events {
		key := e.Kind + "\x00" + e.Message
		if g, ok := index[key]; ok {
			g.count++
			g.lastLine = e.Line
			continue
		}
		g := &eventGroup{Event: e, count: 1, firstLine: e.Line, lastLine: e.Line}
		index[key] = g
		groups = append(groups, g)
	}
	return groups
}

func (b *DiagnosticBundle) writeEvents(sb *strings.Builder, st Styles) {
	groups := groupEvents(b.Events)
	if len(groups) == 0 {
		sb.WriteString("  No failing requests or error/warn entries found in the log body.\n")
		return
	}
	fmt.Fprintf(sb, "  %s\n", st.Dim(fmt.Sprintf("%d log entries, %d distinct", len(b.Events), len(groups))))

	for _, g := range groups {
		kindColor := st.Bad
		if g.Kind == "warn" {
			kindColor = st.Warn
		}
		sb.WriteString("\n")
		WriteBlockHeader(sb, st.Bad("✗"), kindColor("["+strings.ToUpper(g.Kind)+"]"), g.Message, st)

		occurrence := fmt.Sprintf("line %d", g.firstLine)
		if g.count > 1 {
			occurrence = fmt.Sprintf("%d, lines %d-%d", g.count, g.firstLine, g.lastLine)
		}
		WriteProperties(sb, []Property{{"Occurrences", occurrence}}, st)
	}
}

func writeWhoAmI(sb *strings.Builder, s Signal, st Styles) {
	if s.Status != SignalOK {
		WriteBlockHeader(sb, st.Bad("✗"), st.Bad("[FAILED]"), "Authentication", st)
		WriteProperties(sb, []Property{{"Info", s.Summary}}, st)
		if s.Detail != "" {
			WriteWrapped(sb, s.Detail, "   Error: ", "          ")
		}
		return
	}
	WriteBlockHeader(sb, st.Good("✓"), st.Good("[OK]"), "Authentication", st)
	WriteProperties(sb, []Property{{"User", s.Summary}}, st)
}

func writeConnectivity(sb *strings.Builder, c ConnectivitySummary, st Styles) {
	if c.Failed {
		WriteBlockHeader(sb, st.Bad("✗"), st.Bad("[FAILED]"), "Connectivity", st)
		WriteProperties(sb, []Property{{"Info", "the connectivity check could not run"}}, st)
		WriteWrapped(sb, c.FailureText, "   Error: ", "          ")
		return
	}

	mark, kind := st.Good("✓"), st.Good("[OK]")
	if len(c.FailureGroups) > 0 {
		mark, kind = st.Bad("✗"), st.Bad("[FAILED]")
	}
	WriteBlockHeader(sb, mark, kind, "Connectivity", st)

	properties := []Property{{"Endpoints", fmt.Sprintf("%d/%d reachable", c.HostsOK, c.HostsTotal)}}
	for _, group := range c.FailureGroups {
		properties = append(properties, Property{"Failed", describeFailureGroup(group, c.HostsTotal)})
	}
	properties = append(properties, Property{"Proxy", c.Proxy})

	token := st.Good("configured")
	if !c.TokenPresent {
		token = st.Bad("not configured")
	}
	properties = append(properties, Property{"Token", token})

	properties = append(properties, Property{"Organizations", fmt.Sprintf("%d accessible", c.OrgCount)})
	WriteProperties(sb, properties, st)
	for _, org := range c.Organizations {
		fmt.Fprintf(sb, "     %s %s\n", st.Dim("-"), org)
	}

	for _, warning := range c.Warnings {
		message := warning.Message
		if warning.Similar > 0 {
			message += fmt.Sprintf(" (+%d similar)", warning.Similar)
		}
		sb.WriteString("\n")
		WriteWrapped(sb, message, "   "+st.Warn("⚠")+" ", "     ")
	}
}

func describeFailureGroup(group HostFailureGroup, total int) string {
	switch {
	case len(group.Hosts) == total:
		return fmt.Sprintf("all %d endpoints %s", total, group.Status)
	case len(group.Hosts) <= 3:
		return fmt.Sprintf("%s: %s", strings.Join(group.Hosts, ", "), group.Status)
	default:
		return fmt.Sprintf("%d endpoints %s (%s, +%d more)",
			len(group.Hosts), group.Status, strings.Join(group.Hosts[:2], ", "), len(group.Hosts)-2)
	}
}
