// Package tui provides a reusable, keyboard-driven terminal menu built on
// Bubble Tea v2 and Lip Gloss v2.
//
// Features:
//   - Centered, responsive panel that scrolls when content overflows
//   - Compact list with a details panel for the highlighted item
//   - Section headers, disabled items, right-aligned item badges
//   - Number shortcuts (1-9), vim keys, PgUp/PgDn, Home/End
//   - Confirmation prompt for destructive actions
//   - Non-blocking actions with spinner and success/error status
//   - Safe glyphs on legacy Windows consoles (auto-detected)
//   - Panic-safe action execution and full theming
//
// Basic usage:
//
//	app := tui.New(tui.Config{Title: "My Tool", Version: "1.0.0", ShowNumbers: true})
//	app.AddSeparator("Section")
//	app.AddItem(tui.MenuItem{Title: "Check status", Description: "Runs a health check", Action: check})
//	app.AddItem(tui.MenuItem{Title: "Reset", Confirm: true, Action: reset})
//	app.AddSeparator("")
//	app.AddExitMenu("Quit")
//	if err := app.Run(); err != nil { log.Fatal(err) }
package tui

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

const (
	defaultWidth = 72
	minWidth     = 40

	// Horizontal chrome: border (2) + horizontal padding (4).
	horizontalChrome = 6
	// Vertical chrome: border (2) + vertical padding (2).
	verticalChrome = 4
	// Lines reserved for the details panel text.
	detailLines = 2
)

// Action is executed when the user selects a menu item.
// It runs off the UI goroutine, so long-running work will not freeze the menu.
// Avoid writing directly to stdout/stderr from an Action while the menu is
// active; return an error to report a failure.
type Action func() error

// MenuItem describes one selectable menu entry.
type MenuItem struct {
	Title string
	// Description is shown in the details panel while the item is highlighted.
	Description string
	// Disabled items are dimmed and skipped by navigation.
	Disabled bool
	// Exit closes the menu when selected. If Action is set it runs after the
	// UI has closed, on the normal terminal.
	Exit bool
	// Confirm asks the user to press "y" before running the action.
	Confirm bool
	// Separator renders a non-selectable section header (Title may be empty
	// for a plain rule).
	Separator bool
	Action    Action
}

func (i MenuItem) selectable() bool { return !i.Disabled && !i.Separator }

// Theme defines the colour palette. Empty fields fall back to defaults.
// Values are any colour string accepted by lipgloss.Color (hex, ANSI index).
type Theme struct {
	Accent     string
	Text       string
	Muted      string
	Disabled   string
	SelectedBg string
	SelectedFg string
	Border     string
	Success    string
	Error      string
	Warning    string
}

// DefaultTheme returns the built-in theme.
func DefaultTheme() Theme {
	return Theme{
		Accent:     "#7CDAFF",
		Text:       "#E6EDF3",
		Muted:      "#8B949E",
		Disabled:   "#5A6068",
		SelectedBg: "#1F6F9F",
		SelectedFg: "#FFFFFF",
		Border:     "#4A7896",
		Success:    "#56D364",
		Error:      "#FF7B72",
		Warning:    "#E3B341",
	}
}

func (t Theme) withDefaults() Theme {
	d := DefaultTheme()
	pick := func(v, def string) string {
		if strings.TrimSpace(v) == "" {
			return def
		}
		return v
	}
	return Theme{
		Accent:     pick(t.Accent, d.Accent),
		Text:       pick(t.Text, d.Text),
		Muted:      pick(t.Muted, d.Muted),
		Disabled:   pick(t.Disabled, d.Disabled),
		SelectedBg: pick(t.SelectedBg, d.SelectedBg),
		SelectedFg: pick(t.SelectedFg, d.SelectedFg),
		Border:     pick(t.Border, d.Border),
		Success:    pick(t.Success, d.Success),
		Error:      pick(t.Error, d.Error),
		Warning:    pick(t.Warning, d.Warning),
	}
}

// SymbolMode selects the glyph set used for spinner and status icons.
type SymbolMode int

const (
	// SymbolsAuto uses ASCII on legacy Windows consoles and Unicode elsewhere.
	SymbolsAuto SymbolMode = iota
	SymbolsUnicode
	SymbolsASCII
)

type symbols struct {
	cursor  string
	spinner []string
	success string
	failure string
	warning string
	info    string
}

func resolveSymbols(mode SymbolMode) symbols {
	if mode == SymbolsAuto {
		legacyWindows := runtime.GOOS == "windows" &&
			os.Getenv("WT_SESSION") == "" && os.Getenv("TERM_PROGRAM") == ""
		if legacyWindows {
			mode = SymbolsASCII
		} else {
			mode = SymbolsUnicode
		}
	}
	if mode == SymbolsASCII {
		return symbols{
			cursor:  ">",
			spinner: []string{"|", "/", "-", "\\"},
			success: "+", failure: "x", warning: "!", info: "-",
		}
	}
	return symbols{
		cursor:  "›",
		spinner: []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		success: "✔", failure: "✖", warning: "!", info: "•",
	}
}

// Config controls the terminal application's appearance and behaviour.
type Config struct {
	Title       string
	Subtitle    string
	Version     string
	Footer      string     // overrides the default key-hint footer
	Width       int        // maximum width; the UI shrinks on narrow terminals
	ShowNumbers bool       // number items and enable 1-9 shortcuts
	Theme       Theme      // optional; zero value uses DefaultTheme
	Symbols     SymbolMode // optional; default auto-detects
}

// App is a reusable interactive terminal application.
type App struct {
	config Config
	items  []MenuItem
}

// New creates an application with the supplied configuration.
func New(config Config) *App {
	if strings.TrimSpace(config.Title) == "" {
		config.Title = "Terminal Menu"
	}
	if config.Width <= 0 {
		config.Width = defaultWidth
	}
	if config.Width < minWidth {
		config.Width = minWidth
	}
	config.Theme = config.Theme.withDefaults()
	return &App{config: config}
}

// AddMenu registers a selectable menu item.
func (a *App) AddMenu(title string, action Action) {
	a.AddItem(MenuItem{Title: title, Action: action})
}

// AddExitMenu registers a menu item that exits the application.
func (a *App) AddExitMenu(title string) {
	a.AddItem(MenuItem{Title: title, Exit: true})
}

// AddSeparator registers a non-selectable section header. An empty label
// draws a plain rule.
func (a *App) AddSeparator(label string) {
	a.items = append(a.items, MenuItem{Title: strings.TrimSpace(label), Separator: true})
}

// AddItem registers a fully configured menu item. Items without a title
// are ignored unless they are separators.
func (a *App) AddItem(item MenuItem) {
	item.Title = strings.TrimSpace(item.Title)
	if item.Title == "" && !item.Separator {
		return
	}
	a.items = append(a.items, item)
}

// Run starts the interactive terminal application and blocks until it exits.
// A user interrupt (Ctrl+C) is treated as a normal exit and returns nil.
func (a *App) Run() error {
	selectable := false
	for _, it := range a.items {
		if it.selectable() {
			selectable = true
			break
		}
	}
	if !selectable {
		return errors.New("tui: no selectable menu items registered")
	}

	m := newModel(a.config, append([]MenuItem(nil), a.items...))
	final, err := tea.NewProgram(m).Run()
	if errors.Is(err, tea.ErrInterrupted) {
		return nil
	}
	if err != nil {
		return err
	}
	if fm, ok := final.(model); ok && fm.pending != nil {
		return fm.pending() // runs on the normal terminal, not inside the TUI
	}
	return nil
}

// ───────────────────────────── internals ─────────────────────────────

type statusKind int

const (
	statusNone statusKind = iota
	statusInfo
	statusSuccess
	statusError
	statusWarning
)

type actionFinishedMsg struct {
	title string
	err   error
}

type spinnerTickMsg struct{}

func spinnerTick() tea.Cmd {
	return tea.Tick(80*time.Millisecond, func(time.Time) tea.Msg { return spinnerTickMsg{} })
}

// safeRun executes an action and converts panics into errors so a faulty
// action can never crash the terminal UI.
func safeRun(a Action) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return a()
}

type styles struct {
	title     lipgloss.Style
	muted     lipgloss.Style
	text      lipgloss.Style
	selected  lipgloss.Style
	disabled  lipgloss.Style
	separator lipgloss.Style
	success   lipgloss.Style
	err       lipgloss.Style
	warning   lipgloss.Style
	accent    lipgloss.Style
	key       lipgloss.Style
	frame     lipgloss.Style
}

func newStyles(t Theme) styles {
	c := lipgloss.Color
	return styles{
		title:     lipgloss.NewStyle().Bold(true).Foreground(c(t.Accent)),
		muted:     lipgloss.NewStyle().Foreground(c(t.Muted)),
		text:      lipgloss.NewStyle().Foreground(c(t.Text)),
		selected:  lipgloss.NewStyle().Bold(true).Foreground(c(t.SelectedFg)).Background(c(t.SelectedBg)),
		disabled:  lipgloss.NewStyle().Foreground(c(t.Disabled)),
		separator: lipgloss.NewStyle().Bold(true).Foreground(c(t.Accent)),
		success:   lipgloss.NewStyle().Foreground(c(t.Success)),
		err:       lipgloss.NewStyle().Foreground(c(t.Error)),
		warning:   lipgloss.NewStyle().Foreground(c(t.Warning)),
		accent:    lipgloss.NewStyle().Foreground(c(t.Accent)),
		key:       lipgloss.NewStyle().Bold(true).Foreground(c(t.Text)),
		frame: lipgloss.NewStyle().
			Padding(1, 2).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(c(t.Border)),
	}
}

type model struct {
	config Config
	items  []MenuItem
	styles styles
	sym    symbols

	numbers  []int // item index -> display number (0 = unnumbered)
	numWidth int

	cursor int
	offset int // first visible item index

	width, height int

	status     string
	statusKind statusKind

	running    bool
	confirming bool
	frame      int
	pending    Action // run by Run() after the UI has closed
}

func newModel(cfg Config, items []MenuItem) model {
	m := model{
		config:  cfg,
		items:   items,
		styles:  newStyles(cfg.Theme),
		sym:     resolveSymbols(cfg.Symbols),
		numbers: make([]int, len(items)),
	}
	n := 0
	for i, it := range items {
		if !it.Separator && !it.Exit {
			n++
			m.numbers[i] = n
		}
	}
	m.numWidth = len(fmt.Sprint(n))
	m.cursor = m.firstSelectable()
	return m
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.ensureVisible()
		return m, nil

	case spinnerTickMsg:
		if !m.running {
			return m, nil
		}
		m.frame = (m.frame + 1) % len(m.sym.spinner)
		return m, spinnerTick()

	case actionFinishedMsg:
		m.running = false
		if msg.err != nil {
			m.setStatus(statusError, fmt.Sprintf("%s failed: %v", msg.title, msg.err))
		} else {
			m.setStatus(statusSuccess, msg.title+" completed")
		}
		return m, nil

	case tea.KeyPressMsg:
		return m.handleKey(msg.String())
	}
	return m, nil
}

func (m model) handleKey(key string) (tea.Model, tea.Cmd) {
	if key == "ctrl+c" {
		return m, tea.Quit
	}

	// While an action runs, the UI is locked (except Ctrl+C) to prevent
	// accidental double execution.
	if m.running {
		return m, nil
	}

	// Pending confirmation: "y" proceeds, anything else cancels.
	if m.confirming {
		m.confirming = false
		if key == "y" || key == "Y" {
			return m.execute(m.items[m.cursor])
		}
		m.setStatus(statusInfo, "Cancelled")
		return m, nil
	}

	switch key {
	case "q", "esc":
		return m, tea.Quit

	case "up", "k":
		m.cursor = m.nextSelectable(m.cursor, -1)
	case "down", "j":
		m.cursor = m.nextSelectable(m.cursor, 1)
	case "home", "g":
		m.cursor = m.firstSelectable()
	case "end", "G":
		m.cursor = m.lastSelectable()
	case "pgup":
		m.cursor = m.stepSelectable(m.cursor, -m.pageSize())
	case "pgdown":
		m.cursor = m.stepSelectable(m.cursor, m.pageSize())

	case "enter", "space", "right", "l":
		return m.activate(m.cursor)

	default:
		if m.config.ShowNumbers && len(key) == 1 && key[0] >= '1' && key[0] <= '9' {
			target := int(key[0] - '0')
			for i, n := range m.numbers {
				if n == target && m.items[i].selectable() {
					m.cursor = i
					m.ensureVisible()
					return m.activate(i)
				}
			}
		}
		return m, nil
	}

	if m.statusKind != statusError { // keep errors visible until the next action
		m.setStatus(statusNone, "")
	}
	m.ensureVisible()
	return m, nil
}

func (m model) activate(i int) (tea.Model, tea.Cmd) {
	if i < 0 || i >= len(m.items) || !m.items[i].selectable() {
		return m, nil
	}
	item := m.items[i]

	if item.Exit {
		m.pending = item.Action // nil for a plain "Quit" item
		return m, tea.Quit
	}
	if item.Confirm && item.Action != nil {
		m.confirming = true
		m.setStatus(statusWarning, fmt.Sprintf("Run %q? Press y to confirm.", item.Title))
		return m, nil
	}
	return m.execute(item)
}

func (m model) execute(item MenuItem) (tea.Model, tea.Cmd) {
	if item.Action == nil {
		m.setStatus(statusInfo, "Selected: "+item.Title)
		return m, nil
	}
	m.running = true
	m.frame = 0
	m.setStatus(statusInfo, "Running "+item.Title+"…")

	run := func() tea.Msg {
		return actionFinishedMsg{title: item.Title, err: safeRun(item.Action)}
	}
	return m, tea.Batch(run, spinnerTick())
}

func (m *model) setStatus(k statusKind, s string) {
	m.statusKind, m.status = k, s
}

// ───────────── navigation helpers ─────────────

func (m model) firstSelectable() int {
	for i, it := range m.items {
		if it.selectable() {
			return i
		}
	}
	return 0
}

func (m model) lastSelectable() int {
	for i := len(m.items) - 1; i >= 0; i-- {
		if m.items[i].selectable() {
			return i
		}
	}
	return 0
}

// nextSelectable moves one step in direction (±1), wrapping and skipping
// disabled items and separators.
func (m model) nextSelectable(from, direction int) int {
	n := len(m.items)
	if n == 0 {
		return 0
	}
	i := from
	for range n {
		i = (i + direction + n) % n
		if m.items[i].selectable() {
			return i
		}
	}
	return from
}

// stepSelectable moves by up to |steps| selectable items without wrapping.
func (m model) stepSelectable(from, steps int) int {
	dir := 1
	if steps < 0 {
		dir, steps = -1, -steps
	}
	cur := from
	for ; steps > 0; steps-- {
		next := cur + dir
		for next >= 0 && next < len(m.items) && !m.items[next].selectable() {
			next += dir
		}
		if next < 0 || next >= len(m.items) {
			break
		}
		cur = next
	}
	return cur
}

func (m model) pageSize() int {
	if p := m.bodyHeight() / 2; p > 1 {
		return p
	}
	return 1
}

// ───────────── layout helpers ─────────────

func (m model) viewWidth() int {
	w := m.config.Width
	if m.width > 0 && m.width < w {
		w = m.width
	}
	return w
}

func (m model) innerWidth() int {
	if w := m.viewWidth() - horizontalChrome; w > 10 {
		return w
	}
	return 10
}

func (m model) headerLines() int {
	n := 3 // title + rule + blank
	if m.config.Subtitle != "" {
		n++
	}
	return n
}

// bodyHeight is how many lines are available for menu items.
func (m model) bodyHeight() int {
	if m.height <= 0 {
		return 1 << 20 // unknown size: don't constrain
	}
	// header + 2 scroll indicators + details (rule + text) + status + footer (blank + line)
	overhead := verticalChrome + m.headerLines() + 2 + (1 + detailLines) + 1 + 2
	if h := m.height - overhead; h > 3 {
		return h
	}
	return 3
}

// itemLines is how many terminal lines item i occupies.
func (m model) itemLines(i int) int {
	it := m.items[i]
	if it.Separator && it.Title != "" && i > 0 {
		return 2 // blank spacer + header
	}
	return 1
}

// ensureVisible adjusts the scroll offset so the cursor is on screen.
func (m *model) ensureVisible() {
	if len(m.items) == 0 {
		return
	}
	body := m.bodyHeight()

	// Keep leading separators visible when the cursor is on the first entry.
	if m.cursor == m.firstSelectable() {
		m.offset = 0
		return
	}
	if m.cursor < m.offset {
		m.offset = m.cursor
		return
	}
	for m.offset < m.cursor {
		used := 0
		for i := m.offset; i <= m.cursor; i++ {
			used += m.itemLines(i)
		}
		if used <= body {
			break
		}
		m.offset++
	}
}

// ───────────── rendering ─────────────

func truncate(s string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max == 1 {
		return "…"
	}
	return string(r[:max-1]) + "…"
}

func spaces(n int) string {
	if n < 0 {
		n = 0
	}
	return strings.Repeat(" ", n)
}

func (m model) rule(n int) string {
	return m.styles.muted.Render(strings.Repeat("─", n))
}

func (m model) renderItem(i, inner int) []string {
	item, st := m.items[i], m.styles

	if item.Separator {
		if item.Title == "" {
			return []string{m.rule(inner)}
		}
		label := strings.ToUpper(item.Title)
		line := st.separator.Render(label) + " " + m.rule(inner-lipgloss.Width(label)-1)
		if i > 0 {
			return []string{"", line}
		}
		return []string{line}
	}

	selected := i == m.cursor
	cursor := "  "
	if selected {
		cursor = m.sym.cursor + " "
	}

	num := ""
	if m.config.ShowNumbers {
		if m.numbers[i] > 0 {
			num = fmt.Sprintf("%*d", m.numWidth, m.numbers[i])
		} else {
			num = spaces(m.numWidth)
		}
		num += "  "
	}

	hint := ""
	switch {
	case item.Disabled:
		hint = "unavailable"
	case item.Exit:
		hint = "q"
	case item.Confirm:
		hint = "confirm"
	}
	hintW := lipgloss.Width(hint)
	reserve := hintW
	if hint != "" {
		reserve++ // one space gap before the hint
	}

	title := truncate(item.Title, inner-lipgloss.Width(cursor)-lipgloss.Width(num)-reserve)
	pad := inner - lipgloss.Width(cursor) - lipgloss.Width(num) - lipgloss.Width(title) - hintW

	switch {
	case selected:
		plain := cursor + num + title + spaces(pad) + hint
		return []string{st.selected.Width(inner).Render(plain)}
	case item.Disabled:
		plain := cursor + num + title + spaces(pad) + hint
		return []string{st.disabled.Render(plain)}
	default:
		return []string{cursor + st.muted.Render(num) + st.text.Render(title) + spaces(pad) + st.muted.Render(hint)}
	}
}

func (m model) renderDetails(inner int) string {
	desc := ""
	if m.cursor >= 0 && m.cursor < len(m.items) {
		desc = m.items[m.cursor].Description
	}
	return m.styles.muted.Width(inner).Height(detailLines).MaxHeight(detailLines).Render(desc)
}

func (m model) renderStatus(inner int) string {
	st := m.styles
	text := truncate(m.status, inner-2)
	if m.running {
		return st.accent.Render(m.sym.spinner[m.frame%len(m.sym.spinner)]) + " " + st.text.Render(text)
	}
	if m.status == "" {
		return ""
	}
	switch m.statusKind {
	case statusSuccess:
		return st.success.Render(m.sym.success + " " + text)
	case statusError:
		return st.err.Render(m.sym.failure + " " + text)
	case statusWarning:
		return st.warning.Render(m.sym.warning + " " + text)
	default:
		return st.muted.Render(m.sym.info + " " + text)
	}
}

type keyHint struct{ key, label string }

func (m model) renderFooter(inner int) string {
	st := m.styles
	if m.config.Footer != "" {
		return st.muted.MaxWidth(inner).Render(m.config.Footer)
	}

	var hints []keyHint
	switch {
	case m.running:
		hints = []keyHint{{"ctrl+c", "quit"}}
	case m.confirming:
		hints = []keyHint{{"y", "confirm"}, {"any key", "cancel"}}
	default:
		hints = []keyHint{{"↑↓", "navigate"}, {"enter", "select"}}
		if m.config.ShowNumbers {
			hints = append(hints, keyHint{"1-9", "jump"})
		}
		hints = append(hints, keyHint{"q", "quit"})
	}

	parts := make([]string, 0, len(hints))
	for _, h := range hints {
		parts = append(parts, st.key.Render(h.key)+" "+st.muted.Render(h.label))
	}
	return lipgloss.NewStyle().MaxWidth(inner).Render(strings.Join(parts, st.muted.Render("  ·  ")))
}

func (m model) View() tea.View {
	st := m.styles
	inner := m.innerWidth()
	lines := make([]string, 0, 32)

	// Header: title left, version right.
	ver := ""
	if m.config.Version != "" {
		ver = st.muted.Render("v" + strings.TrimPrefix(m.config.Version, "v"))
	}
	title := st.title.Render(truncate(m.config.Title, inner-lipgloss.Width(ver)-1))
	gap := inner - lipgloss.Width(title) - lipgloss.Width(ver)
	if gap < 1 {
		gap = 1
	}
	lines = append(lines, title+spaces(gap)+ver)
	if m.config.Subtitle != "" {
		lines = append(lines, st.muted.Render(truncate(m.config.Subtitle, inner)))
	}
	lines = append(lines, m.rule(inner), "")

	// Body (windowed).
	body := m.bodyHeight()
	used, end := 0, m.offset
	for end < len(m.items) {
		l := m.itemLines(end)
		if used+l > body && end > m.offset {
			break
		}
		used += l
		end++
	}

	if m.offset > 0 {
		lines = append(lines, st.muted.Render(fmt.Sprintf("  ↑ %d more", m.offset)))
	} else {
		lines = append(lines, "")
	}
	for i := m.offset; i < end; i++ {
		lines = append(lines, m.renderItem(i, inner)...)
	}
	if end < len(m.items) {
		lines = append(lines, st.muted.Render(fmt.Sprintf("  ↓ %d more", len(m.items)-end)))
	} else {
		lines = append(lines, "")
	}

	// Details, status, footer.
	lines = append(lines, m.rule(inner), m.renderDetails(inner), m.renderStatus(inner), "", m.renderFooter(inner))

	content := st.frame.Width(m.viewWidth()).Render(strings.Join(lines, "\n"))
	if m.width > 0 && m.height > 0 {
		content = lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Position(0.3), content)
	}

	view := tea.NewView(content)
	view.AltScreen = true
	return view
}
