// Package main implements a TUI tool to trigger reimports for selected sources in Datastore.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	db "github.com/google/osv.dev/go/internal/database/datastore"
	"github.com/google/osv.dev/go/internal/models"
)

type state int

const (
	stateSelectEnv state = iota
	stateLoading
	stateSelectSources
	stateConfirm
	stateApplying
	stateDone
)

type envOption struct {
	name      string
	projectID string
}

type applyResult struct {
	name    string
	skipped bool
	err     error
}

// Msg types
type errMsg struct{ err error }
type sourcesLoadedMsg struct{ sources []*models.SourceRepository }
type appliedMsg struct{ results []applyResult }

func initialModel() model {
	return model{
		state: stateSelectEnv,
		envs: []envOption{
			{name: "Test (oss-vdb-test)", projectID: "oss-vdb-test"},
			{name: "Prod (oss-vdb)", projectID: "oss-vdb"},
		},
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

type item struct {
	repo    *models.SourceRepository
	checked bool
}

func (i *item) Title() string {
	actionDesc := ""
	switch i.repo.Type {
	case models.SourceRepositoryTypeGit:
		actionDesc = " (Clear Last Synced Commit)"
	case models.SourceRepositoryTypeBucket, models.SourceRepositoryTypeREST:
		actionDesc = " (Set Ignore Last Import Time)"
	}

	title := i.repo.Name
	if actionDesc != "" {
		title += actionStyle.Render(actionDesc)
	}

	if i.checked {
		return "[x] " + title
	}

	return "[ ] " + title
}

func (i *item) Description() string {
	return ""
}

func (i *item) FilterValue() string { return i.repo.Name }

type model struct {
	state       state
	err         error
	envs        []envOption
	envCursor   int
	selectedEnv envOption

	list list.Model

	width  int
	height int

	results []applyResult
}

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#7D56F4"))

	cursorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#AD58FE"))

	selectedItemStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#AD58FE")).
				Bold(true)

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF0000")).
			Bold(true)

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#626262"))

	actionStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#8A8A8A"))

	dialogStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7D56F4")).
			Padding(1, 2)
)

// Commands

func loadSourcesCmd(projectID string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		databaseID := os.Getenv("DATASTORE_DATABASE_ID")
		client, err := datastore.NewClientWithDatabase(ctx, projectID, databaseID)
		if err != nil {
			return errMsg{fmt.Errorf("failed to connect to datastore: %w. Make sure you ran 'gcloud auth application-default login'", err)}
		}

		store := db.NewSourceRepositoryStore(client)
		var repos []*models.SourceRepository
		for repo, err := range store.All(ctx) {
			if err != nil {
				return errMsg{fmt.Errorf("failed to fetch sources: %w", err)}
			}
			repos = append(repos, repo)
		}

		slices.SortFunc(repos, func(a, b *models.SourceRepository) int {
			return strings.Compare(a.Name, b.Name)
		})

		return sourcesLoadedMsg{sources: repos}
	}
}

func applyChangesCmd(projectID string, repos []*models.SourceRepository) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		databaseID := os.Getenv("DATASTORE_DATABASE_ID")
		client, err := datastore.NewClientWithDatabase(ctx, projectID, databaseID)
		if err != nil {
			return errMsg{err}
		}

		store := db.NewSourceRepositoryStore(client)
		var results []applyResult

		for _, repo := range repos {
			// We need to fetch the latest version of the entity first to avoid overwriting other fields
			// that might have changed, and to ensure we are modifying the correct datastore entity.
			latestRepo, err := store.Get(ctx, repo.Name)
			if err != nil {
				results = append(results, applyResult{name: repo.Name, err: fmt.Errorf("failed to get latest state: %w", err)})
				continue
			}

			modified := false
			switch latestRepo.Type {
			case models.SourceRepositoryTypeGit:
				if latestRepo.Git != nil {
					if latestRepo.Git.LastSyncedCommit != "" {
						latestRepo.Git.LastSyncedCommit = ""
						modified = true
					} else {
						// Already cleared
						results = append(results, applyResult{name: repo.Name, skipped: true})
						continue
					}
				}
			case models.SourceRepositoryTypeBucket:
				if latestRepo.Bucket != nil {
					if !latestRepo.Bucket.IgnoreLastImportTime {
						latestRepo.Bucket.IgnoreLastImportTime = true
						modified = true
					} else {
						results = append(results, applyResult{name: repo.Name, skipped: true})
						continue
					}
				}
			case models.SourceRepositoryTypeREST:
				if latestRepo.REST != nil {
					if !latestRepo.REST.IgnoreLastImportTime {
						latestRepo.REST.IgnoreLastImportTime = true
						modified = true
					} else {
						results = append(results, applyResult{name: repo.Name, skipped: true})
						continue
					}
				}
			}

			if !modified {
				results = append(results, applyResult{name: repo.Name, err: errors.New("unsupported source type or config missing")})
				continue
			}

			err = store.Update(ctx, latestRepo.Name, latestRepo)
			results = append(results, applyResult{name: repo.Name, err: err})
		}

		return appliedMsg{results: results}
	}
}

// Update

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		dialogWidth := msg.Width - 4
		dialogHeight := msg.Height - 2

		contentWidth := dialogWidth - 6
		contentHeight := dialogHeight - 4

		// List needs to leave 2 lines for the top title
		listHeight := contentHeight - 2

		if contentWidth < 20 {
			contentWidth = 20
		}
		if listHeight < 5 {
			listHeight = 5
		}
		if m.state >= stateSelectSources {
			m.list.SetSize(contentWidth, listHeight)
		}

		return m, nil

	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC || (msg.Type == tea.KeyRunes && msg.String() == "q") {
			return m, tea.Quit
		}

	case errMsg:
		m.err = msg.err
		m.state = stateDone

		return m, nil
	}

	switch m.state {
	case stateSelectEnv:
		return m.updateSelectEnv(msg)
	case stateLoading:
		return m.updateLoading(msg)
	case stateSelectSources:
		return m.updateSelectSources(msg)
	case stateConfirm:
		return m.updateConfirm(msg)
	case stateApplying:
		return m.updateApplying(msg)
	case stateDone:
		return m.updateDone(msg)
	}

	return m, nil
}

func (m model) updateSelectEnv(msg tea.Msg) (tea.Model, tea.Cmd) {
	if msg, ok := msg.(tea.KeyMsg); ok {
		switch msg.Type {
		case tea.KeyUp:
			if m.envCursor > 0 {
				m.envCursor--
			}
		case tea.KeyDown:
			if m.envCursor < len(m.envs)-1 {
				m.envCursor++
			}
		case tea.KeyEnter:
			m.selectedEnv = m.envs[m.envCursor]
			m.state = stateLoading

			return m, loadSourcesCmd(m.selectedEnv.projectID)
		default:
		}
	}

	return m, nil
}

func (m model) updateLoading(msg tea.Msg) (tea.Model, tea.Cmd) {
	if msg, ok := msg.(sourcesLoadedMsg); ok {
		var items []list.Item
		for _, r := range msg.sources {
			items = append(items, &item{repo: r})
		}

		contentWidth := 60
		listHeight := 16
		if m.width > 0 && m.height > 0 {
			dialogWidth := m.width - 4
			dialogHeight := m.height - 2
			contentWidth = dialogWidth - 6
			listHeight = (dialogHeight - 4) - 2
		}
		if contentWidth < 20 {
			contentWidth = 20
		}
		if listHeight < 5 {
			listHeight = 5
		}

		delegate := list.NewDefaultDelegate()
		delegate.ShowDescription = false
		delegate.SetSpacing(0)

		m.list = list.New(items, delegate, contentWidth, listHeight)
		m.list.Title = "Select sources to reimport"
		m.list.SetShowHelp(true)
		m.state = stateSelectSources
	}

	return m, nil
}

func (m model) updateSelectSources(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.list.FilterState() == list.Filtering {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)

		return m, cmd
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeySpace:
			if selected, ok := m.list.SelectedItem().(*item); ok {
				selected.checked = !selected.checked
			}

			return m, nil
		case tea.KeyEnter:
			var checkedRepos []*models.SourceRepository
			for _, li := range m.list.Items() {
				if i, ok := li.(*item); ok && i.checked {
					checkedRepos = append(checkedRepos, i.repo)
				}
			}
			if len(checkedRepos) > 0 {
				m.state = stateConfirm
			}

			return m, nil
		default:
		}
	default:
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)

	return m, cmd
}

func (m model) updateConfirm(msg tea.Msg) (tea.Model, tea.Cmd) {
	if msg, ok := msg.(tea.KeyMsg); ok {
		switch msg.Type {
		case tea.KeyEsc:
			m.state = stateSelectSources
		case tea.KeyRunes:
			switch msg.String() {
			case "y", "Y":
				m.state = stateApplying
				var checkedRepos []*models.SourceRepository
				for _, li := range m.list.Items() {
					if i, ok := li.(*item); ok && i.checked {
						checkedRepos = append(checkedRepos, i.repo)
					}
				}

				return m, applyChangesCmd(m.selectedEnv.projectID, checkedRepos)
			case "n", "N":
				m.state = stateSelectSources
			}
		default:
		}
	}

	return m, nil
}

func (m model) updateApplying(msg tea.Msg) (tea.Model, tea.Cmd) {
	if msg, ok := msg.(appliedMsg); ok {
		m.results = msg.results
		m.state = stateDone
	}

	return m, nil
}

func (m model) updateDone(msg tea.Msg) (tea.Model, tea.Cmd) {
	if msg, ok := msg.(tea.KeyMsg); ok {
		if msg.Type == tea.KeyEnter || (msg.Type == tea.KeyRunes && msg.String() == "q") {
			return m, tea.Quit
		}
	}

	return m, nil
}

// View

func (m model) View() string {
	if m.width == 0 || m.height == 0 {
		return "Initializing TUI..."
	}

	dialogWidth := m.width - 4
	dialogHeight := m.height - 2
	contentWidth := dialogWidth - 6
	contentHeight := dialogHeight - 4

	if contentWidth < 20 {
		contentWidth = 20
	}
	if contentHeight < 5 {
		contentHeight = 5
	}

	var s strings.Builder
	s.WriteString(titleStyle.Render("=== OSV Reimport Trigger Tool ===") + "\n\n")

	if m.err != nil {
		s.WriteString(errorStyle.Render(fmt.Sprintf("Error: %v", m.err)) + "\n\nPress 'q' to quit.\n")
	} else {
		switch m.state {
		case stateSelectEnv:
			s.WriteString(headerStyle.Render("Select Environment:") + "\n")
			for i, env := range m.envs {
				cursor := "  "
				name := env.name
				if m.envCursor == i {
					cursor = cursorStyle.Render("> ")
					name = selectedItemStyle.Render(env.name)
				}
				s.WriteString(fmt.Sprintf("%s%s\n", cursor, name))
			}
			s.WriteString("\n" + helpStyle.Render("[Use up/down to navigate, Enter to select, ctrl+c to quit]") + "\n")

		case stateLoading:
			s.WriteString(fmt.Sprintf("Connecting to Datastore and loading sources for %s...\n", m.selectedEnv.name))

		case stateSelectSources:
			s.WriteString(m.list.View())

		case stateConfirm:
			s.WriteString(headerStyle.Render("Confirm Reimport Triggering:") + "\n\n")
			s.WriteString(fmt.Sprintf("You are about to trigger reimport for the following sources in %s:\n", m.selectedEnv.name))
			var checked []*item
			for _, li := range m.list.Items() {
				if i, ok := li.(*item); ok && i.checked {
					checked = append(checked, i)
				}
			}

			maxItemsToPrint := contentHeight - 8
			if maxItemsToPrint < 1 {
				maxItemsToPrint = 1
			}

			printed := 0
			for _, i := range checked {
				if printed < maxItemsToPrint {
					s.WriteString(selectedItemStyle.Render(" - "+i.repo.Name) + "\n")
					printed++
				}
			}
			if len(checked) > maxItemsToPrint {
				s.WriteString(helpStyle.Render(fmt.Sprintf(" ... and %d more", len(checked)-maxItemsToPrint)) + "\n")
			}
			s.WriteString("\nAre you sure you want to proceed? (y/n): ")

		case stateApplying:
			s.WriteString("Applying changes to Datastore...\n")

		case stateDone:
			s.WriteString(headerStyle.Render("Results:") + "\n\n")

			successes := 0
			skipped := 0
			var failures []applyResult

			for _, res := range m.results {
				if res.err != nil {
					failures = append(failures, res)
				} else if res.skipped {
					skipped++
				} else {
					successes++
				}
			}

			s.WriteString(fmt.Sprintf("Success: %d, Skipped: %d, Failed: %d\n", successes, skipped, len(failures)))
			if len(failures) > 0 {
				s.WriteString("\n" + errorStyle.Render("Failures:") + "\n")

				maxFailuresToPrint := contentHeight - 10
				if maxFailuresToPrint < 1 {
					maxFailuresToPrint = 1
				}

				printed := 0
				for _, res := range failures {
					if printed < maxFailuresToPrint {
						s.WriteString(fmt.Sprintf(" - %-25s : %v\n", res.name, res.err))
						printed++
					}
				}
				if len(failures) > maxFailuresToPrint {
					s.WriteString(helpStyle.Render(fmt.Sprintf(" ... and %d more failures", len(failures)-maxFailuresToPrint)) + "\n")
				}
			}
			s.WriteString("\n" + helpStyle.Render("Press 'q' or Enter to quit.") + "\n")
		}
	}

	return dialogStyle.
		Width(contentWidth).
		Height(contentHeight).
		Render(s.String())
}

func main() {
	p := tea.NewProgram(initialModel())
	if _, err := p.Run(); err != nil {
		log.Fatalf("Alas, it's all gone wrong: %v", err)
	}
}
