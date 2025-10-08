package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	levelColors = map[slog.Level]lipgloss.Color{
		slog.LevelDebug: lipgloss.Color("5"), // Purple
		slog.LevelInfo:  lipgloss.Color("4"), // Blue
		slog.LevelWarn:  lipgloss.Color("3"), // Yellow
		slog.LevelError: lipgloss.Color("1"), // Red
	}
	levelStyle   = lipgloss.NewStyle().Width(8).Bold(true)
	messageStyle = lipgloss.NewStyle()
	keyStyle     = lipgloss.NewStyle().
			Foreground(lipgloss.Color("6")). // Cyan
			Bold(true)
	valueStyle = lipgloss.NewStyle()
)

type localHandler struct {
	w io.Writer
}

func newLocalHandler(w io.Writer) *localHandler {
	return &localHandler{
		w: w,
	}
}

func (h *localHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

func (h *localHandler) Handle(_ context.Context, r slog.Record) error {
	// INFO:  message foo=bar
	sb := &strings.Builder{}
	fmt.Fprint(sb, levelStyle.Foreground(levelColors[r.Level]).Render(r.Level.String()+":"))
	fmt.Fprint(sb, messageStyle.Render(r.Message))
	r.Attrs(func(a slog.Attr) bool {
		keyStyle := keyStyle
		if a.Key == "err" || a.Key == "error" {
			// Make the error key bright red.
			keyStyle = keyStyle.Foreground(lipgloss.Color("9"))
		}
		fmt.Fprint(sb, " "+keyStyle.Render(a.Key+"="))
		fmt.Fprint(sb, valueStyle.Render(fmt.Sprintf("%v", a.Value)))

		return true
	})
	_, err := fmt.Fprintln(h.w, sb.String())

	return err
}

func (h *localHandler) WithAttrs(_ []slog.Attr) slog.Handler {
	panic("not implemented")
}

func (h *localHandler) WithGroup(_ string) slog.Handler {
	panic("not implemented")
}
