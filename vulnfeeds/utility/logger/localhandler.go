package logger

import (
	"context"
	"fmt"
	"image/color"
	"io"
	"log/slog"
	"os"
	"strings"

	"charm.land/lipgloss/v2"
)

var (
	levelColors = map[slog.Level]color.Color{
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
	w     io.Writer
	level slog.Level
}

var _ slog.Handler = (*localHandler)(nil)

func newLocalHandler(w io.Writer) *localHandler {
	level := slog.LevelInfo
	if lvl := os.Getenv("LOG_LEVEL"); lvl != "" {
		switch strings.ToLower(lvl) {
		case "debug":
			level = slog.LevelDebug
		case "info":
			level = slog.LevelInfo
		case "warn":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		}
	}

	return &localHandler{
		w:     w,
		level: level,
	}
}

func (h *localHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *localHandler) Handle(_ context.Context, r slog.Record) error {
	// INFO:  message foo=bar
	sb := &strings.Builder{}
	sb.WriteString(levelStyle.Foreground(levelColors[r.Level]).Render(r.Level.String()+":"))
	sb.WriteString(messageStyle.Render(r.Message))
	r.Attrs(func(a slog.Attr) bool {
		keyStyle := keyStyle
		if a.Key == "err" || a.Key == "error" {
			// Make the error key bright red.
			keyStyle = keyStyle.Foreground(lipgloss.Color("9"))
		}
		sb.WriteString(" " + keyStyle.Render(a.Key+"="))
		sb.WriteString(valueStyle.Render(fmt.Sprintf("%v", a.Value)))

		return true
	})
	_, err := lipgloss.Fprintln(h.w, sb.String())

	return err
}

func (h *localHandler) WithAttrs(_ []slog.Attr) slog.Handler {
	panic("not implemented")
}

func (h *localHandler) WithGroup(_ string) slog.Handler {
	panic("not implemented")
}
