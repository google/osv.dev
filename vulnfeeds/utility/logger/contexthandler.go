package logger

import (
	"context"
	"log/slog"
	"sync"
)

var (
	ctxKeysMu sync.RWMutex
	ctxKeys   = make(map[any]string)
)

// RegisterContextKey registers a context key that should be automatically
// extracted and logged if present in the context.
func RegisterContextKey(ctxKey any, logKey string) {
	ctxKeysMu.Lock()
	defer ctxKeysMu.Unlock()
	ctxKeys[ctxKey] = logKey
}

// contextHandler is a wrapper around slog.Handler that automatically
// extracts registered context keys and logs their values as part of the attributes.
type contextHandler struct {
	slog.Handler
}

func (h *contextHandler) Handle(ctx context.Context, r slog.Record) error {
	ctxKeysMu.RLock()
	for ctxKey, logKey := range ctxKeys {
		if val := ctx.Value(ctxKey); val != nil {
			r.AddAttrs(slog.Any(logKey, val))
		}
	}
	ctxKeysMu.RUnlock()

	return h.Handler.Handle(ctx, r)
}

func (h *contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &contextHandler{h.Handler.WithAttrs(attrs)}
}

func (h *contextHandler) WithGroup(name string) slog.Handler {
	return &contextHandler{h.Handler.WithGroup(name)}
}
