// Package logger provides a slog logging wrapper that all packages within vulnfeeds should use to log output.
package logger

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"time"

	"go.opentelemetry.io/otel/trace"
)

func log(ctx context.Context, level slog.Level, msg string, a []any) {
	var pcs [1]uintptr
	runtime.Callers(3, pcs[:]) // skip [Callers, log, Info/Warn/etc]
	r := slog.NewRecord(time.Now(), level, msg, pcs[0])
	r.Add(a...)

	if projectID != "" {
		spanContext := trace.SpanContextFromContext(ctx)
		if spanContext.HasTraceID() {
			r.Add(
				slog.String("logging.googleapis.com/trace", fmt.Sprintf("projects/%s/traces/%s", projectID, spanContext.TraceID().String())),
				slog.String("logging.googleapis.com/spanId", spanContext.SpanID().String()),
				slog.Bool("logging.googleapis.com/trace_sampled", spanContext.IsSampled()),
			)
		}

		if level >= slog.LevelError && !ignoreError(r) {
			r.Add(slog.String("@type", "type.googleapis.com/google.devtools.clouderrorreporting.v1beta1.ReportedErrorEvent"))
		}
	}

	if slogLogger.Handler().Enabled(ctx, level) {
		//nolint:errcheck
		slogLogger.Handler().Handle(ctx, r)
	}
}

func ignoreError(r slog.Record) bool {
	ignore := false
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "exception" || a.Key == "err" || a.Key == "error" {
			if err, ok := a.Value.Any().(error); ok {
				// We want to ignore context cancelled errors, since they're usually caused by something else
				// and we don't want to be alerted about them.
				if errors.Is(err, context.Canceled) {
					ignore = true

					return false
				}
			}
		}

		return true
	})

	return ignore
}

// Debug prints a Debug level log.
//
//nolint:contextcheck,nolintlint
func Debug(msg string, a ...any) {
	// We don't call DebugContext because we want to make sure call stack calculation is correct.
	log(context.Background(), slog.LevelDebug, msg, a)
}

// DebugContext prints a Debug level log with context.
//
//nolint:contextcheck,nolintlint
func DebugContext(ctx context.Context, msg string, a ...any) {
	log(ctx, slog.LevelDebug, msg, a)
}

// Info prints an Info level log.
//
//nolint:contextcheck,nolintlint
func Info(msg string, a ...any) {
	// We don't call InfoContext because we want to make sure call stack calculation is correct.
	log(context.Background(), slog.LevelInfo, msg, a)
}

// InfoContext prints an Info level log with context.
//
//nolint:contextcheck,nolintlint
func InfoContext(ctx context.Context, msg string, a ...any) {
	log(ctx, slog.LevelInfo, msg, a)
}

// Warn prints a Warning level log.
//
//nolint:contextcheck,nolintlint
func Warn(msg string, a ...any) {
	// We don't call WarnContext because we want to make sure call stack calculation is correct.
	log(context.Background(), slog.LevelWarn, msg, a)
}

// WarnContext prints a Warning level log with context.
//
//nolint:contextcheck,nolintlint
func WarnContext(ctx context.Context, msg string, a ...any) {
	log(ctx, slog.LevelWarn, msg, a)
}

// Error prints an Error level log.
//
//nolint:contextcheck,nolintlint
func Error(msg string, a ...any) {
	// We don't call ErrorContext because we want to make sure call stack calculation is correct.
	log(context.Background(), slog.LevelError, msg, a)
}

// ErrorContext prints an Error level log with context.
//
//nolint:contextcheck,nolintlint
func ErrorContext(ctx context.Context, msg string, a ...any) {
	log(ctx, slog.LevelError, msg, a)
}

// Fatal prints an Error level log and then exits the program.
//
//nolint:contextcheck,nolintlint
func Fatal(msg string, a ...any) {
	// We don't call FatalContext because we want to make sure call stack calculation is correct.
	log(context.Background(), slog.LevelError, msg, a)
	Close()
	os.Exit(1)
}

// FatalContext prints an Error level log with context and then exits.
//
//nolint:contextcheck,nolintlint
func FatalContext(ctx context.Context, msg string, a ...any) {
	log(ctx, slog.LevelError, msg, a)
	Close()
	os.Exit(1)
}

// Panic prints an Error level log and then panics.
//
//nolint:contextcheck,nolintlint
func Panic(msg string, a ...any) {
	// We don't call PanicContext because we want to make sure call stack calculation is correct.
	log(context.Background(), slog.LevelError, msg, a)
	Close()
	panic(msg)
}

// PanicContext prints an Error level log with context and then panics.
//
//nolint:contextcheck,nolintlint
func PanicContext(ctx context.Context, msg string, a ...any) {
	log(ctx, slog.LevelError, msg, a)
	Close()
	panic(msg)
}
