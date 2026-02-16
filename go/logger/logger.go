// Package logger provides a slog logging wrapper that all packages within vulnfeeds should use to log output.
package logger

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"cloud.google.com/go/errorreporting"
)

var (
	slogLogger  *slog.Logger
	errorClient *errorreporting.Client
	once        sync.Once
)

// InitGlobalLogger initializes the global slog logger.
func InitGlobalLogger(ctx context.Context) {
	once.Do(func() {
		if slogLogger != nil {
			// Logger is already initialized.
			return
		}

		inGKE := os.Getenv("KUBERNETES_SERVICE_HOST") != ""
		inCloudRun := os.Getenv("K_SERVICE") != ""
		inCloud := inGKE || inCloudRun
		var handler slog.Handler
		if inCloud {
			projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
			if projectID != "" {
				serviceName := os.Getenv("K_SERVICE")
				if serviceName == "" {
					// Fallback to binary name for GKE services where K_SERVICE is not set.
					serviceName = filepath.Base(os.Args[0])
				}
				var err error
				errorClient, err = errorreporting.NewClient(ctx, projectID, errorreporting.Config{
					ServiceName: serviceName,
					OnError: func(err error) {
						fmt.Fprintf(os.Stderr, "Could not log error to Error Reporting: %v\n", err)
					},
				})
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to create errorreporting client: %v\n", err)
				}
			}

			opts := &slog.HandlerOptions{
				// AddSource adds the source code position to the log output, which is invaluable for debugging.
				// Google Cloud Logging will automatically parse this into the `sourceLocation` field.
				AddSource: true,
				// ReplaceAttr is used to customize log attributes. We use it here to make the output
				// perfectly align with what Google Cloud Logging expects for structured logs.
				ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
					// Remap the default "level" key to "severity" for Google Cloud Logging.
					if a.Key == slog.LevelKey {
						level := a.Value.Any().(slog.Level)
						var levelStr string
						switch level {
						case slog.LevelDebug:
							levelStr = "DEBUG"
						case slog.LevelInfo:
							levelStr = "INFO"
						case slog.LevelWarn:
							levelStr = "WARNING"
						case slog.LevelError:
							levelStr = "ERROR"
						default:
							levelStr = "DEFAULT"
						}

						return slog.String("severity", levelStr)
					}
					// Remap the default "msg" key to "message" for better compatibility.
					if a.Key == slog.MessageKey {
						return slog.Attr{Key: "message", Value: a.Value}
					}
					// Remap the default "source" key to "sourceLocation", and trim file path to just file name.
					if a.Key == slog.SourceKey {
						source := a.Value.Any().(*slog.Source)
						source.File = filepath.Base(source.File)

						return slog.Attr{Key: "sourceLocation", Value: slog.AnyValue(source)}
					}

					return a
				},
			}

			// A JSONHandler writing to stdout is the standard and correct way to log in GKE.
			handler = slog.NewJSONHandler(os.Stdout, opts)
		} else {
			handler = newLocalHandler(os.Stdout)
		}
		slogLogger = slog.New(handler)
	})
}

// Close flushes any buffered log or error reports.
func Close() {
	if errorClient != nil {
		errorClient.Close()
	}
}

func log(ctx context.Context, level slog.Level, msg string, a []any) {
	var pcs [1]uintptr
	runtime.Callers(3, pcs[:]) // skip [Callers, log, Info/Warn/etc]
	r := slog.NewRecord(time.Now(), level, msg, pcs[0])
	r.Add(a...)

	if slogLogger.Handler().Enabled(ctx, level) {
		//nolint:errcheck
		slogLogger.Handler().Handle(ctx, r)
	}

	if level >= slog.LevelError && errorClient != nil {
		// Report the error to Google Cloud Error Reporting.
		// We leave Stack nil to let the client automatically capture the stack trace.
		// Note: This will include the logger functions at the top of the stack.
		// If we want to hide them, we would need to manually capture and trim the stack.
		errorClient.Report(errorreporting.Entry{
			Error: fmt.Errorf("%s %v", msg, a),
			Stack: nil,
		})
	}
}

// Debug prints a Debug level log.
//
//nolint:contextcheck,nolintlint
func Debug(msg string, a ...any) {
	DebugContext(context.Background(), msg, a...)
}

// DebugContext prints a Debug level log with context.
//
//nolint:contextcheck,nolintlint
func DebugContext(ctx context.Context, msg string, a ...any) {
	if slogLogger == nil {
		InitGlobalLogger(ctx)
	}
	log(ctx, slog.LevelDebug, msg, a)
}

// Info prints an Info level log.
//
//nolint:contextcheck,nolintlint
func Info(msg string, a ...any) {
	InfoContext(context.Background(), msg, a...)
}

// InfoContext prints an Info level log with context.
//
//nolint:contextcheck,nolintlint
func InfoContext(ctx context.Context, msg string, a ...any) {
	if slogLogger == nil {
		InitGlobalLogger(ctx)
	}
	log(ctx, slog.LevelInfo, msg, a)
}

// Warn prints a Warning level log.
//
//nolint:contextcheck,nolintlint
func Warn(msg string, a ...any) {
	WarnContext(context.Background(), msg, a...)
}

// WarnContext prints a Warning level log with context.
//
//nolint:contextcheck,nolintlint
func WarnContext(ctx context.Context, msg string, a ...any) {
	if slogLogger == nil {
		InitGlobalLogger(ctx)
	}
	log(ctx, slog.LevelWarn, msg, a)
}

// Error prints an Error level log.
//
//nolint:contextcheck,nolintlint
func Error(msg string, a ...any) {
	ErrorContext(context.Background(), msg, a...)
}

// ErrorContext prints an Error level log with context.
//
//nolint:contextcheck,nolintlint
func ErrorContext(ctx context.Context, msg string, a ...any) {
	if slogLogger == nil {
		InitGlobalLogger(ctx)
	}
	log(ctx, slog.LevelError, msg, a)
}

// Fatal prints an Error level log and then exits the program.
//
//nolint:contextcheck,nolintlint
func Fatal(msg string, a ...any) {
	FatalContext(context.Background(), msg, a...)
}

// FatalContext prints an Error level log with context and then exits.
//
//nolint:contextcheck,nolintlint
func FatalContext(ctx context.Context, msg string, a ...any) {
	if slogLogger == nil {
		InitGlobalLogger(ctx)
	}
	log(ctx, slog.LevelError, msg, a)
	Close()
	os.Exit(1)
}

// Panic prints an Error level log and then panics.
//
//nolint:contextcheck,nolintlint
func Panic(msg string, a ...any) {
	PanicContext(context.Background(), msg, a...)
}

// PanicContext prints an Error level log with context and then panics.
//
//nolint:contextcheck,nolintlint
func PanicContext(ctx context.Context, msg string, a ...any) {
	if slogLogger == nil {
		InitGlobalLogger(ctx)
	}
	log(ctx, slog.LevelError, msg, a)
	Close()
	panic(msg)
}
