// Package logger provides a slog logging wrapper that all packages within vulnfeeds should use to log output.
package logger

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

var slogLogger *slog.Logger

// InitGlobalLogger initializes the global slog logger.
func InitGlobalLogger() {
	if slogLogger != nil {
		// Logger is already initialized.
		return
	}

	inGKE := os.Getenv("KUBERNETES_SERVICE_HOST") != ""
	inCloudRun := os.Getenv("K_SERVICE") != ""
	inCloud := inGKE || inCloudRun
	var handler slog.Handler
	if inCloud {
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
}

func log(level slog.Level, msg string, a []any) {
	var pcs [1]uintptr
	runtime.Callers(3, pcs[:]) // skip [Callers, log, Info/Warn/etc]
	r := slog.NewRecord(time.Now(), level, msg, pcs[0])
	r.Add(a...)
	//nolint:errcheck
	slogLogger.Handler().Handle(context.Background(), r)
}

// Debug prints a Debug level log.
//
//nolint:contextcheck,nolintlint
func Debug(msg string, a ...any) {
	if slogLogger == nil {
		InitGlobalLogger() // Initialize with defaults if not already done.
	}
	log(slog.LevelDebug, msg, a)
}

// Info prints an Info level log.
//
//nolint:contextcheck,nolintlint
func Info(msg string, a ...any) {
	if slogLogger == nil {
		InitGlobalLogger() // Initialize with defaults if not already done.
	}
	log(slog.LevelInfo, msg, a)
}

// Warn prints a Warning level log.
//
//nolint:contextcheck,nolintlint
func Warn(msg string, a ...any) {
	if slogLogger == nil {
		InitGlobalLogger() // Initialize with defaults if not already done.
	}
	log(slog.LevelWarn, msg, a)
}

// Error prints an Error level log.
//
//nolint:contextcheck,nolintlint
func Error(msg string, a ...any) {
	if slogLogger == nil {
		InitGlobalLogger() // Initialize with defaults if not already done.
	}
	log(slog.LevelError, msg, a)
}

// Fatal prints an Error level log and then exits the program.
//
//nolint:contextcheck,nolintlint
func Fatal(msg string, a ...any) {
	if slogLogger == nil {
		InitGlobalLogger() // Initialize with defaults if not already done.
	}
	log(slog.LevelError, msg, a)
	os.Exit(1)
}

// Panic prints an Error level log and then panics.
//
//nolint:contextcheck,nolintlint
func Panic(msg string, a ...any) {
	if slogLogger == nil {
		InitGlobalLogger() // Initialize with defaults if not already done.
	}
	log(slog.LevelError, msg, a)
	panic(msg)
}
