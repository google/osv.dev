// Package logger provides a slog logging wrapper that all packages within vulnfeeds should use to log output.
package logger

import (
	"log/slog"
	"os"
)

var slogLogger *slog.Logger

// InitGlobalLogger initializes the global slog logger.
func InitGlobalLogger() {
	if slogLogger != nil {
		// Logger is already initialized.
		return
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

			return a
		},
	}

	// A JSONHandler writing to stdout is the standard and correct way to log in GKE.
	handler := slog.NewJSONHandler(os.Stdout, opts)
	slogLogger = slog.New(handler)
}

// Info prints an Info level log.
func Info(msg string, a ...any) {
	if slogLogger == nil {
		InitGlobalLogger() // Initialize with defaults if not already done.
	}
	slogLogger.Info(msg, a...)
}

// Warn prints a Warning level log.
func Warn(msg string, a ...any) {
	if slogLogger == nil {
		InitGlobalLogger() // Initialize with defaults if not already done.
	}
	slogLogger.Warn(msg, a...)
}

// Error prints an Error level log.
func Error(msg string, a ...any) {
	if slogLogger == nil {
		InitGlobalLogger() // Initialize with defaults if not already done.
	}
	slogLogger.Error(msg, a...)
}

// Fatal prints an Error level log and then exits the program.
func Fatal(msg string, a ...any) {
	if slogLogger == nil {
		InitGlobalLogger() // Initialize with defaults if not already done.
	}
	slogLogger.Error(msg, a...)
	os.Exit(1)
}

// Panic prints an Error level log and then panics.
func Panic(msg string, a ...any) {
	if slogLogger == nil {
		InitGlobalLogger() // Initialize with defaults if not already done.
	}
	slogLogger.Error(msg, a...)
	panic(msg)
}
