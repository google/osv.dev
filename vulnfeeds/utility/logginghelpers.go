package utility

import (
	"fmt"
	"log"
	"os"
	"runtime/debug"

	"cloud.google.com/go/logging"
)

// LoggerWrapper wraps the Logger provided by google cloud
// Will default to the go stdout and stderr logging if GCP logger is not set
type LoggerWrapper struct {
	Logger *logging.Logger
}

// InfoLogf prints Info level log
func (wrapper LoggerWrapper) InfoLogf(format string, a ...any) {
	if wrapper.Logger == nil {
		log.Printf(format, a...)
		return
	}

	wrapper.Logger.Log(logging.Entry{
		Severity: logging.Info,
		Payload:  fmt.Sprintf(format, a...) + "\n",
	})
}

// WarnLogf prints Warning level log, defaults to stdout if GCP logger is not set
func (wrapper LoggerWrapper) WarnLogf(format string, a ...any) {
	if wrapper.Logger == nil {
		log.Printf(format, a...)
		return
	}

	wrapper.Logger.Log(logging.Entry{
		Severity: logging.Warning,
		Payload:  fmt.Sprintf(format, a...) + "\n",
	})
}

// FatalLogf prints Error level log with stack trace, before exiting with error code 1
func (wrapper LoggerWrapper) FatalLogf(format string, a ...any) {
	if wrapper.Logger == nil {
		log.Fatalf(format, a...)
		return
	}

	wrapper.Logger.Log(logging.Entry{
		Severity: logging.Error,
		Payload:  fmt.Sprintf(format, a...) + "\n" + string(debug.Stack()),
	})
	err := wrapper.Logger.Flush()
	if err != nil {
		log.Fatalln("Failed to flush logger")
	}
	os.Exit(1)
}
