package utility

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime/debug"

	"cloud.google.com/go/logging"
)

// CreateLoggerWrapper creates and initializes the LoggerWrapper,
// and also returns a cleanup function to be deferred
func CreateLoggerWrapper(name string) (LoggerWrapper, func()) {
	projectId, ok := os.LookupEnv("GOOGLE_CLOUD_PROJECT")
	var loggerOptions []logging.LoggerOption
	if !ok {
		log.Println("GOOGLE_CLOUD_PROJECT not set, routing logs to stdout")
		loggerOptions = append(loggerOptions, logging.RedirectAsJSON(os.Stdout))
	}
	client, err := logging.NewClient(context.Background(), projectId)

	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	wrapper := LoggerWrapper{
		GCloudLogger: client.Logger(name, loggerOptions...),
	}

	return wrapper, func() { client.Close() }
}

// LoggerWrapper wraps the Logger provided by google cloud
// Will default to the go stdout and stderr logging if GCP logger is not set
type LoggerWrapper struct {
	GCloudLogger *logging.Logger
}

// Infof prints Info level log
func (wrapper LoggerWrapper) Infof(format string, a ...any) {
	if wrapper.GCloudLogger == nil {
		log.Printf(format, a...)
		return
	}

	wrapper.GCloudLogger.Log(logging.Entry{
		Severity: logging.Info,
		Payload:  fmt.Sprintf(format, a...) + "\n",
	})
}

// Warnf prints Warning level log, defaults to stdout if GCP logger is not set
func (wrapper LoggerWrapper) Warnf(format string, a ...any) {
	if wrapper.GCloudLogger == nil {
		log.Printf(format, a...)
		return
	}

	wrapper.GCloudLogger.Log(logging.Entry{
		Severity: logging.Warning,
		Payload:  fmt.Sprintf(format, a...) + "\n",
	})
}

// Fatalf prints Error level log with stack trace, before exiting with error code 1
func (wrapper LoggerWrapper) Fatalf(format string, a ...any) {
	if wrapper.GCloudLogger == nil {
		log.Fatalf(format, a...)
		return
	}

	wrapper.GCloudLogger.Log(logging.Entry{
		Severity: logging.Error,
		Payload:  fmt.Sprintf(format, a...) + "\n" + string(debug.Stack()),
	})
	err := wrapper.GCloudLogger.Flush()
	if err != nil {
		log.Fatalln("Failed to flush logger")
	}
	os.Exit(1)
}
