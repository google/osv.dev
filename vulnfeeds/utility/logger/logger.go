package logger

import (
	"cloud.google.com/go/logging"
	"context"
	"fmt"
	"log"
	"os"
	"runtime/debug"
)

var GlobalLogger LoggerWrapper

func InitGlobalLogger(logID string) func() {
	if GlobalLogger.GCloudLogger != nil {
		log.Panicf("logger already initialized")
	}

	gl, cleanup := createLoggerWrapper(logID)
	GlobalLogger = gl

	return cleanup
}

// CreateLoggerWrapper creates and initializes the LoggerWrapper,
// and also returns a cleanup function to be deferred
func createLoggerWrapper(logID string) (LoggerWrapper, func()) {
	projectID, projectIDSet := os.LookupEnv("GOOGLE_CLOUD_PROJECT")
	if !projectIDSet {
		return LoggerWrapper{}, func() {}
	}

	log.Println("Logging to project id: " + projectID)
	client, err := logging.NewClient(context.Background(), projectID)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	wrapper := LoggerWrapper{
		GCloudLogger: client.Logger(logID),
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

// Errorf prints Error level log
func (wrapper LoggerWrapper) Errorf(format string, a ...any) {
	if wrapper.GCloudLogger == nil {
		log.Printf(format, a...)
		return
	}

	wrapper.GCloudLogger.Log(logging.Entry{
		Severity: logging.Error,
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

// ---- Global versions of these funcs:

// Infof prints Info level log
func Infof(format string, a ...any) {
	GlobalLogger.Infof(format, a...)
}

// Warnf prints Warning level log, defaults to stdout if GCP logger is not set
func Warnf(format string, a ...any) {
	GlobalLogger.Warnf(format, a...)
}

// Errorf prints an error level log, defaults to stdout if GCP logger is not set
func Errorf(format string, a ...any) {
	GlobalLogger.Errorf(format, a...)
}

// Fatalf prints Error level log with stack trace, before exiting with error code 1
func Fatalf(format string, a ...any) {
	GlobalLogger.Fatalf(format, a...)
}
