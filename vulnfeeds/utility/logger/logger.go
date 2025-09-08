// Package logger provides a gcloud logging wrapper that all packages within vulnfeeds should use to log output
package logger

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime/debug"

	"cloud.google.com/go/logging"
)

var GlobalLogger Wrapper

func InitGlobalLogger(logID string, forceLocalLogging bool) func() {
	if GlobalLogger.GCloudLogger != nil {
		log.Panicf("logger already initialized")
	}

	gl, cleanup := createLoggerWrapper(logID, forceLocalLogging)
	GlobalLogger = gl

	return cleanup
}

// CreateLoggerWrapper creates and initializes the LoggerWrapper,
// and also returns a cleanup function to be deferred
func createLoggerWrapper(logID string, forceLocalLogging bool) (Wrapper, func()) {
	_, runningInCloud := os.LookupEnv("KUBERNETES_SERVICE_HOST")
	if !runningInCloud {
		log.Println("[Info] Detected running locally, routing logs to stdout.")
		return Wrapper{}, func() {}
	}

	projectID, projectIDSet := os.LookupEnv("GOOGLE_CLOUD_PROJECT")
	if !projectIDSet {
		return Wrapper{}, func() {}
	}

	log.Println("Logging to project id: " + projectID)
	client, err := logging.NewClient(context.Background(), projectID)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	wrapper := Wrapper{
		GCloudLogger:      client.Logger(logID),
		ForceLocalLogging: forceLocalLogging,
	}

	return wrapper, func() { client.Close() }
}

// Wrapper wraps the Logger provided by google cloud
// Will default to the go stdout and stderr logging if GCP logger is not set
type Wrapper struct {
	GCloudLogger      *logging.Logger
	ForceLocalLogging bool
}

// Infof prints Info level log
func (wrapper Wrapper) Infof(format string, a ...any) {
	if wrapper.GCloudLogger == nil || wrapper.ForceLocalLogging {
		log.Printf("[Info] "+format, a...)
		return
	}

	wrapper.GCloudLogger.Log(logging.Entry{
		Severity: logging.Info,
		Payload:  fmt.Sprintf(format, a...) + "\n",
	})
}

// Warnf prints Warning level log, defaults to stdout if GCP logger is not set
func (wrapper Wrapper) Warnf(format string, a ...any) {
	if wrapper.GCloudLogger == nil || wrapper.ForceLocalLogging {
		log.Printf("[Warning] "+format, a...)
		return
	}

	wrapper.GCloudLogger.Log(logging.Entry{
		Severity: logging.Warning,
		Payload:  fmt.Sprintf(format, a...) + "\n",
	})
}

// Errorf prints Error level log
func (wrapper Wrapper) Errorf(format string, a ...any) {
	if wrapper.GCloudLogger == nil || wrapper.ForceLocalLogging {
		log.Printf("[Error] "+format, a...)
		return
	}

	wrapper.GCloudLogger.Log(logging.Entry{
		Severity: logging.Error,
		Payload:  fmt.Sprintf(format, a...) + "\n",
	})
}

// Fatalf prints Error level log with stack trace, before exiting with error code 1
func (wrapper Wrapper) Fatalf(format string, a ...any) {
	if wrapper.GCloudLogger == nil || wrapper.ForceLocalLogging {
		log.Fatalf("[Fatal] "+format, a...)
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

// Panicf prints Error level log with stack trace, before panicing
func (wrapper Wrapper) Panicf(format string, a ...any) {
	if wrapper.GCloudLogger == nil || wrapper.ForceLocalLogging {
		log.Panicf("[Panic] "+format, a...)
		return
	}

	wrapper.GCloudLogger.Log(logging.Entry{
		Severity: logging.Error,
		Payload:  fmt.Sprintf(format, a...) + "\n" + string(debug.Stack()),
	})
	err := wrapper.GCloudLogger.Flush()
	if err != nil {
		log.Panicln("Failed to flush logger")
	}
	panic(nil)
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

// Panicf prints Error level log with stack trace, before panicing
func Panicf(format string, a ...any) {
	GlobalLogger.Panicf(format, a...)
}
