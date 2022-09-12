package utility

import (
	"fmt"
	"log"
	"os"
	"runtime/debug"

	"cloud.google.com/go/logging"
)

type LoggerWrapper struct {
	Logger *logging.Logger
}

type Logger logging.Logger

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
