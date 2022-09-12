package utility

import (
	"fmt"
	"log"
	"os"
	"runtime/debug"

	"cloud.google.com/go/logging"
)

type Logger logging.Logger

func InfoLogf(logger *logging.Logger, format string, a ...any) {
	logger.Log(logging.Entry{
		Severity: logging.Info,
		Payload:  fmt.Sprintf(format, a) + "\n",
	})
}

func FatalLogf(logger *logging.Logger, format string, a ...any) {
	logger.Log(logging.Entry{
		Severity: logging.Error,
		Payload:  fmt.Sprintf(format, a) + "\n" + string(debug.Stack()),
	})
	err := logger.Flush()
	if err != nil {
		log.Fatalln("Failed to flush logger")
	}
	os.Exit(1)
}
