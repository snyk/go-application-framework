// OS interface wrappers

package utils

import (
	"log"
	"strings"

	"github.com/rs/zerolog"
)

// since the are a couple of places that take different types of loggers outside of our scope, we introduce these simple wrapper to adapt between the worlds.

// ToZeroLogDebug is an io.Writer that can be used for example in log.Logger to write to an existing zerolog writer
type ToZeroLogDebug struct {
	Logger *zerolog.Logger
}

// Write writes debug messages to the given zerolog logger
func (w *ToZeroLogDebug) Write(p []byte) (n int, err error) {
	w.Logger.Debug().Msg(strings.TrimSpace(string(p)))
	return len(p), nil
}

// ToLog is an io.Writer that can be used to write into a log.Logger, for example from a zerolog.Logger
type ToLog struct {
	Logger *log.Logger
}

func (w *ToLog) Write(p []byte) (n int, err error) {
	w.Logger.Println(strings.TrimSpace(string(p)))
	return len(p), nil
}
