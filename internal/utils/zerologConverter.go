// OS interface wrappers

package utils

import (
	"log"
	"strings"

	"github.com/rs/zerolog"
)

type ToZeroLogDebug struct {
	Logger *zerolog.Logger
}

func (w *ToZeroLogDebug) Write(p []byte) (n int, err error) {
	w.Logger.Debug().Msg(strings.TrimSpace(string(p)))
	return len(p), nil
}

type ToLog struct {
	Logger *log.Logger
}

func (w *ToLog) Write(p []byte) (n int, err error) {
	w.Logger.Println(strings.TrimSpace(string(p)))
	return len(p), nil
}
