// OS interface wrappers

package utils

import (
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
