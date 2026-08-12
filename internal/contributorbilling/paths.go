package contributorbilling

import (
	"path/filepath"

	zlog "github.com/rs/zerolog/log"
)

func resolveRepoPath(path string) string {
	if path == "" {
		path = "."
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		zlog.Warn().Err(err).Str("path", path).Msg("contributor billing: failed to resolve repo path to absolute")
		return path
	}

	return abs
}
