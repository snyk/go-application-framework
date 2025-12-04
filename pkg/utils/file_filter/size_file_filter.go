package file_filter

import (
	"github.com/rs/zerolog"
	"os"
)

type FileSizeFilter struct {
	maxSize int64
	logger  *zerolog.Logger
}

func NewFileSizeFilter(logger *zerolog.Logger, maxSize int64) *FileSizeFilter {
	return &FileSizeFilter{
		maxSize: maxSize,
		logger:  logger,
	}
}

func (f *FileSizeFilter) Filter(path string) bool {
	// Get file size
	info, statErr := os.Stat(path)
	if statErr != nil {
		// Filters are enforced, we should exclude any files that we can't classify
		f.logger.Error().Msgf("failed to get file stats: %v", statErr)
		return true
	}
	size := info.Size()
	if size == 0 || size > f.maxSize {
		return true
	}
	return false
}
