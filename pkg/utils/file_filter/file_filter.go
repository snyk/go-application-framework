package file_filter

import (
	"context"
	"fmt"
	"github.com/rs/zerolog"
	"golang.org/x/sync/semaphore"
	"io/fs"
	"path/filepath"
	"runtime"
)

type Filterable interface {
	Filter(path string) bool
}

type FileFilter struct {
	path             string
	logger           *zerolog.Logger
	filterStrategies []Filterable
	max_threads      int64
}

type FileFilterOption func(*FileFilter) error

func WithThreadNumber(maxThreadCount int) FileFilterOption {
	return func(filter *FileFilter) error {
		if maxThreadCount > 0 {
			filter.max_threads = int64(maxThreadCount)
			return nil
		}

		return fmt.Errorf("max thread count must be greater than 0")
	}
}

func WithFileFilterStrategies(strategies []Filterable) FileFilterOption {
	return func(filter *FileFilter) error {
		filter.filterStrategies = append(filter.filterStrategies, strategies...)
		return nil
	}
}

func WithSecretsFileFilter(path string, logger *zerolog.Logger) FileFilterOption {
	return func(filter *FileFilter) error {
		secretsFilter, err := NewSecretsFileFilter(path, logger)
		if err != nil {
			return fmt.Errorf("error creating secrets filter: %w", err)

		}
		filter.filterStrategies = append(filter.filterStrategies, secretsFilter...)
		return nil
	}
}

func WithDefaultRulesFilter() FileFilterOption {
	return func(filter *FileFilter) error {
		defaultFilter, err := NewIgnoresFileFilterFromGlobs([]string{"**/.git/**"})
		if err != nil {
			return fmt.Errorf("error creating default filter: %w", err)

		}

		filter.filterStrategies = append(filter.filterStrategies, defaultFilter)
		return nil
	}
}

func NewFileFilter(path string, logger *zerolog.Logger, options ...FileFilterOption) *FileFilter {
	filter := &FileFilter{
		path:        path,
		logger:      logger,
		max_threads: int64(runtime.NumCPU()),
	}

	for _, option := range options {
		err := option(filter)
		if err != nil {
			logger.Err(err).Msg("failed to apply option for FileFilter")
		}
	}

	return filter
}

// GetAllFiles traverses a given dir path and fetches all filesToFilter in the directory
func (fw *FileFilter) GetAllFiles() chan string {
	var filesCh = make(chan string)
	go func() {
		defer close(filesCh)

		err := filepath.WalkDir(fw.path, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if !d.IsDir() {
				filesCh <- path
			}

			return err
		})
		if err != nil {
			fw.logger.Error().Msgf("walk dir failed: %v", err)
		}
	}()

	return filesCh
}

// GetFilteredFiles returns a filtered channel of filepaths from a given channel of filespaths and glob patterns to filter on
func (fw *FileFilter) GetFilteredFiles(filesCh chan string) chan string {
	var filteredFilesCh = make(chan string)

	go func() {
		ctx := context.Background()
		availableThreads := semaphore.NewWeighted(fw.max_threads)

		defer close(filteredFilesCh)

		// iterate the filesToFilter channel
		for file := range filesCh {
			err := availableThreads.Acquire(ctx, 1)
			if err != nil {
				fw.logger.Err(err).Msg("failed to limit threads")
			}
			go func(f string) {
				defer availableThreads.Release(1)
				// filesToFilter that do not match the filter list are excluded
				keepFile := true
				for _, filter := range fw.filterStrategies {
					if filter.Filter(f) {
						keepFile = false
						break
					}
				}

				if keepFile {
					filteredFilesCh <- f
				}
			}(file)
		}

		// wait until the last thread is done
		err := availableThreads.Acquire(ctx, fw.max_threads)
		if err != nil {
			fw.logger.Err(err).Msg("failed to wait for all threads")
		}
	}()

	return filteredFilesCh
}
