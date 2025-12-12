package fileupload

import (
	"iter"
	"os"
	"path/filepath"

	"github.com/snyk/go-application-framework/internal/api/fileupload/uploadrevision"
)

// uploadBatch manages a batch of files for upload.
type uploadBatch struct {
	files       []uploadrevision.UploadFile
	currentSize int64
	limits      uploadrevision.Limits
}

func newUploadBatch(limits uploadrevision.Limits) *uploadBatch {
	return &uploadBatch{
		files:  make([]uploadrevision.UploadFile, 0, limits.FileCountLimit),
		limits: limits,
	}
}

func (b *uploadBatch) addFile(file uploadrevision.UploadFile, fileSize int64) {
	b.files = append(b.files, file)
	b.currentSize += fileSize
}

func (b *uploadBatch) wouldExceedLimits(fileSize int64) bool {
	wouldExceedCount := len(b.files) >= b.limits.FileCountLimit
	wouldExceedSize := b.currentSize+fileSize > b.limits.TotalPayloadSizeLimit
	return wouldExceedCount || wouldExceedSize
}

func (b *uploadBatch) isEmpty() bool {
	return len(b.files) == 0
}

func (b *uploadBatch) closeRemainingFiles() {
	for _, file := range b.files {
		file.File.Close()
	}
}

type batchingResult struct {
	batch         *uploadBatch
	filteredFiles []FilteredFile
}

func batchPaths(rootPath string, paths <-chan string, limits uploadrevision.Limits, filters ...filter) iter.Seq2[*batchingResult, error] {
	return func(yield func(*batchingResult, error) bool) {
		batch := newUploadBatch(limits)
		filtered := []FilteredFile{}
		for path := range paths {
			relPath, err := filepath.Rel(rootPath, path)
			if err != nil {
				if !yield(&batchingResult{batch: batch, filteredFiles: filtered}, uploadrevision.NewFileAccessError(path, err)) {
					return
				}
			}

			f, err := os.Open(path)
			if err != nil {
				f.Close()
				if !yield(&batchingResult{batch: batch, filteredFiles: filtered}, uploadrevision.NewFileAccessError(path, err)) {
					return
				}
			}

			fstat, err := f.Stat()
			if err != nil {
				f.Close()
				if !yield(&batchingResult{batch: batch, filteredFiles: filtered}, uploadrevision.NewFileAccessError(path, err)) {
					return
				}
			}

			ff := applyFilters(fileToFilter{Path: relPath, Stat: fstat}, filters...)
			if ff != nil {
				f.Close()
				filtered = append(filtered, *ff)
				continue
			}

			if batch.wouldExceedLimits(fstat.Size()) {
				if !yield(&batchingResult{batch: batch, filteredFiles: filtered}, nil) {
					return
				}
				batch = newUploadBatch(limits)
				filtered = []FilteredFile{}
			}

			batch.addFile(uploadrevision.UploadFile{
				Path: relPath,
				File: f,
			}, fstat.Size())
		}

		if !batch.isEmpty() || len(filtered) > 0 {
			yield(&batchingResult{batch: batch, filteredFiles: filtered}, nil)
		}
	}
}

func applyFilters(ff fileToFilter, filters ...filter) *FilteredFile {
	for _, filter := range filters {
		if ff := filter(ff); ff != nil {
			return ff
		}
	}

	return nil
}
