package fileupload

import (
	"iter"
	"os"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/internal/api/fileupload/uploadrevision"
	"github.com/snyk/go-application-framework/pkg/utils"
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
	batch        *uploadBatch
	skippedFiles []SkippedFile
}

func batchPaths(
	rootPath string,
	paths <-chan string,
	limits uploadrevision.Limits,
	logger *zerolog.Logger,
	filters ...filter,
) iter.Seq[*batchingResult] {
	return func(yield func(*batchingResult) bool) {
		batch := newUploadBatch(limits)
		skipped := []SkippedFile{}
		batchNumber := 0
		logger.Debug().
			Int("file_count_limit", limits.FileCountLimit).
			Int64("file_size_limit_bytes", limits.FileSizeLimit).
			Int64("total_payload_limit_bytes", limits.TotalPayloadSizeLimit).
			Msg("Starting file batching")
		for path := range paths {
			relPath, err := utils.ToRelativeUnixPath(rootPath, path)
			if err != nil {
				logger.Debug().Msgf("failed to get relative unix path for file: %s", path)
				skipped = append(skipped, SkippedFile{Path: path, Reason: uploadrevision.NewFileAccessError(path, err)})
				continue
			}

			f, err := os.Open(path)
			if err != nil {
				logger.Debug().Msgf("failed to open file: %s", path)
				f.Close()
				skipped = append(skipped, SkippedFile{Path: relPath, Reason: uploadrevision.NewFileAccessError(path, err)})
				continue
			}

			fstat, err := f.Stat()
			if err != nil {
				logger.Debug().Msgf("failed to stat file: %s", path)
				f.Close()
				skipped = append(skipped, SkippedFile{Path: relPath, Reason: uploadrevision.NewFileAccessError(path, err)})
				continue
			}

			ff := applyFilters(fileToFilter{Path: relPath, Stat: fstat}, filters...)
			if ff != nil {
				f.Close()
				skipped = append(skipped, *ff)
				continue
			}

			if batch.wouldExceedLimits(fstat.Size()) {
				batchNumber++
				logger.Debug().
					Int("batch_number", batchNumber).
					Int("file_count", len(batch.files)).
					Int64("total_size_bytes", batch.currentSize).
					Msg("Batch complete, starting new batch")
				if !yield(&batchingResult{batch: batch, skippedFiles: skipped}) {
					return
				}
				batch = newUploadBatch(limits)
				skipped = []SkippedFile{}
			}

			batch.addFile(uploadrevision.UploadFile{
				Path: relPath,
				File: f,
			}, fstat.Size())
		}

		if !batch.isEmpty() || len(skipped) > 0 {
			yield(&batchingResult{batch: batch, skippedFiles: skipped})
		}
	}
}

func applyFilters(ff fileToFilter, filters ...filter) *SkippedFile {
	for _, filter := range filters {
		if ff := filter(ff); ff != nil {
			return ff
		}
	}

	return nil
}
