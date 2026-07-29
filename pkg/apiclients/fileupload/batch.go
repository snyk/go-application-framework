package fileupload

import (
	"bytes"
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

type batchingResult struct {
	batch        *uploadBatch
	skippedFiles []SkippedFile
}

func readAndTranscode(path string, transcode ContentTranscoder) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if transcode == nil {
		return content, nil
	}

	return transcode(content)
}

// checkReadable confirms the file can be opened, so that an unreadable file is skipped during
// batching rather than failing the whole batch when it is streamed.
func checkReadable(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	return file.Close()
}

// transcodedFileReader reads and transcodes a file the first time it is read, so that a batched
// file holds neither its content nor a file descriptor until it is streamed.
//
// content is the read cursor, not a cache: ContentTranscoder transforms a whole []byte at once,
// so the transcoded bytes cannot be produced incrementally and have to outlive the individual
// Read calls io.Copy makes. They are released with the batch.
type transcodedFileReader struct {
	path      string
	transcode ContentTranscoder
	content   *bytes.Reader
}

func (r *transcodedFileReader) Read(p []byte) (int, error) {
	if r.content == nil {
		content, err := readAndTranscode(r.path, r.transcode)
		if err != nil {
			return 0, err
		}
		r.content = bytes.NewReader(content)
	}

	return r.content.Read(p)
}

func batchPaths(
	rootPath string,
	paths <-chan string,
	limits uploadrevision.Limits,
	logger *zerolog.Logger,
	pathEncoder PathEncoder,
	contentTranscoder ContentTranscoder,
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

			relPath = pathEncoder(relPath)

			info, err := os.Stat(path)
			if err != nil {
				logger.Debug().Msgf("failed to stat file: %s", path)
				skipped = append(skipped, SkippedFile{Path: relPath, Reason: uploadrevision.NewFileAccessError(path, err)})
				continue
			}

			// Reading a device file would never return, so this has to be decided before the read.
			if !info.Mode().IsRegular() {
				logger.Debug().Msgf("skipping special file: %s", path)
				skipped = append(skipped, SkippedFile{Path: relPath, Reason: uploadrevision.NewSpecialFileError(path, info.Mode())})
				continue
			}

			if err := checkReadable(path); err != nil {
				logger.Debug().Msgf("failed to open file: %s", path)
				skipped = append(skipped, SkippedFile{Path: relPath, Reason: uploadrevision.NewFileAccessError(path, err)})
				continue
			}

			// Without a transcoder the uploaded content is the file as it is on disk, so the
			// stat above already gives its size and the file does not need reading here.
			fileSize := info.Size()
			if contentTranscoder != nil {
				content, err := readAndTranscode(path, contentTranscoder)
				if err != nil {
					logger.Debug().Msgf("failed to read file: %s", path)
					skipped = append(skipped, SkippedFile{Path: relPath, Reason: uploadrevision.NewFileAccessError(path, err)})
					continue
				}
				fileSize = int64(len(content))
			}

			ff := applyFilters(fileToFilter{Path: relPath, Size: fileSize}, filters...)
			if ff != nil {
				skipped = append(skipped, *ff)
				continue
			}

			if batch.wouldExceedLimits(fileSize) {
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
				Path:   relPath,
				Size:   fileSize,
				Reader: &transcodedFileReader{path: path, transcode: contentTranscoder},
			}, fileSize)
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
