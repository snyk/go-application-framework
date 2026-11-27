package fileupload

import (
	"bytes"
	"errors"
	"io"
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

func (b *uploadBatch) addFile(file uploadrevision.UploadFile) {
	b.files = append(b.files, file)
	b.currentSize += file.Size
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

// errFileChanged reports that the file at a path is not the one that was checked before it was read.
var errFileChanged = errors.New("file changed while it was opened")

// readAndTranscode reads the file at path, named name in errors, and refuses to read through a symlink.
// Batched files are read when they are streamed, long after they were checked, so the path may have been
// replaced meanwhile. Like openLargeFile, the type is decided before the open, because opening a swapped-in
// named pipe would block. The opened file must be the one the path currently names; comparing with a fresh
// Lstat rather than with the identity from batching keeps editors' atomic-rename saves working.
func readAndTranscode(path, name string, transcode ContentTranscoder) ([]byte, error) {
	current, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if current.Mode()&os.ModeSymlink != 0 {
		return nil, uploadrevision.NewSymlinkError(name)
	}
	if !current.Mode().IsRegular() {
		return nil, uploadrevision.NewSpecialFileError(name, current.Mode())
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(current, opened) {
		return nil, uploadrevision.NewFileAccessError(name, errFileChanged)
	}

	content, err := io.ReadAll(file)
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
	name      string
	transcode ContentTranscoder
	content   *bytes.Reader
}

func (r *transcodedFileReader) Read(p []byte) (int, error) {
	if r.content == nil {
		content, err := readAndTranscode(r.path, r.name, r.transcode)
		if err != nil {
			return 0, err
		}
		r.content = bytes.NewReader(content)
	}

	return r.content.Read(p)
}

// createUploadFile turns a filesystem path into the file to upload, or reports why it cannot be
// uploaded. The returned file holds no content and no descriptor; both are produced when it is
// streamed.
func createUploadFile(
	rootPath string,
	path string,
	encodePath PathEncoder,
	transcode ContentTranscoder,
) (uploadrevision.UploadFile, *SkippedFile) {
	relPath, err := utils.ToRelativeUnixPath(rootPath, path)
	if err != nil {
		// relPath is not known yet, so the raw path is the best identifier available.
		return uploadrevision.UploadFile{}, &SkippedFile{Path: path, Reason: uploadrevision.NewFileAccessError(path, err)}
	}

	relPath = encodePath(relPath)

	info, err := os.Lstat(path)
	if err != nil {
		return uploadrevision.UploadFile{}, &SkippedFile{Path: relPath, Reason: uploadrevision.NewFileAccessError(path, err)}
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return uploadrevision.UploadFile{}, &SkippedFile{Path: relPath, Reason: uploadrevision.NewSymlinkError(relPath)}
	}

	// Reading a device file would never return, so this has to be decided before the read.
	if !info.Mode().IsRegular() {
		return uploadrevision.UploadFile{}, &SkippedFile{Path: relPath, Reason: uploadrevision.NewSpecialFileError(relPath, info.Mode())}
	}

	if err := checkReadable(path); err != nil {
		return uploadrevision.UploadFile{}, &SkippedFile{Path: relPath, Reason: uploadrevision.NewFileAccessError(path, err)}
	}

	// Without a transcoder the uploaded content is the file as it is on disk, so the stat above
	// already gives its size and the file does not need reading here.
	fileSize := info.Size()
	if transcode != nil {
		content, err := readAndTranscode(path, relPath, transcode)
		if err != nil {
			return uploadrevision.UploadFile{}, &SkippedFile{Path: relPath, Reason: uploadrevision.NewFileAccessError(path, err)}
		}
		fileSize = int64(len(content))
	}

	return uploadrevision.UploadFile{
		Path:   relPath,
		Size:   fileSize,
		Reader: &transcodedFileReader{path: path, name: relPath, transcode: transcode},
	}, nil
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
			file, skippedFile := createUploadFile(rootPath, path, pathEncoder, contentTranscoder)
			if skippedFile != nil {
				logger.Debug().Err(skippedFile.Reason).Msgf("skipping file: %s", path)
				skipped = append(skipped, *skippedFile)
				continue
			}

			ff := applyFilters(fileToFilter{Path: file.Path, Size: file.Size}, filters...)
			if ff != nil {
				skipped = append(skipped, *ff)
				continue
			}

			if batch.wouldExceedLimits(file.Size) {
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

			batch.addFile(file)
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
