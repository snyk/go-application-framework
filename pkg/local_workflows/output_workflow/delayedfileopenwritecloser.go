package output_workflow

import (
	"io"
	"os"

	iUtils "github.com/snyk/go-application-framework/internal/utils"
)

type delayedFileOpenWriteCloser struct {
	Filename string
	file     io.WriteCloser
}

func (wc *delayedFileOpenWriteCloser) Write(p []byte) (n int, err error) {
	// lazy open file if not exists
	if wc.file == nil {
		pathError := iUtils.CreateFilePath(wc.Filename)
		if pathError != nil {
			return 0, pathError
		}

		file, fileErr := os.OpenFile(wc.Filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, iUtils.FILEPERM_666)
		if fileErr != nil {
			return 0, fileErr
		}

		wc.file = file
	}

	return wc.file.Write(p)
}

func (wc *delayedFileOpenWriteCloser) Close() error {
	if wc.file != nil {
		return wc.file.Close()
	}
	return nil
}
