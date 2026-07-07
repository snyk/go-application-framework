package diagnosis

import (
	"fmt"
	"io"
	"os"

	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// OpenInput returns an io.ReadCloser for the debug log. If inputPath is set,
// the file at that path is opened. Otherwise, stdin is returned directly.
// The caller is responsible for gating the call (e.g. via --stdin / --input).
func OpenInput(inputPath string, stdin io.Reader) (io.ReadCloser, error) {
	if inputPath != "" {
		f, err := os.Open(inputPath)
		if err != nil {
			return nil, cli.NewGeneralCLIFailureError(
				fmt.Sprintf("Could not read the debug log file at '%s'. Check that the path is correct and the file is readable.", inputPath),
				snyk_errors.WithCause(err),
			)
		}
		return f, nil
	}

	return io.NopCloser(stdin), nil
}
