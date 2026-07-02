package diagnosis

import (
	"fmt"
	"io"
	"os"

	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// OpenInput returns an io.Reader for the debug log. If inputPath is set, the
// file at that path is opened. Otherwise, stdin is returned (provided it is
// not a terminal).
func OpenInput(inputPath string, stdin io.Reader, isTerminal bool) (io.ReadCloser, error) {
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

	if isTerminal {
		return nil, cli.NewCommandArgsError(
			"No debug log was provided. Pipe one in with 'snyk <command> -d 2>&1 | snyk doctor', or pass a log file with --input <path>.",
		)
	}

	return io.NopCloser(stdin), nil
}
