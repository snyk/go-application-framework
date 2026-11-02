package localworkflows

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

const maxStdinSecretSize = 64 * 1024

var (
	errStdinTerminal = errors.New(`--stdin expects piped input, but stdin is a terminal; pipe the secret in, for example: echo "$SECRET" | snyk auth --stdin`)
	errStdinTooLarge = fmt.Errorf("the input on stdin is too large: --stdin accepts at most %d KiB; pipe only the secret", maxStdinSecretSize/1024)
	errStdinEmpty    = errors.New("stdin was empty, but --stdin needs the secret piped in; check that the variable or file you pipe holds the secret")
)

// readSecretFromStdin returns the secret piped into stdin, without one trailing LF or CRLF.
func readSecretFromStdin(stdin *os.File) (string, error) {
	if term.IsTerminal(int(stdin.Fd())) {
		return "", errStdinTerminal
	}
	data, err := io.ReadAll(io.LimitReader(stdin, maxStdinSecretSize+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxStdinSecretSize {
		return "", errStdinTooLarge
	}
	secret, hadLF := strings.CutSuffix(string(data), "\n")
	if hadLF {
		secret = strings.TrimSuffix(secret, "\r")
	}
	if secret == "" {
		return "", errStdinEmpty
	}
	return secret, nil
}
