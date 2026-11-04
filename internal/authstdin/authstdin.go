// Package authstdin reads the auth workflow's secret from stdin.
package authstdin

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/snyk/error-catalog-golang-public/cli"
	"golang.org/x/term"
)

// Far above the largest PEM private key; stops a wrong pipe, such as a log file, from being read into memory.
const maxSecretSize = 64 * 1024

// ReadSecret returns the secret piped into stdin, without one trailing LF or CRLF.
func ReadSecret(stdin *os.File) (string, error) {
	if term.IsTerminal(int(stdin.Fd())) {
		return "", cli.NewInvalidFlagOptionError(`--stdin expects piped input, but stdin is a terminal; pipe the secret in, for example: echo "$SECRET" | snyk auth --stdin`)
	}
	data, err := io.ReadAll(io.LimitReader(stdin, maxSecretSize+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxSecretSize {
		return "", cli.NewInvalidFlagOptionError(fmt.Sprintf("the input on stdin is too large: --stdin accepts at most %d KiB; pipe only the secret", maxSecretSize/1024))
	}
	secret, hadLF := strings.CutSuffix(string(data), "\n")
	if hadLF {
		secret = strings.TrimSuffix(secret, "\r")
	}
	if secret == "" {
		return "", cli.NewInvalidFlagOptionError("stdin was empty, but --stdin needs the secret piped in; check that the variable or file you pipe holds the secret")
	}
	return secret, nil
}
