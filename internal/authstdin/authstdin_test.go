package authstdin

import (
	"bytes"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// invalidFlagDetail returns the detail of err, which must be the error catalog's invalid flag option error.
func invalidFlagDetail(t *testing.T, err error) string {
	t.Helper()
	var catalogErr snyk_errors.Error
	require.True(t, errors.As(err, &catalogErr), "error catalog error: %v", err)
	assert.Equal(t, cli.NewInvalidFlagOptionError("").ErrorCode, catalogErr.ErrorCode)
	return catalogErr.Detail
}

func stdinWith(t *testing.T, input string) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdin")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	_, err = f.WriteString(input)
	require.NoError(t, err)
	_, err = f.Seek(0, io.SeekStart)
	require.NoError(t, err)
	return f
}

func Test_ReadSecret_echoedValueLosesItsNewline(t *testing.T) {
	secret, err := ReadSecret(stdinWith(t, "my-client-secret\n"))

	require.NoError(t, err)
	assert.Equal(t, "my-client-secret", secret)
}

func Test_ReadSecret_windowsLineEndingIsRemoved(t *testing.T) {
	secret, err := ReadSecret(stdinWith(t, "my-client-secret\r\n"))

	require.NoError(t, err)
	assert.Equal(t, "my-client-secret", secret)
}

func Test_ReadSecret_onlyOneLineEndingIsRemoved(t *testing.T) {
	for name, tc := range map[string]struct{ input, want string }{
		"two trailing newlines": {"my-client-secret\n\n", "my-client-secret\n"},
		"lone carriage return":  {"my-client-secret\r", "my-client-secret\r"},
		"surrounding spaces":    {" my-client-secret \n", " my-client-secret "},
	} {
		t.Run(name, func(t *testing.T) {
			secret, err := ReadSecret(stdinWith(t, tc.input))

			require.NoError(t, err)
			assert.Equal(t, tc.want, secret)
		})
	}
}

func Test_ReadSecret_pemKeepsItsInnerNewlines(t *testing.T) {
	keyPEM := strings.TrimSuffix(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: bytes.Repeat([]byte{0x5a}, 200)})), "\n")
	require.Greater(t, strings.Count(keyPEM, "\n"), 2)

	for name, input := range map[string]string{
		"printf": keyPEM,
		"echo":   keyPEM + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			secret, err := ReadSecret(stdinWith(t, input))

			require.NoError(t, err)
			assert.Equal(t, keyPEM, secret)
		})
	}
}

func Test_ReadSecret_emptyInputIsAnError(t *testing.T) {
	for name, input := range map[string]string{
		"nothing piped":  "",
		"only a newline": "\n",
		"only a CRLF":    "\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ReadSecret(stdinWith(t, input))

			detail := invalidFlagDetail(t, err)
			assert.Contains(t, detail, "stdin was empty")
			assert.Contains(t, detail, "--stdin")
		})
	}
}

func endlessStdin(t *testing.T) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	go func() {
		defer func() { _ = w.Close() }()
		chunk := bytes.Repeat([]byte{'a'}, 4096)
		for {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}()
	return r
}

func Test_ReadSecret_inputOf64KiBIsAccepted(t *testing.T) {
	input := strings.Repeat("a", 64*1024)

	secret, err := ReadSecret(stdinWith(t, input))

	require.NoError(t, err)
	assert.Equal(t, input, secret)
}

func Test_ReadSecret_inputOver64KiBIsTooLarge(t *testing.T) {
	_, err := ReadSecret(stdinWith(t, strings.Repeat("a", 64*1024+1)))

	detail := invalidFlagDetail(t, err)
	assert.Contains(t, detail, "too large")
	assert.Contains(t, detail, "--stdin")
}

func Test_ReadSecret_endlessPipeFailsWithoutReadingItAll(t *testing.T) {
	_, err := ReadSecret(endlessStdin(t))

	assert.Contains(t, invalidFlagDetail(t, err), "too large")
}
