package localworkflows

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func Test_readSecretFromStdin_echoedValueLosesItsNewline(t *testing.T) {
	secret, err := readSecretFromStdin(stdinWith(t, "my-client-secret\n"))

	require.NoError(t, err)
	assert.Equal(t, "my-client-secret", secret)
}

func Test_readSecretFromStdin_windowsLineEndingIsRemoved(t *testing.T) {
	secret, err := readSecretFromStdin(stdinWith(t, "my-client-secret\r\n"))

	require.NoError(t, err)
	assert.Equal(t, "my-client-secret", secret)
}

func Test_readSecretFromStdin_onlyOneLineEndingIsRemoved(t *testing.T) {
	for name, tc := range map[string]struct{ input, want string }{
		"two trailing newlines": {"my-client-secret\n\n", "my-client-secret\n"},
		"lone carriage return":  {"my-client-secret\r", "my-client-secret\r"},
		"surrounding spaces":    {" my-client-secret \n", " my-client-secret "},
	} {
		t.Run(name, func(t *testing.T) {
			secret, err := readSecretFromStdin(stdinWith(t, tc.input))

			require.NoError(t, err)
			assert.Equal(t, tc.want, secret)
		})
	}
}

func Test_readSecretFromStdin_pemKeepsItsInnerNewlines(t *testing.T) {
	keyPEM := strings.TrimSuffix(pemOf(t, "PRIVATE KEY", bytes.Repeat([]byte{0x5a}, 200)), "\n")
	require.Greater(t, strings.Count(keyPEM, "\n"), 2)

	for name, input := range map[string]string{
		"printf": keyPEM,
		"echo":   keyPEM + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			secret, err := readSecretFromStdin(stdinWith(t, input))

			require.NoError(t, err)
			assert.Equal(t, keyPEM, secret)
		})
	}
}

func Test_readSecretFromStdin_emptyInputIsAnError(t *testing.T) {
	for name, input := range map[string]string{
		"nothing piped":  "",
		"only a newline": "\n",
		"only a CRLF":    "\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := readSecretFromStdin(stdinWith(t, input))

			require.Error(t, err)
			assert.Contains(t, err.Error(), "stdin was empty")
			assert.Contains(t, err.Error(), "--stdin")
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

func Test_readSecretFromStdin_inputOf64KiBIsAccepted(t *testing.T) {
	input := strings.Repeat("a", 64*1024)

	secret, err := readSecretFromStdin(stdinWith(t, input))

	require.NoError(t, err)
	assert.Equal(t, input, secret)
}

func Test_readSecretFromStdin_inputOver64KiBIsTooLarge(t *testing.T) {
	_, err := readSecretFromStdin(stdinWith(t, strings.Repeat("a", 64*1024+1)))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
	assert.Contains(t, err.Error(), "--stdin")
}

func Test_readSecretFromStdin_endlessPipeFailsWithoutReadingItAll(t *testing.T) {
	_, err := readSecretFromStdin(endlessStdin(t))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}
