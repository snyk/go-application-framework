package configuration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_JsonStorage_BlankFileOption(t *testing.T) {
	dir := t.TempDir()

	t.Run("off: a blank file fails a persisted write", func(t *testing.T) {
		file := filepath.Join(dir, "off.json")
		require.NoError(t, os.WriteFile(file, []byte(" \n\t"), 0o644))
		assert.Error(t, NewJsonStorage(file).Set("a", "x"))
	})

	t.Run("on: a blank file is an empty file", func(t *testing.T) {
		file := filepath.Join(dir, "on.json")
		require.NoError(t, os.WriteFile(file, []byte(" \n\t"), 0o644))
		require.NoError(t, NewJsonStorage(file, withBlankFileAsEmpty()).Set("a", "x"))
		assert.JSONEq(t, `{"a":"x"}`, readFileString(t, file))
	})

	t.Run("on: a file with content is unchanged by the option", func(t *testing.T) {
		file := filepath.Join(dir, "content.json")
		require.NoError(t, os.WriteFile(file, []byte(`{"b":"y"}`), 0o644))
		require.NoError(t, NewJsonStorage(file, withBlankFileAsEmpty()).Set("a", "x"))
		assert.JSONEq(t, `{"a":"x","b":"y"}`, readFileString(t, file))
	})
}

func Test_JsonStorage_ExactNumbersOption(t *testing.T) {
	dir := t.TempDir()

	t.Run("off: other numbers are rounded to float64", func(t *testing.T) {
		file := filepath.Join(dir, "off.json")
		require.NoError(t, os.WriteFile(file, []byte(`{"big":9007199254740993}`), 0o644))
		require.NoError(t, NewJsonStorage(file).Set("other", "x"))
		assert.Contains(t, readFileString(t, file), "9007199254740992")
	})

	t.Run("on: other numbers keep their text", func(t *testing.T) {
		file := filepath.Join(dir, "on.json")
		require.NoError(t, os.WriteFile(file, []byte(`{"id":12345678901234567890,"big":9007199254740993}`), 0o644))
		require.NoError(t, NewJsonStorage(file, withExactNumbers()).Set("other", "x"))
		content := readFileString(t, file)
		assert.Contains(t, content, "12345678901234567890")
		assert.Contains(t, content, "9007199254740993")
	})

	t.Run("on: trailing data still fails a write, as by default", func(t *testing.T) {
		file := filepath.Join(dir, "trailing.json")
		require.NoError(t, os.WriteFile(file, []byte(`{"a":1} {"b":2}`), 0o644))
		assert.Error(t, NewJsonStorage(file, withExactNumbers()).Set("c", "x"))
		assert.Equal(t, `{"a":1} {"b":2}`, readFileString(t, file))
	})
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(content)
}

func Test_JsonStorage_BlankFileOption_OnlyJSONWhiteSpaceIsBlank(t *testing.T) {
	file := filepath.Join(t.TempDir(), "vertical-tab.json")
	require.NoError(t, os.WriteFile(file, []byte("\v"), 0o644))
	assert.Error(t, NewJsonStorage(file, withBlankFileAsEmpty()).Set("a", "x"), "a vertical tab is not JSON white space")
	assert.Equal(t, "\v", readFileString(t, file))
}

func Test_JsonStorage_ExactNumbersOption_NullAndWhiteSpace(t *testing.T) {
	dir := t.TempDir()

	t.Run("null is an empty document", func(t *testing.T) {
		file := filepath.Join(dir, "null.json")
		require.NoError(t, os.WriteFile(file, []byte("null"), 0o644))
		require.NoError(t, NewJsonStorage(file, withExactNumbers()).Set("a", "x"))
		assert.JSONEq(t, `{"a":"x"}`, readFileString(t, file))
	})

	t.Run("trailing white space is accepted", func(t *testing.T) {
		file := filepath.Join(dir, "spaces.json")
		require.NoError(t, os.WriteFile(file, []byte("{\"a\":1} \n\t"), 0o644))
		require.NoError(t, NewJsonStorage(file, withExactNumbers()).Set("b", "x"))
		assert.JSONEq(t, `{"a":1,"b":"x"}`, readFileString(t, file))
	})
}
