package machineid

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestGenerate(t *testing.T) {
	id := generate()
	require.True(t, valid(id))
	require.Equal(t, strings.ToLower(id), id, "generated id must be lowercase")

	other := generate()
	require.NotEqual(t, id, other, "successive calls must produce distinct ids")
}

func TestSerialStoreFailuresAreLoggedAtTheLevelTheirCauseAndLocationCallFor(t *testing.T) {
	missing := &fs.PathError{Op: "mkdir", Path: "x", Err: fs.ErrNotExist}
	denied := &fs.PathError{Op: "open", Path: "x", Err: fs.ErrPermission}
	diskFull := errors.New("disk full")
	newerSchema := fmt.Errorf("x: %w", errNewerSchema)
	const stored = "store failed"
	const newer = "machine id: shared file was written by a newer or unknown schema, left unchanged"

	for name, tc := range map[string]struct {
		err         error
		machineWide bool
		level       string
		message     string
	}{
		"missing per-user location":           {missing, false, `"level":"warn"`, stored},
		"missing machine-wide location":       {missing, true, `"level":"debug"`, stored},
		"per-user permission denied":          {denied, false, `"level":"debug"`, stored},
		"machine-wide permission denied":      {denied, true, `"level":"debug"`, stored},
		"other per-user failure":              {diskFull, false, `"level":"warn"`, stored},
		"other machine-wide failure":          {diskFull, true, `"level":"warn"`, stored},
		"newer schema at per-user location":   {newerSchema, false, `"level":"warn"`, newer},
		"newer schema at machine-wide":        {newerSchema, true, `"level":"warn"`, newer},
		"no failure at per-user location":     {nil, false, "", ""},
		"no failure at machine-wide location": {nil, true, "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

			logSerialStoreFailure(&logger, tc.err, "path", stored, tc.machineWide)

			if tc.level == "" {
				require.Empty(t, logs.String())
				return
			}
			require.Contains(t, logs.String(), tc.level)
			require.Contains(t, logs.String(), `"message":"`+tc.message+`"`)
		})
	}
}
