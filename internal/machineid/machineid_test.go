package machineid

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerate(t *testing.T) {
	id := generate()
	require.True(t, valid(id))
	require.Equal(t, strings.ToLower(id), id, "generated id must be lowercase")

	other := generate()
	require.NotEqual(t, id, other, "successive calls must produce distinct ids")
}
