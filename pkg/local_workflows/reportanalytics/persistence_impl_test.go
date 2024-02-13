package reportanalytics

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func Test_GetDatabase(t *testing.T) {
	conf := configuration.NewInMemory()
	conf.Set(configuration.CACHE_PATH, t.TempDir())

	database, err := GetDatabase(conf, "huhu", t.Name())

	require.NoError(t, err)
	require.NotNil(t, database)

	err = database.Ping()
	require.NoError(t, err)
}
