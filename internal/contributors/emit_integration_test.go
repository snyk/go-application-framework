package contributors

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// TestEmit_ReachesTheIngestEndpoint wires a real Emitter to a real ingest client
// and checks the whole path end to end.
func TestEmit_ReachesTheIngestEndpoint(t *testing.T) {
	var gotPath, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		gotPath = r.URL.Path
		gotBody = string(body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	repo := newTestRepo(t, commit{email: "alice@example.com", when: time.Now().AddDate(0, 0, -1)})

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)

	logger := zerolog.Nop()
	emitter, err := New(server.Client(), config, &logger)
	require.NoError(t, err)

	require.NoError(t, emitter.Emit(t.Context(), repo.path(), testOrgID, validItem()))

	assert.Equal(t, "/hidden/orgs/"+testOrgID.String()+"/contributing_devs", gotPath)
	assert.Contains(t, gotBody, "alice@example.com", "the contributors collected from git must reach the API")
}
