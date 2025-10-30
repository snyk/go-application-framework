package filters //nolint:testpackage // Testing private utility functions.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClients(t *testing.T) {
	tests := []struct {
		getClient  func(t *testing.T, orgID uuid.UUID, expectedAllow AllowList) (Client, func())
		clientName string
	}{
		{
			clientName: "deeproxyClient",
			getClient: func(t *testing.T, orgID uuid.UUID, expectedAllow AllowList) (Client, func()) {
				t.Helper()

				s := setupServer(t, orgID, expectedAllow)
				cleanup := func() {
					s.Close()
				}
				c := NewDeeproxyClient(Config{BaseURL: s.URL, IsFedRamp: true}, WithHTTPClient(s.Client()))

				return c, cleanup
			},
		},
		{
			clientName: "fakeClient",
			getClient: func(t *testing.T, _ uuid.UUID, expectedAllow AllowList) (Client, func()) {
				t.Helper()

				c := NewFakeClient(expectedAllow, nil)

				return c, func() {}
			},
		},
	}

	for _, testData := range tests {
		t.Run(testData.clientName+": GetFilters", func(t *testing.T) {
			orgID := uuid.New()
			expectedAllow := AllowList{
				ConfigFiles: []string{"package.json"},
				Extensions:  []string{".ts", ".js"},
			}
			client, cleanup := testData.getClient(t, orgID, expectedAllow)
			defer cleanup()

			allow, err := client.GetFilters(t.Context(), orgID)
			require.NoError(t, err)

			assert.Equal(t, expectedAllow, allow)
		})
	}
}

func setupServer(t *testing.T, orgID uuid.UUID, expectedAllow AllowList) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedURL := getFilterURL("", orgID, true)
		assert.Equal(t, expectedURL, r.URL.Path)
		assert.Equal(t, orgID.String(), r.Header.Get("snyk-org-name"))
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(expectedAllow); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
			return
		}
	}))
	ts.Start()
	return ts
}
