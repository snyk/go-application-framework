package config_utils

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jws"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

func Test_CheckSanity_ApiUrl(t *testing.T) {
	expectedAudience := "hello.world"
	header := &jws.Header{}
	claims := &jws.ClaimSet{
		Aud: expectedAudience,
	}
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	accessToken, err := jws.Encode(header, claims, pk)
	assert.NoError(t, err)

	token := oauth2.Token{
		AccessToken: accessToken,
	}

	tokenBytes, err := json.Marshal(token)
	assert.NoError(t, err)

	t.Run("different url from auth material", func(t *testing.T) {
		// Create a configuration with duplicate keys
		config := configuration.NewWithOpts()
		config.Set(configuration.API_URL, "https://api1.example.com")
		config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, string(tokenBytes))

		result := CheckSanity(config)

		expectedDescription := fmt.Sprintf(configCheckMismatchedUrlMsg, "SNYK_API")
		assert.Len(t, result, 1)
		assert.Contains(t, result[0].Description, expectedDescription)
	})

	t.Run("same url auth material", func(t *testing.T) {
		// Create a configuration with duplicate keys
		config := configuration.NewWithOpts()
		config.Set(configuration.API_URL, expectedAudience)
		config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, string(tokenBytes))

		result := CheckSanity(config)
		assert.Len(t, result, 0)
	})

	t.Run("no auth material", func(t *testing.T) {
		// Create a configuration with duplicate keys
		config := configuration.NewWithOpts()
		config.Set(configuration.API_URL, expectedAudience)

		result := CheckSanity(config)
		assert.Len(t, result, 0)
	})
}

func Test_CheckSanity_Token(t *testing.T) {
	alternativeTokenVariable := "my_token"
	expectedDescription := "Possible unexpected behavior, the following configuration values might override each other "

	config := configuration.NewWithOpts()
	config.Set(configuration.AUTHENTICATION_TOKEN, "random1")
	config.Set(alternativeTokenVariable, "random2")
	config.AddAlternativeKeys(configuration.AUTHENTICATION_TOKEN, []string{alternativeTokenVariable})

	result := CheckSanity(config)
	assert.Len(t, result, 1)

	assert.Contains(t, result[0].Description, expectedDescription)
}

func Test_CheckSanity_Tenant(t *testing.T) {
	alternativeTenantVariable := "snyk_cfg_tenant"

	config := configuration.NewWithOpts()
	config.Set(configuration.TENANT, "tenant1")
	config.Set(alternativeTenantVariable, "tenant2")
	config.AddAlternativeKeys(configuration.TENANT, []string{alternativeTenantVariable})

	result := CheckSanity(config)
	require.Len(t, result, 1)

	assert.Contains(t, result[0].Description, "might override each other TENANT, SNYK_CFG_TENANT")
}

func Test_CheckSanity_IgnoredWorkingDirectoryFile(t *testing.T) {
	tests := []struct {
		name     string
		store    bool                                                     // a configstore snyk.json exists
		opt      func(t *testing.T, workingDir string) configuration.Opts // nil for WithFiles("snyk")
		reported bool
	}{
		{name: "only_in_the_working_directory", reported: true},
		{name: "configstore_file_in_use", store: true},
		{
			name: "existing_file_pinned",
			opt: func(t *testing.T, _ string) configuration.Opts {
				t.Helper()
				pinned := filepath.Join(t.TempDir(), "snyk.json")
				require.NoError(t, os.WriteFile(pinned, []byte(`{"org":"pinned-org"}`), 0o600))
				return configuration.WithPinnedFile(pinned)
			},
		},
		{
			name: "missing_file_pinned",
			opt: func(t *testing.T, _ string) configuration.Opts {
				t.Helper()
				return configuration.WithPinnedFile(filepath.Join(t.TempDir(), "snyk.json"))
			},
		},
		{
			name: "the_working_directory_file_pinned",
			opt: func(_ *testing.T, workingDir string) configuration.Opts {
				return configuration.WithPinnedFile(filepath.Join(workingDir, "snyk.json"))
			},
		},
		{
			name: "in_memory",
			opt:  func(*testing.T, string) configuration.Opts { return configuration.WithAutomaticEnv() },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Chdir(t.TempDir())
			workingDir, err := os.Getwd()
			require.NoError(t, err)
			if tc.store {
				store, storeErr := configuration.DefaultStorageDir()
				require.NoError(t, storeErr)
				require.NoError(t, os.MkdirAll(store, 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(store, "snyk.json"), []byte(`{"org":"store-org"}`), 0o600))
			}
			ignored := filepath.Join(workingDir, "snyk.json")
			require.NoError(t, os.WriteFile(ignored, []byte(`{"org":"attacker-org"}`), 0o644))
			opt := configuration.WithFiles("snyk")
			if tc.opt != nil {
				opt = tc.opt(t, workingDir)
			}

			// workflows and the debug log get a clone of the engine configuration
			result := CheckSanity(configuration.NewWithOpts(opt).Clone())

			if tc.reported {
				require.Len(t, result, 1)
				assert.Contains(t, result[0].Description, ignored)
			} else {
				assert.Empty(t, result)
			}
		})
	}
}
