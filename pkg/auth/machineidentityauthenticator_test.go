package auth

import (
	"crypto/tls"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

type fakeMachineIdentitySource struct {
	id        string
	cert      *tls.Certificate
	certErr   error
	proofErr  error
	lastHTM   string
	lastHTU   string
	signCalls int
}

func (f *fakeMachineIdentitySource) MachineID() string { return f.id }

func (f *fakeMachineIdentitySource) ClientCertificate() (*tls.Certificate, error) {
	return f.cert, f.certErr
}

func (f *fakeMachineIdentitySource) SignProof(method, url string) (string, error) {
	f.signCalls++
	f.lastHTM = method
	f.lastHTU = url
	if f.proofErr != nil {
		return "", f.proofErr
	}
	return "proof-for-" + f.id, nil
}

func Test_MachineIdentityAuthenticator_AddsDPoPHeader(t *testing.T) {
	source := &fakeMachineIdentitySource{id: "m-123"}
	authenticator := NewMachineIdentityAuthenticator(source)

	assert.True(t, authenticator.IsSupported())
	assert.NoError(t, authenticator.Authenticate())

	req, err := http.NewRequest(http.MethodPost, "https://api.snyk.io/self/heartbeat?x=1#frag", http.NoBody)
	require.NoError(t, err)
	require.NoError(t, authenticator.AddAuthenticationHeader(req))

	assert.Equal(t, "proof-for-m-123", req.Header.Get(DPOP_HEADER))
	assert.Equal(t, http.MethodPost, source.lastHTM)
	assert.Equal(t, "https://api.snyk.io/self/heartbeat", source.lastHTU, "htu excludes query and fragment")
	assert.Empty(t, req.Header.Get("Authorization"), "machine identity never sends a bearer token")
}

func Test_MachineIdentityAuthenticator_NotSupportedWithoutSource(t *testing.T) {
	t.Run("nil source", func(t *testing.T) {
		authenticator := NewMachineIdentityAuthenticator(nil)
		assert.False(t, authenticator.IsSupported())
		assert.ErrorIs(t, authenticator.Authenticate(), ErrMachineIdentityUnavailable)

		req, err := http.NewRequest(http.MethodGet, "https://api.snyk.io/self", http.NoBody)
		require.NoError(t, err)
		assert.ErrorIs(t, authenticator.AddAuthenticationHeader(req), ErrMachineIdentityUnavailable)
		assert.Empty(t, req.Header.Get(DPOP_HEADER))
	})

	t.Run("source without a joined machine", func(t *testing.T) {
		authenticator := NewMachineIdentityAuthenticator(&fakeMachineIdentitySource{})
		assert.False(t, authenticator.IsSupported())
	})

	t.Run("nil request", func(t *testing.T) {
		authenticator := NewMachineIdentityAuthenticator(&fakeMachineIdentitySource{id: "m"})
		assert.Error(t, authenticator.AddAuthenticationHeader(nil))
	})
}

func Test_MachineIdentityAuthenticator_SignError(t *testing.T) {
	signErr := errors.New("hsm unavailable")
	authenticator := NewMachineIdentityAuthenticator(&fakeMachineIdentitySource{id: "m", proofErr: signErr})

	req, err := http.NewRequest(http.MethodGet, "https://api.snyk.io/self", http.NoBody)
	require.NoError(t, err)
	err = authenticator.AddAuthenticationHeader(req)
	assert.ErrorIs(t, err, signErr)
	assert.Empty(t, req.Header.Get(DPOP_HEADER))
}

func Test_IdentityModeFromConfiguration(t *testing.T) {
	config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	assert.Equal(t, IdentityModeUser, IdentityModeFromConfiguration(config), "default is user")

	config.Set(configuration.IDENTITY_MODE, " Machine ")
	assert.Equal(t, IdentityModeMachine, IdentityModeFromConfiguration(config))

	config.Set(configuration.IDENTITY_MODE, "something-else")
	assert.Equal(t, IdentityModeUser, IdentityModeFromConfiguration(config), "unknown values fall back to user")
}

func Test_CreateAuthenticator_IdentityMode(t *testing.T) {
	source := &fakeMachineIdentitySource{id: "m-1"}

	t.Run("user mode keeps the token authenticator", func(t *testing.T) {
		config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		config.Set(configuration.AUTHENTICATION_TOKEN, "token")
		authenticator := CreateAuthenticator(config, http.DefaultClient, WithMachineIdentitySource(source))
		assert.IsType(t, &tokenAuthenticator{}, authenticator)
	})

	t.Run("machine mode with a source", func(t *testing.T) {
		config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		config.Set(configuration.IDENTITY_MODE, string(IdentityModeMachine))
		authenticator := CreateAuthenticator(config, http.DefaultClient, WithMachineIdentitySource(source))
		assert.IsType(t, &machineIdentityAuthenticator{}, authenticator)
		assert.True(t, authenticator.IsSupported())
	})

	t.Run("machine mode without a source does not fall back to the user", func(t *testing.T) {
		config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		config.Set(configuration.IDENTITY_MODE, string(IdentityModeMachine))
		config.Set(configuration.AUTHENTICATION_TOKEN, "token")
		authenticator := CreateAuthenticator(config, http.DefaultClient)
		assert.IsType(t, &machineIdentityAuthenticator{}, authenticator)
		assert.False(t, authenticator.IsSupported())
	})

	t.Run("explicit mode overrides configuration", func(t *testing.T) {
		config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		config.Set(configuration.AUTHENTICATION_TOKEN, "token")
		machine := CreateAuthenticatorForMode(IdentityModeMachine, config, http.DefaultClient, WithMachineIdentitySource(source))
		assert.IsType(t, &machineIdentityAuthenticator{}, machine)
		user := CreateAuthenticatorForMode(IdentityModeUser, config, http.DefaultClient, WithMachineIdentitySource(source))
		assert.IsType(t, &tokenAuthenticator{}, user)
	})
}
