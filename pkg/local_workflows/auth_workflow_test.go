package localworkflows

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
)

func Test_auth_oauth(t *testing.T) {
	mockCtl := gomock.NewController(t)
	logContent := &bytes.Buffer{}
	config := configuration.NewInMemory()
	logger := zerolog.New(logContent)
	engine := mocks.NewMockEngine(mockCtl)
	authenticator := mocks.NewMockAuthenticator(mockCtl)

	engine.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	engine.EXPECT().Init().Times(1)

	err := InitAuth(engine)
	assert.NoError(t, err)

	err = engine.Init()
	assert.NoError(t, err)

	t.Run("happy", func(t *testing.T) {
		config.Set(authTypeParameter, nil)
		authenticator.EXPECT().Authenticate().Times(1).Return(nil)
		err = entryPointDI(config, &logger, engine, authenticator)
		assert.NoError(t, err)
	})

	t.Run("unhappy", func(t *testing.T) {
		config.Set(authTypeParameter, nil)
		expectedErr := fmt.Errorf("someting went wrong")
		authenticator.EXPECT().Authenticate().Times(1).Return(expectedErr)
		err = entryPointDI(config, &logger, engine, authenticator)
		assert.Equal(t, expectedErr, err)
	})
}

func Test_auth_token(t *testing.T) {
	mockCtl := gomock.NewController(t)
	logContent := &bytes.Buffer{}
	config := configuration.NewInMemory()
	logger := zerolog.New(logContent)
	engine := mocks.NewMockEngine(mockCtl)
	authenticator := mocks.NewMockAuthenticator(mockCtl)

	engine.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	engine.EXPECT().Init().Times(1)

	err := InitAuth(engine)
	assert.NoError(t, err)

	err = engine.Init()
	assert.NoError(t, err)

	t.Run("happy", func(t *testing.T) {
		config.Set(authTypeParameter, authTypeToken)
		engine.EXPECT().InvokeWithConfig(gomock.Any(), gomock.Any())
		err = entryPointDI(config, &logger, engine, authenticator)
		assert.NoError(t, err)
	})

	t.Run("automatically switch to token when API token is given", func(t *testing.T) {
		config.Set(authTypeParameter, nil)
		config.Set(ConfigurationNewAuthenticationToken, "00000000-0000-0000-0000-000000000000")
		engine.EXPECT().InvokeWithConfig(gomock.Any(), gomock.Any())
		err = entryPointDI(config, &logger, engine, authenticator)
		assert.NoError(t, err)
	})
}

func Test_autodetectAuth(t *testing.T) {
	t.Run("in unstable versions, oauth by default", func(t *testing.T) {
		expected := authTypeOAuth
		config := configuration.NewInMemory()
		config.Set(configuration.IS_UNSTABLE_VERSION, true)
		actual := autoDetectAuthType(config)
		assert.Equal(t, expected, actual)
	})

	t.Run("in stable versions, token by default", func(t *testing.T) {
		expected := authTypeToken
		config := configuration.NewInMemory()
		config.Set(configuration.IS_UNSTABLE_VERSION, false)
		actual := autoDetectAuthType(config)
		assert.Equal(t, expected, actual)
	})

	t.Run("token for IDEs", func(t *testing.T) {
		expected := authTypeToken
		config := configuration.NewInMemory()
		config.Set(configuration.INTEGRATION_NAME, "VS_CODE")
		actual := autoDetectAuthType(config)
		assert.Equal(t, expected, actual)
	})

	t.Run("token for given API token", func(t *testing.T) {
		expected := authTypeToken
		config := configuration.NewInMemory()
		config.Set(ConfigurationNewAuthenticationToken, "00000000-0000-0000-0000-000000000000")
		actual := autoDetectAuthType(config)
		assert.Equal(t, expected, actual)
	})
}
