package localworkflows

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/internal/machinecredential"
	"github.com/snyk/go-application-framework/internal/machineenrollment"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/ui"
	pgk_utils "github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	workflowNameAuth  = "auth"
	headlessFlag      = "headless"
	AuthTypeParameter = "auth-type"
)

var authTypeDescription = fmt.Sprint("Authentication type (", auth.AUTH_TYPE_TOKEN, ", ", auth.AUTH_TYPE_OAUTH, ")")

const templateConsoleMessage = `
Now redirecting you to our auth page, go ahead and log in,
and once the auth is complete, return to this prompt and you'll
be ready to start using snyk.

If you can't wait use this url:
%s
`

// define a new workflow identifier for this workflow
var WORKFLOWID_AUTH workflow.Identifier = workflow.NewWorkflowIdentifier(workflowNameAuth)
var ConfigurationNewAuthenticationToken = "internal_new_snyk_token"

// InitAuth initializes the auth workflow before registering it with the engine.
func InitAuth(engine workflow.Engine) error {
	config := pflag.NewFlagSet(workflowNameAuth, pflag.ExitOnError)
	config.String(AuthTypeParameter, "", authTypeDescription)
	config.Bool(headlessFlag, false, "Enable headless OAuth authentication")
	config.String(auth.PARAMETER_CLIENT_SECRET, "", "Client Credential Grant, client secret")
	config.String(auth.PARAMETER_CLIENT_ID, "", "Client Credential Grant, client id")

	_, err := engine.Register(WORKFLOWID_AUTH, workflow.ConfigurationOptionsFromFlagset(config), authEntryPoint)
	return err
}

func OpenBrowser(authUrl string) {
	fmt.Println(fmt.Sprintf(templateConsoleMessage, authUrl))
	auth.OpenBrowser(authUrl)
}

// authEntryPoint is the entry point for the auth workflow.
func authEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (_ []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()
	engine := invocationCtx.GetEngine()
	globalConfig := engine.GetConfiguration()

	// cache always interferes with auth
	globalConfig.ClearCache()

	// make sure the updated environment is forwarded to global config
	defer globalConfig.ClearCache()

	httpClient := invocationCtx.GetNetworkAccess().GetUnauthorizedHttpClient()
	authenticatorOpts := []auth.OAuth2AuthenticatorOption{
		auth.WithHttpClient(httpClient),
		auth.WithOpenBrowserFunc(OpenBrowser),
		auth.WithShutdownServerFunc(auth.ShutdownServer),
		auth.WithLogger(logger),
	}

	authenticator := auth.NewOAuth2AuthenticatorWithOpts(config, authenticatorOpts...)

	err = AuthEntryPointDI(invocationCtx, logger, engine, authenticator)
	return nil, err
}

func autoDetectAuthType(config configuration.Configuration) string {
	// testing if an API token was specified
	token := config.GetString(ConfigurationNewAuthenticationToken)
	if len(token) > 0 && auth.IsAuthTypeToken(token) {
		return auth.AUTH_TYPE_TOKEN
	}

	// currently the auth workflow defaults to traditional token auth when an IDE environment is detected
	// this will need to change if IDEs want to invoke this workflow for oauth/PAT
	integration := config.GetString(configuration.INTEGRATION_NAME)
	if pgk_utils.IsSnykIde(integration) {
		return auth.AUTH_TYPE_TOKEN
	}

	// check if auth type is PAT
	if len(token) > 0 && auth.IsAuthTypePAT(token) {
		return auth.AUTH_TYPE_PAT
	}

	return auth.AUTH_TYPE_OAUTH
}

// clearCredentialTimeout bounds the wait for the storage lock held by another process.
const clearCredentialTimeout = 10 * time.Second

func hideMachineCredentials(configs map[string]configuration.Configuration) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), clearCredentialTimeout)
	defer cancel()
	hidden := map[string]string{}
	for name, c := range configs {
		if c.GetString(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE) == "" {
			continue
		}
		if err := machinecredential.CheckStorage(ctx, c); err != nil {
			return nil, fmt.Errorf("the storage of the %s configuration, which holds the machine credential, cannot be used: %w", name, err)
		}
		hidden[name] = c.GetString(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE)
	}
	for name := range hidden {
		// Not Unset: it writes a deletion to storage.
		configs[name].Set(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE, "")
	}
	return hidden, nil
}

func deleteOrRestoreMachineCredentials(configs map[string]configuration.Configuration, hidden map[string]string, loggedIn bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), clearCredentialTimeout)
	defer cancel()
	var err error
	for name, value := range hidden {
		if loggedIn && err == nil {
			clearErr := machinecredential.Clear(ctx, configs[name])
			if clearErr == nil {
				continue
			}
			err = fmt.Errorf("the login succeeded, but the machine credential is still stored in the %s configuration and will be used: %w", name, clearErr)
		}
		configs[name].Set(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE, value)
	}
	return err
}

func AuthEntryPointDI(invocationCtx workflow.InvocationContext, logger *zerolog.Logger, engine workflow.Engine, authenticator auth.Authenticator) (err error) {
	analytics := invocationCtx.GetAnalytics()
	globalConfig := engine.GetConfiguration()
	config := invocationCtx.GetConfiguration()

	authType := config.GetString(AuthTypeParameter)
	if len(authType) == 0 {
		authType = autoDetectAuthType(config)
	}

	logger.Printf("Authentication Type: %s", authType)
	analytics.AddExtensionStringValue(AuthTypeParameter, authType)

	// Before any stored machine credential is hidden: the deferred cleanup would delete the one this
	// login saves.
	if secret := config.GetString(auth.PARAMETER_CLIENT_SECRET); strings.EqualFold(authType, auth.AUTH_TYPE_OAUTH) && isPEM(secret) {
		return authenticateWithPrivateKey(invocationCtx, logger, config, globalConfig, secret)
	}

	// A person logging in must not authenticate as the enrolled machine, yet the machine keeps its
	// stored credential until the login succeeds.
	credentialConfigs := map[string]configuration.Configuration{"local": config, "global": globalConfig}
	hiddenCredentials, err := hideMachineCredentials(credentialConfigs)
	if err != nil {
		return err
	}
	loggedIn := false
	defer func() {
		if deleteErr := deleteOrRestoreMachineCredentials(credentialConfigs, hiddenCredentials, loggedIn); deleteErr != nil {
			err = deleteErr
		}
	}()

	existingSnykToken := config.GetString(configuration.AUTHENTICATION_TOKEN)
	// always attempt to clear existing tokens before triggering auth for current config clone and global config
	clearUserTokens(logger, config, globalConfig)

	if strings.EqualFold(authType, auth.AUTH_TYPE_OAUTH) { // OAUTH flow
		headless := config.GetBool(headlessFlag)
		logger.Printf("Headless: %v", headless)

		err = authenticator.Authenticate()
		if err != nil {
			return err
		}

		newToken := config.Get(auth.CONFIG_KEY_OAUTH_TOKEN)
		globalConfig.Set(auth.CONFIG_KEY_OAUTH_TOKEN, newToken)
		loggedIn = true

		err = ui.DefaultUi().Output(auth.AUTHENTICATED_MESSAGE)
		if err != nil {
			logger.Debug().Err(err).Msg("Failed to output authenticated message")
		}
	} else if strings.EqualFold(authType, auth.AUTH_TYPE_PAT) { // PAT flow
		globalConfig.PersistInStorage(auth.CONFIG_KEY_TOKEN)
		pat := config.GetString(ConfigurationNewAuthenticationToken)

		logger.Print("Validating pat")
		whoamiConfig := config.Clone()
		whoamiConfig.ClearCache()
		// we don't want to use the cache here, so this is a workaround
		whoamiConfig.Set(configuration.FLAG_EXPERIMENTAL, true)
		whoamiConfig.Set(configuration.AUTHENTICATION_TOKEN, pat)
		_, whoamiErr := engine.InvokeWithConfig(workflow.NewWorkflowIdentifier("whoami"), whoamiConfig)
		if whoamiErr != nil {
			// reset config file
			if len(existingSnykToken) > 0 {
				config.Set(auth.CONFIG_KEY_TOKEN, existingSnykToken)
			}
			return whoamiErr
		}

		logger.Print("Validation successful; set pat credentials in config")
		// we don't want to use the cache here, so this is a workaround
		globalConfig.ClearCache()
		globalConfig.Set(auth.CONFIG_KEY_TOKEN, pat)
		loggedIn = true

		err = ui.DefaultUi().Output(auth.AUTHENTICATED_MESSAGE)
		if err != nil {
			logger.Debug().Err(err).Msg("Failed to output authenticated message")
		}
	} else { // LEGACY flow
		config.Set(configuration.RAW_CMD_ARGS, os.Args[1:])
		config.Set(configuration.WORKFLOW_USE_STDIO, true)
		config.Set(configuration.AUTHENTICATION_TOKEN, "") // clear token to avoid using it during authentication

		_, legacyCLIError := engine.InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)
		if legacyCLIError != nil {
			return legacyCLIError
		}
		loggedIn = true
	}

	return err
}

func clearUserTokens(logger *zerolog.Logger, config, globalConfig configuration.Configuration) {
	logger.Print("Unset existing auth keys")
	config.Unset(configuration.AUTHENTICATION_TOKEN)
	config.Unset(auth.CONFIG_KEY_OAUTH_TOKEN)
	globalConfig.Unset(configuration.AUTHENTICATION_TOKEN)
	globalConfig.Unset(auth.CONFIG_KEY_OAUTH_TOKEN)
}

func isPEM(secret string) bool {
	return strings.HasPrefix(strings.TrimSpace(secret), "-----BEGIN")
}

// authenticateWithPrivateKey logs in with the client credentials grant and a private_key_jwt client
// assertion signed by keyPEM, then stores the key so that later processes can mint their own tokens.
func authenticateWithPrivateKey(invocationCtx workflow.InvocationContext, logger *zerolog.Logger, config, globalConfig configuration.Configuration, keyPEM string) error {
	clientID := config.GetString(auth.PARAMETER_CLIENT_ID)
	if clientID == "" {
		return fmt.Errorf("a private key in --%s needs --%s", auth.PARAMETER_CLIENT_SECRET, auth.PARAMETER_CLIENT_ID)
	}
	key, err := machineenrollment.ParseKeyPEM([]byte(keyPEM))
	if err != nil {
		return fmt.Errorf("--%s looks like a PEM private key but cannot be used: %w. "+
			"It must be an unencrypted PKCS#8 RSA or P-256 key (BEGIN PRIVATE KEY) with real line breaks; "+
			"convert other formats with `openssl pkcs8 -topk8 -nocrypt -in <key file>`", auth.PARAMETER_CLIENT_SECRET, err)
	}
	credential := machinecredential.Credential{ClientID: clientID, Key: key}
	if err = checkPrivateKeyStorage(invocationCtx.Context(), config); err != nil {
		return err
	}
	token, err := mintToken(invocationCtx.GetNetworkAccess().GetUnauthorizedHttpClient(), apiURLWithoutUserLogin(config), credential)
	if err != nil {
		return err
	}
	saveCtx, cancel := context.WithTimeout(invocationCtx.Context(), storeTimeout)
	defer cancel()
	if err = machinecredential.Save(saveCtx, config, credential); err != nil {
		return err
	}
	if globalConfig != config {
		if err = machinecredential.Publish(globalConfig, credential); err != nil {
			return err
		}
	}
	clearUserTokens(logger, config, globalConfig)
	// Later processes derive the API URL from this token's audience.
	config.PersistInStorage(auth.CONFIG_KEY_OAUTH_TOKEN)
	config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, token)
	globalConfig.Set(auth.CONFIG_KEY_OAUTH_TOKEN, token)
	if err = invocationCtx.GetUserInterface().Output(auth.AUTHENTICATED_MESSAGE); err != nil {
		logger.Debug().Err(err).Msg("Failed to output authenticated message")
	}
	return nil
}

// apiURLWithoutUserLogin hides the stored user tokens, whose region would win over the configured API
// URL, on a clone: a clone does not inherit the persisted keys, so its Sets never reach the storage.
func apiURLWithoutUserLogin(config configuration.Configuration) string {
	urlConfig := config.Clone()
	urlConfig.Set(configuration.AUTHENTICATION_TOKEN, "")
	urlConfig.Set(auth.CONFIG_KEY_OAUTH_TOKEN, "")
	return urlConfig.GetString(configuration.API_URL)
}

func checkPrivateKeyStorage(ctx context.Context, config configuration.Configuration) error {
	if storage := config.GetStorage(); storage == nil || isEmptyStorage(storage) {
		return errors.New("the private key cannot be stored: the configuration has no storage")
	}
	ctx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	if err := machinecredential.CheckStorage(ctx, config); err != nil {
		return fmt.Errorf("the private key cannot be stored: %w", err)
	}
	return nil
}

// mintToken works on a throwaway configuration, because the authenticator persists the token it
// mints, and nothing may be stored before the key is.
func mintToken(httpClient *http.Client, apiURL string, credential machinecredential.Credential) (string, error) {
	mintConfig := configuration.NewWithOpts()
	mintConfig.Set(configuration.API_URL, apiURL)
	authenticator := auth.NewOAuth2AuthenticatorWithOpts(mintConfig,
		auth.WithHttpClient(httpClient),
		auth.WithClientAssertionProvider(credential.ClientID, machinecredential.NewSigner(credential.Key)))
	if err := authenticator.Authenticate(); err != nil {
		return "", fmt.Errorf("failed authenticating as client %s, so nothing was stored: %w", credential.ClientID, err)
	}
	return mintConfig.GetString(auth.CONFIG_KEY_OAUTH_TOKEN), nil
}
