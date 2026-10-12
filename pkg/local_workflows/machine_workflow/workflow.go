package machine_workflow

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/machineenrollment"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// ErrNotEnrolled is returned by the status workflow when this device has not been enrolled.
var ErrNotEnrolled = errors.New("this machine is not enrolled")

func enrollEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	config := invocationCtx.GetConfiguration()
	globalConfig := invocationCtx.GetEngine().GetConfiguration()
	// cache always interferes with auth
	globalConfig.ClearCache()
	defer globalConfig.ClearCache()

	message, err := enroll(
		invocationCtx.Context(),
		config,
		globalConfig,
		invocationCtx.GetNetworkAccess().GetUnauthorizedHttpClient(),
		machineenrollment.SystemKeychain(),
		invocationCtx.GetEnhancedLogger(),
	)
	if err != nil {
		return nil, err
	}
	return []workflow.Data{textData(WORKFLOWID_MACHINE_ENROLL, message, invocationCtx)}, nil
}

// enroll enrolls this device, stores the machine client's key and configuration, and gets the
// machine's first access token. From then on, the machine is who this application authenticates
// as.
func enroll(
	ctx context.Context,
	config, globalConfig configuration.Configuration,
	httpClient *http.Client,
	keychain machineenrollment.Keychain,
	logger *zerolog.Logger,
) (string, error) {
	keyFile := config.GetString(machineenrollment.CONFIG_KEY_CLIENT_KEY_FILE)
	if keyFile == "" {
		var err error
		if keyFile, err = machineenrollment.DefaultKeyFile(); err != nil {
			return "", err
		}
	}

	e, err := machineenrollment.Enroll(ctx, httpClient, config.GetString(configuration.API_URL), keychain, time.Now())
	if err != nil {
		return "", err
	}
	if err = machineenrollment.WriteKeyFile(keyFile, e.Key); err != nil {
		return "", err
	}
	logger.Debug().Str("machineId", e.MachineID).Str("clientId", e.ClientID).Str("keyFile", keyFile).Msg("machine enrolled")

	for _, c := range []configuration.Configuration{config, globalConfig} {
		for key, value := range map[string]string{
			machineenrollment.CONFIG_KEY_CLIENT_ID:       e.ClientID,
			machineenrollment.CONFIG_KEY_CLIENT_KEY_FILE: keyFile,
			machineenrollment.CONFIG_KEY_MACHINE_ID:      e.MachineID,
		} {
			c.PersistInStorage(key)
			c.Set(key, value)
		}
		// Whoever was authenticated before is replaced by the machine.
		c.Unset(auth.CONFIG_KEY_OAUTH_TOKEN)
	}

	authenticator := auth.NewOAuth2AuthenticatorWithOpts(config, auth.WithHttpClient(httpClient), auth.WithLogger(logger))
	if err = authenticator.Authenticate(); err != nil {
		return "", fmt.Errorf("enrolled machine %s, but getting its access token failed: %w", e.MachineID, err)
	}
	globalConfig.Set(auth.CONFIG_KEY_OAUTH_TOKEN, config.Get(auth.CONFIG_KEY_OAUTH_TOKEN))

	return fmt.Sprintf("This machine is enrolled.\n  Machine: %s\n  Client:  %s\n", e.MachineID, e.ClientID), nil
}

func statusEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	message, err := status(
		invocationCtx.Context(),
		invocationCtx.GetConfiguration(),
		invocationCtx.GetNetworkAccess().GetHttpClient(),
	)
	if err != nil {
		return nil, err
	}
	return []workflow.Data{textData(WORKFLOWID_MACHINE_STATUS, message, invocationCtx)}, nil
}

// status checks the enrolled machine's credential by listing the tenants it can access.
// httpClient must authenticate requests.
func status(ctx context.Context, config configuration.Configuration, httpClient *http.Client) (string, error) {
	clientID := config.GetString(machineenrollment.CONFIG_KEY_CLIENT_ID)
	if clientID == "" {
		return "", ErrNotEnrolled
	}

	tenants, err := machineenrollment.ListTenants(ctx, httpClient, config.GetString(configuration.API_URL))
	if err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Machine: %s\nClient:  %s\nTenants: %d\n", config.GetString(machineenrollment.CONFIG_KEY_MACHINE_ID), clientID, len(tenants))
	for _, t := range tenants {
		fmt.Fprintf(&b, "  %s  %s\n", t.ID, t.Name)
	}
	return b.String(), nil
}

func textData(id workflow.Identifier, text string, invocationCtx workflow.InvocationContext) workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(id, "text"),
		"text/plain",
		[]byte(text),
		workflow.WithLogger(invocationCtx.GetEnhancedLogger()),
		workflow.WithConfiguration(invocationCtx.GetConfiguration()),
	)
}
