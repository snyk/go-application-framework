package authworkflow

import (
	"errors"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

const refreshWorkflowName = "auth.refresh"

var refreshWorkflowId = workflow.NewWorkflowIdentifier(refreshWorkflowName)

// InitRefresh registers the oauth token refresh workflow with the engine.
func InitRefresh(engine workflow.Engine) error {
	config := pflag.NewFlagSet(refreshWorkflowName, pflag.ExitOnError)
	config.String(authTypeParameter, "token", "Authentication type (token, oauth)")
	_, err := engine.Register(refreshWorkflowId, workflow.ConfigurationOptionsFromFlagset(config), refreshEntryPoint)
	return err
}

func refreshEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (_ []workflow.Data, err error) {
	config := invocationCtx.GetConfiguration()
	oauthEnabled := config.GetString(authTypeParameter) == "oauth"
	if !oauthEnabled { // Only used in OAuth flow
		const oauthDisabled = "OAuth disabled - cannot refresh token"
		fmt.Println(oauthDisabled)
		return nil, errors.New(oauthDisabled)
	}

	authenticator, ok := invocationCtx.GetNetworkAccess().GetAuthenticator().(*auth.OAuth2Authenticator)
	if !ok || authenticator == nil {
		const failedToGetAuthenticator = "failed to get OAuth2 authenticator"
		fmt.Println(failedToGetAuthenticator)
		return nil, errors.New(failedToGetAuthenticator)
	}

	_, err = authenticator.GetOrRefreshAccessToken()
	if err != nil {
		return nil, err
	}

	return nil, nil
}
