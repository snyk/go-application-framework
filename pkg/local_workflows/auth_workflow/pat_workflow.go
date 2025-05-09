package auth_workflow

import "github.com/snyk/go-application-framework/pkg/workflow"

func EntryPointPAT(invocationCtx workflow.InvocationContext) (result []workflow.Data, err error) {
	/**
	needs to clear the snyk config to ensure a clean slate
	needs to handle `snyk auth <PAT>`, it should:
		- Create new PAT authenticator
		- Validate the token by calling PATH authenticator's Authenticate()
			- Aunthenticate() will call PAT validation API and set the Snyk endpoint in config
		- Set the token in config in the format - <KEY>: <PAT>, where <KEY> will be `api`
		- Set the endpoint in config in the format - <KEY>: <URL>, where <KEY> will be `endpoint`

	needs to handle the following IDE use cases:
		- TODO
	**/
	logger := invocationCtx.GetEnhancedLogger()

	logger.Debug().Msg("EntryPointPAT")

	return []workflow.Data{}, nil
}
