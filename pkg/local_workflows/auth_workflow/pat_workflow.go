package auth_workflow

import "github.com/snyk/go-application-framework/pkg/workflow"

func EntryPointPAT(invocationCtx workflow.InvocationContext) (result []workflow.Data, err error) {
	/**
	needs to handle the following CLI use cases:
		- SNYK_PAT_TOKEN env var is set; e.g. SNYK_PAT_TOKEN=<token> snyk <command>
		- INTERNAL_PAT_TOKEN_STORAGE is set in snyk config; e.g. snyk auth <PAT_TOKEN> or possibly via snyk config set <KEY>=<VALUE>

	needs to handle the following IDE use cases:
		- TODO
	**/
	return []workflow.Data{}, nil
}
