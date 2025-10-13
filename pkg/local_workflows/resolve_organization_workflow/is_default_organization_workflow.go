package resolve_organization_workflow

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	isDefaultOrganizationWorkflowName = "is.default.organization"
)

// WORKFLOWID_IS_DEFAULT_ORGANIZATION is the workflow identifier for the is default organization workflow
var WORKFLOWID_IS_DEFAULT_ORGANIZATION workflow.Identifier = workflow.NewWorkflowIdentifier(isDefaultOrganizationWorkflowName)

// IsDefaultOrganizationInput is the input for the is default organization workflow
type IsDefaultOrganizationInput struct {
	Organization  string              `json:"organization"`  // Can be org ID (UUID), slug/name, or empty string
	EmptyStringIs EmptyStringBehavior `json:"emptyStringIs"` // How to handle empty Organization string
}

type EmptyStringBehavior string

const (
	EmptyIsDefaultOrg  EmptyStringBehavior = "default"
	EmptyIsUnknownSlug EmptyStringBehavior = "unknown"
	EmptyIsError       EmptyStringBehavior = "error"
)

// IsDefaultOrganizationOutput is the output for the is default organization workflow
type IsDefaultOrganizationOutput struct {
	IsDefaultOrg  bool `json:"isDefaultOrg"`  // True if the organization is the default org
	IsUnknownSlug bool `json:"isUnknownSlug"` // True if the provided slug was not found
}

// InitIsDefaultOrganizationWorkflow initializes the is default organization workflow
func InitIsDefaultOrganizationWorkflow(engine workflow.Engine) error {
	flagset := pflag.NewFlagSet(isDefaultOrganizationWorkflowName, pflag.ContinueOnError)
	_, err := engine.Register(WORKFLOWID_IS_DEFAULT_ORGANIZATION, workflow.ConfigurationOptionsFromFlagset(flagset), isDefaultOrganizationWorkflowEntryPoint)
	return err
}

// isDefaultOrganizationWorkflowEntryPoint is the entry point for the is default organization workflow
func isDefaultOrganizationWorkflowEntryPoint(invocationCtx workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
	engine := invocationCtx.GetEngine()

	// Create API client
	apiClient := newApiClientImpl(engine)

	// Call DI version with dependencies
	return isDefaultOrganizationWorkflowEntryPointDI(invocationCtx, input, apiClient)
}

// isDefaultOrganizationWorkflowEntryPointDI is the testable entry point with dependency injection
func isDefaultOrganizationWorkflowEntryPointDI(
	invocationCtx workflow.InvocationContext,
	input []workflow.Data,
	apiClient api.ApiClient,
) ([]workflow.Data, error) {
	logger := invocationCtx.GetEnhancedLogger()

	// Parse input
	if len(input) == 0 {
		return nil, fmt.Errorf("no input provided")
	}

	isDefaultInput, ok := input[0].GetPayload().(IsDefaultOrganizationInput)
	if !ok {
		return nil, fmt.Errorf("invalid input payload type: expected IsDefaultOrganizationInput")
	}

	// Validate that EmptyStringIs is always provided
	if isDefaultInput.EmptyStringIs == "" {
		return nil, fmt.Errorf("EmptyStringIs must be specified")
	}

	// Handle empty string based on caller's preference
	if isDefaultInput.Organization == "" {
		switch isDefaultInput.EmptyStringIs {
		case EmptyIsDefaultOrg:
			return createIsDefaultOutput(true, false), nil
		case EmptyIsUnknownSlug:
			return createIsDefaultOutput(false, true), nil
		case EmptyIsError:
			return nil, fmt.Errorf("organization not specified")
		default:
			return nil, fmt.Errorf("invalid EmptyStringIs value: %s", isDefaultInput.EmptyStringIs)
		}
	}

	// Resolve the organization ID (handles UUID or slug)
	orgID := isDefaultInput.Organization
	_, parseErr := uuid.Parse(orgID)
	isSlug := parseErr != nil

	if isSlug {
		// It's a slug/name, resolve it to an ID
		resolvedID, err := apiClient.GetOrgIdFromSlug(orgID)
		if err != nil {
			// Check if it's an unknown slug error
			var orgSlugNotFoundErr *api.OrgSlugNotFoundError
			if errors.As(err, &orgSlugNotFoundErr) {
				logger.Debug().Str("slug", orgID).Msg("Organization slug not found")
				return createIsDefaultOutput(false, true), nil
			}
			// Other error
			logger.Debug().Err(err).Str("slug", orgID).Msg("Failed to resolve organization slug")
			return nil, fmt.Errorf("failed to resolve organization slug: %w", err)
		}
		orgID = resolvedID
	}

	// Get default organization ID
	defaultOrgID, err := apiClient.GetDefaultOrgId()
	if err != nil {
		logger.Debug().Err(err).Msg("Failed to get default organization ID")
		return nil, fmt.Errorf("failed to get default organization: %w", err)
	}

	// Compare
	isDefault := defaultOrgID == orgID

	return createIsDefaultOutput(isDefault, false), nil
}

// createIsDefaultOutput creates the workflow output data
func createIsDefaultOutput(isDefaultOrg bool, isUnknownSlug bool) []workflow.Data {
	output := IsDefaultOrganizationOutput{
		IsDefaultOrg:  isDefaultOrg,
		IsUnknownSlug: isUnknownSlug,
	}

	outputData := workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_IS_DEFAULT_ORGANIZATION, "is-default-org-output"),
		"application/go-struct",
		output,
	)

	return []workflow.Data{outputData}
}
