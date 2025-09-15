package ldx_sync_config

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"
)

//go:generate go tool github.com/golang/mock/mockgen -source=ldx_sync_config.go -destination ../mocks/ldx_sync_config.go -package mocks -imports ldx_sync_config=github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config

// Configuration represents the extracted LDX-Sync configuration data
// that can be consumed by Snyk Language Server without knowing about LDX-Sync types
type Configuration struct {
	// Core configuration
	Organization   string
	SeverityFilter *SeverityFilter
	ProductConfig  *ProductConfig
	AutoScan       bool
	TrustedFolders []string
	ProxyConfig    *ProxyConfig

	// Authentication and endpoints
	AuthenticationMethod *string
	Endpoints            *Endpoints

	// Complete filter configuration
	FilterConfig *FilterConfig

	// Folder-specific configurations
	FolderConfigs []FolderConfig

	// Complete IDE configuration
	IdeConfig *IdeConfig

	// Complete organization data
	Organizations []Organization

	// Configuration metadata
	AttributeSource *AttributeSource
	CreatedAt       *time.Time
	LastModifiedAt  *time.Time
	Scope           *string
	Policy          *Policy
}

// SeverityFilter represents the severity filter configuration
type SeverityFilter struct {
	Critical bool
	High     bool
	Medium   bool
	Low      bool
}

// ProductConfig represents the product enablement configuration
type ProductConfig struct {
	Code      bool
	Container bool
	Iac       bool
	Oss       bool
}

// ProxyConfig represents the proxy configuration
type ProxyConfig struct {
	Http     string
	Https    string
	Insecure bool
	NoProxy  string
}

// Endpoints represents API endpoints configuration
type Endpoints struct {
	ApiEndpoint  *string
	CodeEndpoint *string
}

// FilterConfig represents the complete filter configuration
type FilterConfig struct {
	Cve                []string
	Cwe                []string
	RiskScoreThreshold *int
	Rule               []string
	Severities         *SeverityFilter
}

// FolderConfig represents folder-specific configuration
type FolderConfig struct {
	FolderPath             string
	Organizations          []Organization
	RemoteUrl              string
	AdditionalEnvironment  []string
	AdditionalParameters   []string
	PreScanExecuteCommand  *string
	PostScanExecuteCommand *string
	ReferenceBranch        *string
	ReferenceFolder        *string
}

// IdeConfig represents the complete IDE configuration
type IdeConfig struct {
	BinaryManagementConfig *BinaryManagementConfig
	CodeActions            *CodeActions
	HoverVerbosity         *int
	IssueViewConfig        *IssueViewConfig
	ProductConfig          *ProductConfig
	ScanConfig             *ScanConfig
	TrustConfig            *TrustConfig
}

// BinaryManagementConfig represents binary management configuration
type BinaryManagementConfig struct {
	AutomaticDownload *bool
	CliPath           *string
}

// CodeActions represents code actions configuration
type CodeActions struct {
	OpenBrowser     []CodeAction
	OpenLearnLesson []CodeAction
	ScaUpgrade      []CodeAction
}

// CodeAction represents a single code action configuration
type CodeAction struct {
	Enabled         *bool
	IntegrationName *string
}

// IssueViewConfig represents issue view configuration
type IssueViewConfig struct {
	IgnoredIssues *bool
	OpenIssues    *bool
}

// ScanConfig represents scan configuration
type ScanConfig struct {
	Automatic *bool
	NetNew    *bool
}

// TrustConfig represents trust configuration
type TrustConfig struct {
	Enable         *bool
	TrustedFolders []string
}

// Organization represents organization information
type Organization struct {
	Id                   string
	IsDefault            *bool
	Name                 string
	PreferredByAlgorithm *bool
	ProjectCount         *int
	Slug                 string
}

// AttributeSource represents configuration location sources
type AttributeSource struct {
	Asset       []string
	Group       []string
	Org         []string
	ProjectName []string
	RemoteUrl   []string
	Tenant      []string
}

// Policy represents policy configuration
type Policy struct {
	EnforcedAttributes []string
	LockedAttributes   []string
}

// config holds configuration for the LDX-Sync config client, set using ConfigOption functions.
type config struct {
	APIVersion            string
	Logger                *zerolog.Logger
	lowLevelClientOptions []v20241015.ClientOption
}

// ConfigOption allows setting custom parameters during construction
type ConfigOption func(c *config)

// WithAPIVersion sets the API version for the LDX-Sync config client.
func WithAPIVersion(v string) ConfigOption {
	return func(c *config) {
		if v == "" {
			c.APIVersion = DefaultAPIVersion
		} else {
			c.APIVersion = v
		}
	}
}

// WithLogger sets the logger for the LDX-Sync config client.
func WithLogger(l *zerolog.Logger) ConfigOption {
	return func(c *config) {
		c.Logger = l
	}
}

// WithCustomHTTPClient allows overriding the default Doer, which is
// automatically created using http.Client. This is useful for tests.
func WithCustomHTTPClient(doer v20241015.HttpRequestDoer) ConfigOption {
	return func(c *config) {
		opt := v20241015.WithHTTPClient(doer)
		c.lowLevelClientOptions = append(c.lowLevelClientOptions, opt)
	}
}

// WithCustomRequestEditorFn allows setting up a callback function, which will be
// called right before sending the request. This can be used to mutate the request.
func WithCustomRequestEditorFn(fn v20241015.RequestEditorFn) ConfigOption {
	return func(c *config) {
		opt := v20241015.WithRequestEditorFn(fn)
		c.lowLevelClientOptions = append(c.lowLevelClientOptions, opt)
	}
}

// LdxSyncConfigClient interface for retrieving LDX-Sync configuration
type LdxSyncConfigClient interface {
	GetConfiguration(ctx context.Context, params GetConfigurationParams) (*Configuration, error)
}

// GetConfigurationParams defines parameters for the GetConfiguration function.
type GetConfigurationParams struct {
	RemoteUrl   string
	Org         *string
	AssetId     *string
	ProjectName *string
}

type client struct {
	lowLevelClient v20241015.ClientWithResponsesInterface
	config         config
	logger         *zerolog.Logger
}

const (
	DefaultAPIVersion = "2024-10-15"
)

// NewLdxSyncConfigClient returns a new instance of the LDX-Sync config client, configured with the provided options.
func NewLdxSyncConfigClient(serverBaseUrl string, options ...ConfigOption) (LdxSyncConfigClient, error) {
	cfg := config{
		APIVersion: DefaultAPIVersion,
	}

	for _, opt := range options {
		opt(&cfg)
	}

	llClient, err := v20241015.NewClientWithResponses(serverBaseUrl, cfg.lowLevelClientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create low-level LDX-Sync config client: %w", err)
	}

	var clLogger *zerolog.Logger
	if cfg.Logger != nil {
		clLogger = cfg.Logger
	} else {
		nopLogger := zerolog.Nop()
		clLogger = &nopLogger
	}

	return &client{
		lowLevelClient: llClient,
		config:         cfg,
		logger:         clLogger,
	}, nil
}

// GetConfiguration retrieves and extracts LDX-Sync configuration
func (c *client) GetConfiguration(ctx context.Context, params GetConfigurationParams) (*Configuration, error) {
	c.logger.Debug().
		Str("remoteUrl", params.RemoteUrl).
		Interface("params", params).
		Msg("Retrieving LDX-Sync configuration")

	// Prepare API parameters
	apiParams := &v20241015.GetConfigParams{
		Version:     c.config.APIVersion,
		Org:         params.Org,
		AssetId:     params.AssetId,
		ProjectName: params.ProjectName,
		RemoteUrl:   &params.RemoteUrl,
	}

	// Get the raw LDX-Sync configuration
	resp, err := c.lowLevelClient.GetConfigWithResponse(ctx, apiParams)
	if err != nil {
		c.logger.Warn().Err(err).Msg("Failed to retrieve LDX-Sync configuration")
		return nil, fmt.Errorf("failed to retrieve LDX-Sync configuration: %w", err)
	}

	c.logger.Debug().Int("statusCode", resp.StatusCode()).Msg("Received response")

	// Handle response and extract configuration
	configResponse, err := c.handleResponse(resp, params.RemoteUrl)
	if err != nil {
		return nil, err
	}

	configuration := c.extractAllConfiguration(configResponse)

	c.logger.Debug().Msg("Successfully extracted LDX-Sync configuration")
	return configuration, nil
}

// handleResponse handles the API response and returns the config response or error
func (c *client) handleResponse(resp *v20241015.GetConfigResponse, remoteUrl string) (*v20241015.ConfigResponse, error) {
	switch resp.StatusCode() {
	case http.StatusOK:
		return c.handleOKResponse(resp, remoteUrl)
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusInternalServerError:
		return nil, c.handleErrorResponse(resp, remoteUrl)
	default:
		return nil, c.handleUnexpectedResponse(resp.StatusCode(), resp.Body, remoteUrl)
	}
}

// handleOKResponse handles successful responses
func (c *client) handleOKResponse(resp *v20241015.GetConfigResponse, remoteUrl string) (*v20241015.ConfigResponse, error) {
	if resp.ApplicationvndApiJSON200 != nil {
		return resp.ApplicationvndApiJSON200, nil
	}
	if resp.JSON200 != nil {
		return resp.JSON200, nil
	}
	c.logger.Debug().Int("statusCode", resp.StatusCode()).Msg("Unexpected 200 response")
	return nil, c.handleUnexpectedResponse(resp.StatusCode(), resp.Body, remoteUrl)
}

// handleErrorResponse handles error responses
func (c *client) handleErrorResponse(resp *v20241015.GetConfigResponse, remoteUrl string) error {
	c.logger.Debug().Int("statusCode", resp.StatusCode()).Msg("Error response")
	err := c.handleUnexpectedResponse(resp.StatusCode(), resp.Body, remoteUrl)
	c.logger.Debug().Str("error", err.Error()).Msg("Generated error")
	return err
}

// extractAllConfiguration extracts all configuration from the response
func (c *client) extractAllConfiguration(configResponse *v20241015.ConfigResponse) *Configuration {
	configuration := &Configuration{}
	configData := &configResponse.Data.Attributes.ConfigData
	attributes := &configResponse.Data.Attributes

	// Extract core configuration (existing)
	c.extractOrganization(configData, configuration)
	c.extractFilterConfig(configData, configuration)
	c.extractIdeConfig(configData, configuration)
	c.extractProxyConfig(configData, configuration)

	// Extract new configuration fields
	c.extractAuthenticationMethod(configData, configuration)
	c.extractEndpoints(configData, configuration)
	c.extractCompleteFilterConfig(configData, configuration)
	c.extractFolderConfigs(configData, configuration)
	c.extractCompleteIdeConfig(configData, configuration)
	c.extractCompleteOrganizations(configData, configuration)

	// Extract metadata
	c.extractAttributeSource(attributes, configuration)
	c.extractTimestamps(attributes, configuration)
	c.extractScope(attributes, configuration)
	c.extractPolicy(attributes, configuration)

	return configuration
}

// handleUnexpectedResponse handles unexpected API responses and returns appropriate errors
func (c *client) handleUnexpectedResponse(statusCode int, body []byte, identifier string) error {
	if len(body) > 0 {
		snykErrorList, parseErr := snyk_errors.FromJSONAPIErrorBytes(body)
		if parseErr == nil && len(snykErrorList) > 0 {
			errsToJoin := []error{}
			for i := range snykErrorList {
				errsToJoin = append(errsToJoin, snykErrorList[i])
			}
			return fmt.Errorf("unexpected response retrieving LDX-Sync configuration (status: %d): %w", statusCode, fmt.Errorf("%v", errsToJoin))
		}
	}

	detailMsg := fmt.Sprintf("unexpected response retrieving LDX-Sync configuration (status: %d)", statusCode)
	if identifier != "" {
		detailMsg = fmt.Sprintf("unexpected response retrieving LDX-Sync configuration for %s (status: %d)", identifier, statusCode)
	}
	return fmt.Errorf("%s", detailMsg)
}

// extractOrganization extracts organization configuration
func (c *client) extractOrganization(configData *v20241015.ConfigData, configuration *Configuration) {
	if configData.Organizations == nil || len(*configData.Organizations) == 0 {
		return
	}

	// Find the default organization or use the first one
	var selectedOrg *v20241015.Organization
	for _, org := range *configData.Organizations {
		if org.IsDefault != nil && *org.IsDefault {
			selectedOrg = &org
			break
		}
	}

	if selectedOrg == nil {
		selectedOrg = &(*configData.Organizations)[0]
	}

	if selectedOrg != nil {
		configuration.Organization = selectedOrg.Id
	}
}

// extractFilterConfig extracts filter configuration
func (c *client) extractFilterConfig(configData *v20241015.ConfigData, configuration *Configuration) {
	if configData.FilterConfig == nil || configData.FilterConfig.Severities == nil {
		return
	}

	severities := configData.FilterConfig.Severities
	configuration.SeverityFilter = &SeverityFilter{
		Critical: *severities.Critical,
		High:     *severities.High,
		Medium:   *severities.Medium,
		Low:      *severities.Low,
	}
}

// extractIdeConfig extracts IDE configuration
func (c *client) extractIdeConfig(configData *v20241015.ConfigData, configuration *Configuration) {
	if configData.IdeConfig == nil {
		return
	}

	ideConfig := configData.IdeConfig

	// Extract product configuration
	if ideConfig.ProductConfig != nil {
		productConfig := ideConfig.ProductConfig
		configuration.ProductConfig = &ProductConfig{
			Code:      productConfig.Code != nil && *productConfig.Code,
			Container: productConfig.Container != nil && *productConfig.Container,
			Iac:       productConfig.Iac != nil && *productConfig.Iac,
			Oss:       productConfig.Oss != nil && *productConfig.Oss,
		}
	}

	// Extract scan configuration
	if ideConfig.ScanConfig != nil && ideConfig.ScanConfig.Automatic != nil {
		configuration.AutoScan = *ideConfig.ScanConfig.Automatic
	}

	// Extract trust configuration
	if ideConfig.TrustConfig != nil && ideConfig.TrustConfig.TrustedFolders != nil {
		configuration.TrustedFolders = *ideConfig.TrustConfig.TrustedFolders
	}
}

// extractProxyConfig extracts proxy configuration
func (c *client) extractProxyConfig(configData *v20241015.ConfigData, configuration *Configuration) {
	if configData.ProxyConfig == nil {
		return
	}

	proxyConfig := configData.ProxyConfig
	configuration.ProxyConfig = &ProxyConfig{}

	if proxyConfig.Http != nil {
		configuration.ProxyConfig.Http = *proxyConfig.Http
	}
	if proxyConfig.Https != nil {
		configuration.ProxyConfig.Https = *proxyConfig.Https
	}
	if proxyConfig.Insecure != nil {
		configuration.ProxyConfig.Insecure = *proxyConfig.Insecure
	}
	if proxyConfig.NoProxy != nil {
		configuration.ProxyConfig.NoProxy = *proxyConfig.NoProxy
	}
}

// extractAuthenticationMethod extracts authentication method configuration
func (c *client) extractAuthenticationMethod(configData *v20241015.ConfigData, configuration *Configuration) {
	if configData.AuthenticationMethod != nil {
		authMethod := string(*configData.AuthenticationMethod)
		configuration.AuthenticationMethod = &authMethod
	}
}

// extractEndpoints extracts endpoints configuration
func (c *client) extractEndpoints(configData *v20241015.ConfigData, configuration *Configuration) {
	if configData.Endpoints != nil {
		configuration.Endpoints = &Endpoints{
			ApiEndpoint:  configData.Endpoints.ApiEndpoint,
			CodeEndpoint: configData.Endpoints.CodeEndpoint,
		}
	}
}

// extractCompleteFilterConfig extracts complete filter configuration
func (c *client) extractCompleteFilterConfig(configData *v20241015.ConfigData, configuration *Configuration) {
	if configData.FilterConfig == nil {
		return
	}

	filterConfig := configData.FilterConfig
	configuration.FilterConfig = &FilterConfig{
		Cve:                convertStringSlice(filterConfig.Cve),
		Cwe:                convertStringSlice(filterConfig.Cwe),
		RiskScoreThreshold: filterConfig.RiskScoreThreshold,
		Rule:               convertStringSlice(filterConfig.Rule),
	}

	// Extract severities if present
	if filterConfig.Severities != nil {
		severities := filterConfig.Severities
		configuration.FilterConfig.Severities = &SeverityFilter{
			Critical: *severities.Critical,
			High:     *severities.High,
			Medium:   *severities.Medium,
			Low:      *severities.Low,
		}
	}
}

// extractFolderConfigs extracts folder configurations
func (c *client) extractFolderConfigs(configData *v20241015.ConfigData, configuration *Configuration) {
	if configData.FolderConfigs == nil {
		return
	}

	folderConfigs := make([]FolderConfig, 0, len(*configData.FolderConfigs))
	for _, folderConfig := range *configData.FolderConfigs {
		organizations := make([]Organization, 0)
		if folderConfig.Organizations != nil {
			for _, org := range *folderConfig.Organizations {
				organizations = append(organizations, Organization{
					Id:                   org.Id,
					IsDefault:            org.IsDefault,
					Name:                 org.Name,
					PreferredByAlgorithm: org.PreferredByAlgorithm,
					ProjectCount:         org.ProjectCount,
					Slug:                 org.Slug,
				})
			}
		}

		folderConfigs = append(folderConfigs, FolderConfig{
			FolderPath:             folderConfig.FolderPath,
			Organizations:          organizations,
			RemoteUrl:              folderConfig.RemoteUrl,
			AdditionalEnvironment:  convertStringSlice(folderConfig.AdditionalEnvironment),
			AdditionalParameters:   convertStringSlice(folderConfig.AdditionalParameters),
			PreScanExecuteCommand:  folderConfig.PreScanExecuteCommand,
			PostScanExecuteCommand: folderConfig.PostScanExecuteCommand,
			ReferenceBranch:        folderConfig.ReferenceBranch,
			ReferenceFolder:        folderConfig.ReferenceFolder,
		})
	}

	configuration.FolderConfigs = folderConfigs
}

// extractCompleteIdeConfig extracts complete IDE configuration
func (c *client) extractCompleteIdeConfig(configData *v20241015.ConfigData, configuration *Configuration) {
	if configData.IdeConfig == nil {
		return
	}

	ideConfig := configData.IdeConfig
	configuration.IdeConfig = &IdeConfig{
		HoverVerbosity: ideConfig.HoverVerbosity,
	}

	// Extract binary management config
	if ideConfig.BinaryManagementConfig != nil {
		bmConfig := ideConfig.BinaryManagementConfig
		configuration.IdeConfig.BinaryManagementConfig = &BinaryManagementConfig{
			AutomaticDownload: bmConfig.AutomaticDownload,
			CliPath:           bmConfig.CliPath,
		}
	}

	// Extract code actions
	if ideConfig.CodeActions != nil {
		codeActions := ideConfig.CodeActions
		configuration.IdeConfig.CodeActions = &CodeActions{
			OpenBrowser:     convertCodeActions(codeActions.OpenBrowser),
			OpenLearnLesson: convertCodeActions(codeActions.OpenLearnLesson),
			ScaUpgrade:      convertCodeActions(codeActions.ScaUpgrade),
		}
	}

	// Extract issue view config
	if ideConfig.IssueViewConfig != nil {
		ivConfig := ideConfig.IssueViewConfig
		configuration.IdeConfig.IssueViewConfig = &IssueViewConfig{
			IgnoredIssues: ivConfig.IgnoredIssues,
			OpenIssues:    ivConfig.OpenIssues,
		}
	}

	// Extract product config
	if ideConfig.ProductConfig != nil {
		productConfig := ideConfig.ProductConfig
		configuration.IdeConfig.ProductConfig = &ProductConfig{
			Code:      productConfig.Code != nil && *productConfig.Code,
			Container: productConfig.Container != nil && *productConfig.Container,
			Iac:       productConfig.Iac != nil && *productConfig.Iac,
			Oss:       productConfig.Oss != nil && *productConfig.Oss,
		}
	}

	// Extract scan config
	if ideConfig.ScanConfig != nil {
		scanConfig := ideConfig.ScanConfig
		configuration.IdeConfig.ScanConfig = &ScanConfig{
			Automatic: scanConfig.Automatic,
			NetNew:    scanConfig.NetNew,
		}
	}

	// Extract trust config
	if ideConfig.TrustConfig != nil {
		trustConfig := ideConfig.TrustConfig
		configuration.IdeConfig.TrustConfig = &TrustConfig{
			Enable:         trustConfig.Enable,
			TrustedFolders: convertStringSlice(trustConfig.TrustedFolders),
		}
	}
}

// extractCompleteOrganizations extracts complete organization data
func (c *client) extractCompleteOrganizations(configData *v20241015.ConfigData, configuration *Configuration) {
	if configData.Organizations == nil {
		return
	}

	organizations := make([]Organization, 0, len(*configData.Organizations))
	for _, org := range *configData.Organizations {
		organizations = append(organizations, Organization{
			Id:                   org.Id,
			IsDefault:            org.IsDefault,
			Name:                 org.Name,
			PreferredByAlgorithm: org.PreferredByAlgorithm,
			ProjectCount:         org.ProjectCount,
			Slug:                 org.Slug,
		})
	}

	configuration.Organizations = organizations
}

// extractAttributeSource extracts attribute source configuration
func (c *client) extractAttributeSource(attributes *v20241015.ConfigAttributes, configuration *Configuration) {
	configuration.AttributeSource = &AttributeSource{
		Asset:       convertStringSlice(attributes.AttributeSource.Asset),
		Group:       convertStringSlice(attributes.AttributeSource.Group),
		Org:         convertStringSlice(attributes.AttributeSource.Org),
		ProjectName: convertStringSlice(attributes.AttributeSource.ProjectName),
		RemoteUrl:   convertStringSlice(attributes.AttributeSource.RemoteUrl),
		Tenant:      convertStringSlice(attributes.AttributeSource.Tenant),
	}
}

// extractTimestamps extracts timestamp information
func (c *client) extractTimestamps(attributes *v20241015.ConfigAttributes, configuration *Configuration) {
	configuration.CreatedAt = attributes.CreatedAt
	configuration.LastModifiedAt = &attributes.LastModifiedAt
}

// extractScope extracts scope information
func (c *client) extractScope(attributes *v20241015.ConfigAttributes, configuration *Configuration) {
	scope := string(attributes.Scope)
	configuration.Scope = &scope
}

// extractPolicy extracts policy configuration
func (c *client) extractPolicy(attributes *v20241015.ConfigAttributes, configuration *Configuration) {
	if attributes.Policy != nil {
		configuration.Policy = &Policy{
			EnforcedAttributes: convertStringSlice(attributes.Policy.EnforcedAttributes),
			LockedAttributes:   convertStringSlice(attributes.Policy.LockedAttributes),
		}
	}
}

// Helper functions

// convertStringSlice converts a pointer to string slice to a regular string slice
func convertStringSlice(ptr *[]string) []string {
	if ptr == nil {
		return nil
	}
	return *ptr
}

// convertCodeActions converts API code actions to our code actions
func convertCodeActions(ptr *v20241015.CodeActions) []CodeAction {
	if ptr == nil {
		return nil
	}

	codeActions := make([]CodeAction, 0, len(*ptr))
	for _, action := range *ptr {
		codeActions = append(codeActions, CodeAction{
			Enabled:         action.Enabled,
			IntegrationName: action.IntegrationName,
		})
	}
	return codeActions
}
