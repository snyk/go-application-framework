package contract

// API reference: https://docs.snyk.io/snyk-api/reference/organizations-v1#get-org-orgid-settings

type OrgIgnoreSettings struct {
	ReasonRequired          bool `json:"reasonRequired,omitempty"`
	AutoApproveIgnores      bool `json:"autoApproveIgnores,omitempty"`
	ApprovalWorkflowEnabled bool `json:"approvalWorkflowEnabled,omitempty"`
}

type OrgRequestAccessSettings struct {
	Enabled bool `json:"enabled,omitempty"`
}

type OrgSettingsResponse struct {
	Ignores       *OrgIgnoreSettings        `json:"ignores"`
	RequestAccess *OrgRequestAccessSettings `json:"requestAccess"`
}
