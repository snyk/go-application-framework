package contract

type OrgIgnoreSettings struct {
	ReasonRequired          bool `json:"reasonRequired,omitempty"`
	AutoApproveIgnores      bool `json:"autoApproveIgnores,omitempty"`
	ApprovalWorkflowEnabled bool `json:"approvalWorkflowEnabled,omitempty"`
}

type OrgSettingsResponse struct {
	Ignores OrgIgnoreSettings `json:"ignores"`
}
