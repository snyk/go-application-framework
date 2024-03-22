package contract

type OrgFeatureFlagResponse struct {
	Ok          bool   `json:"ok,omitempty"`
	UserMessage string `json:"userMessage,omitempty"`
	Code        int    `json:"code,omitempty,string"`
	Error       string `json:"error,omitempty"`
}
