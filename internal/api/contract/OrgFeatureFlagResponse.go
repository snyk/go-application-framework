package contract

type OrgFeatureFlagResponse struct {
	Ok          bool    `json:"ok,omitempty"`
	UserMessage string  `json:"userMessage,omitempty"`
	Code        float64 `json:"code,omitempty"`
	Error       string  `json:"error,omitempty"`
}
