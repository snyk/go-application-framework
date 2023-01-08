package contract

type SelfResponseDataAttribute struct {
	AvatarUrl         string `json:"avatar_url,omitempty"`
	DefaultOrgContext string `json:"default_org_context,omitempty"`
	Name              string `json:"name,omitempty"`
	Username          string `json:"username,omitempty"`
	Email             string `json:"email,omitempty"`
}

type SelfResponseData struct {
	Attributes SelfResponseDataAttribute `json:"attributes,omitempty"`
	Id         string                    `json:"id,omitempty"`
	Type       string                    `json:"type,omitempty"`
}

type SelfResponse struct {
	Data SelfResponseData
}
