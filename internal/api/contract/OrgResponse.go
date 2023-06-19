package contract

type Organization struct {
	Name  string `json:"name"`
	ID    string `json:"id"`
	Slug  string `json:"slug"`
	URL   string `json:"url"`
	Group *Group `json:"group"`
}

type Group struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

type OrganizationsResponse struct {
	Organizations []Organization `json:"orgs"`
}

type RestApiOrganizationAttributes struct {
	GroupId    string `json:"group_id,omitempty"`
	IsPersonal bool   `json:"is_personal,omitempty"`
	Name       string `json:"name,omitempty"`
	Slug       string `json:"slug,omitempty"`
}

type RestApiOrganizationData struct {
	Attributes RestApiOrganizationAttributes `json:"attributes,omitempty"`
	Id         string                        `json:"id,omitempty"`
	Type       string                        `json:"type,omitempty"`
}

type RestApiOrganizationsResponse struct {
	Data RestApiOrganizationData
}
