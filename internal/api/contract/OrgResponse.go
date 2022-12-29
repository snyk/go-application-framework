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
