package contract

type OrgAttributes struct {
	IsPersonal bool   `json:"is_personal"`
	Name       string `json:"name"`
	Slug       string `json:"slug"`
	GroupId    string `json:"group_id,omitempty"`
}

type OrgRelationships struct {
	MemberRole struct {
		Data struct {
			Id   string `json:"id"`
			Type string `json:"type"`
		} `json:"data"`
	} `json:"member_role"`
}

type Organization struct {
	Id            string           `json:"id"`
	Type          string           `json:"type"`
	Attributes    OrgAttributes    `json:"attributes"`
	Relationships OrgRelationships `json:"relationships"`
}

type OrganizationsResponse struct {
	Organizations []Organization `json:"data"`
	Jsonapi       struct {
		Version string `json:"version"`
	} `json:"jsonapi"`
	Links struct {
		Self  string `json:"self"`
		First string `json:"first"`
	} `json:"links"`
}
