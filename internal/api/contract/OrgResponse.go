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
	Group struct {
		Data struct {
			Id   string `json:"id"`
			Type string `json:"type"`
		} `json:"data"`
	} `json:"group"`
}

type Organization struct {
	Id            string           `json:"id"`
	Type          string           `json:"type"`
	Attributes    OrgAttributes    `json:"attributes"`
	Relationships OrgRelationships `json:"relationships"`
}

type IncludedItem struct {
	Id         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		Name string `json:"name"`
	} `json:"attributes"`
}

type OrganizationsResponse struct {
	Organizations []Organization `json:"data"`
	Included      []IncludedItem `json:"included"`
	Jsonapi       struct {
		Version string `json:"version"`
	} `json:"jsonapi"`
	Links struct {
		Self  string `json:"self"`
		First string `json:"first"`
	} `json:"links"`
}
