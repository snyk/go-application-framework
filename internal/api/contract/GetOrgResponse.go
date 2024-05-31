package contract

import "time"

// api version 2024-03-12

type GetOrgAttributes struct {
	GroupId    string    `json:"group_id"`
	IsPersonal bool      `json:"is_personal"`
	Name       string    `json:"name"`
	Slug       string    `json:"slug"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type GetOrganizationResponse struct {
	Data struct {
		Id         string           `json:"id"`
		Type       string           `json:"type"`
		Attributes GetOrgAttributes `json:"attributes"`
	} `json:"data"`
	Jsonapi struct {
		Version string `json:"version"`
	} `json:"jsonapi"`
	Links struct {
		Self string `json:"self"`
	} `json:"links"`
}
