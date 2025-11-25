package contract

type AvailableTenantsResponse struct {
	Data    []TenantResource `json:"data"`
	JSONAPI JSONApi          `json:"jsonapi"`
	Links   Links            `json:"links"`
}

type TenantResource struct {
	ID            string              `json:"id"`
	Type          string              `json:"type"`
	Attributes    TenantAttributes    `json:"attributes"`
	Relationships TenantRelationships `json:"relationships"`
}

type TenantAttributes struct {
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
}

type TenantRelationships struct {
	Owner OwnerRelationship `json:"owner"`
}

type OwnerRelationship struct {
	Data OwnerData `json:"data"`
}

type OwnerData struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type JSONApi struct {
	Version string `json:"version"`
}

type Links struct {
	First string `json:"first"`
	Last  string `json:"last"`
	Next  string `json:"next"`
}
