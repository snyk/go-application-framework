package machineenrollment

import (
	"context"
	"fmt"
	"net/http"
)

const tenantsPath = "/rest/tenants"

// Tenant is a tenant the authenticated principal can access.
type Tenant struct {
	ID   string
	Name string
}

// ListTenants returns the tenants the principal httpClient authenticates as can access. It is how
// an enrolled machine checks that its credential works.
func ListTenants(ctx context.Context, httpClient *http.Client, apiURL string) ([]Tenant, error) {
	var res struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				Name string `json:"name"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := doJSONAPI(ctx, httpClient, http.MethodGet, apiURL+tenantsPath, "", http.StatusOK, &res); err != nil {
		return nil, fmt.Errorf("failed listing tenants: %w", err)
	}

	tenants := make([]Tenant, 0, len(res.Data))
	for _, t := range res.Data {
		tenants = append(tenants, Tenant{ID: t.ID, Name: t.Attributes.Name})
	}
	return tenants, nil
}
