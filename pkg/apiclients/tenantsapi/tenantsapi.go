package tenantsapi

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/snyk/go-application-framework/pkg/apiclients/tenantsapi/internal/generated"
)

type Version = generated.Version

type ListTenantsParams = generated.ListTenantsParams
type RequestEditorFn = generated.RequestEditorFn

type Client interface {
	ListTenants(ctx context.Context, params *ListTenantsParams, reqEditors ...RequestEditorFn) (*ListTenantsResult, error)
}

type client struct {
	ll *generated.ClientWithResponses
}

type Tenant struct {
	ID   string
	Name string
	Slug string
}

type ListTenantsLinks struct {
	First string
	Last  string
	Next  string
	Prev  string
}

type ListTenantsResult struct {
	Tenants []Tenant
	Links   ListTenantsLinks
}

const DefaultAPIVersion Version = "2024-10-15"

func NewClientWithResponses(server string, httpClient *http.Client) (Client, error) {
	server, err := normalizeServerURL(server)
	if err != nil {
		return nil, err
	}

	ll, err := generated.NewClientWithResponses(server, generated.WithHTTPClient(httpClient))
	if err != nil {
		return nil, err
	}
	return &client{ll: ll}, nil
}

func (c *client) ListTenants(ctx context.Context, params *ListTenantsParams, reqEditors ...RequestEditorFn) (*ListTenantsResult, error) {
	if params == nil {
		params = &ListTenantsParams{Version: DefaultAPIVersion}
	} else if params.Version == "" {
		params.Version = DefaultAPIVersion
	}

	rsp, err := c.ll.ListTenantsWithResponse(ctx, params, reqEditors...)
	if err != nil {
		return nil, err
	}
	if rsp.ApplicationvndApiJSON200 == nil {
		return nil, fmt.Errorf("unexpected ListTenants response status %d", rsp.StatusCode())
	}

	out := &ListTenantsResult{
		Tenants: make([]Tenant, 0, len(rsp.ApplicationvndApiJSON200.Data)),
		Links: ListTenantsLinks{
			First: linkPropertyToString(rsp.ApplicationvndApiJSON200.Links.First),
			Last:  linkPropertyToString(rsp.ApplicationvndApiJSON200.Links.Last),
			Next:  linkPropertyToString(rsp.ApplicationvndApiJSON200.Links.Next),
			Prev:  linkPropertyToString(rsp.ApplicationvndApiJSON200.Links.Prev),
		},
	}

	for _, t := range rsp.ApplicationvndApiJSON200.Data {
		out.Tenants = append(out.Tenants, Tenant{
			ID:   t.Id.String(),
			Name: t.Attributes.Name,
			Slug: t.Attributes.Slug,
		})
	}

	return out, nil
}

func ListTenants(ctx context.Context, client Client, params *ListTenantsParams, reqEditors ...RequestEditorFn) (*ListTenantsResult, error) {
	return client.ListTenants(ctx, params, reqEditors...)
}

func linkPropertyToString(lp *generated.LinkProperty) string {
	if lp == nil {
		return ""
	}
	if v, err := lp.AsLinkProperty0(); err == nil {
		return v
	}
	if v, err := lp.AsLinkProperty1(); err == nil {
		return v.Href
	}
	return ""
}

func normalizeServerURL(server string) (string, error) {
	u, err := url.Parse(server)
	if err != nil {
		return "", err
	}

	trimmedPath := strings.TrimSuffix(u.Path, "/")
	if trimmedPath == "" {
		trimmedPath = "/"
	}
	if trimmedPath == "/rest" || strings.HasSuffix(trimmedPath, "/rest") {
		return u.String(), nil
	}

	u.Path = path.Join(u.Path, "rest")
	if !strings.HasPrefix(u.Path, "/") {
		u.Path = "/" + u.Path
	}

	return u.String(), nil
}
