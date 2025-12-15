package tenantsapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListTenants_DefaultVersionWhenParamsNil(t *testing.T) {
	t.Parallel()

	gotVersion := make(chan string, 1)
	gotPath := make(chan string, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVersion <- r.URL.Query().Get("version")
		gotPath <- r.URL.Path

		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"data":[],"jsonapi":{"version":"1.0"},"links":{}}`)); err != nil {
			t.Fatal(err)
		}
	}))
	defer srv.Close()

	client, err := NewClientWithResponses(srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("NewClientWithResponses: %v", err)
	}

	resp, err := ListTenants(context.Background(), client, nil)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected non-nil response")
	}
	if len(resp.Tenants) != 0 {
		t.Fatalf("expected 0 tenants, got %d", len(resp.Tenants))
	}

	if v := <-gotVersion; v != DefaultAPIVersion {
		t.Fatalf("expected version %q, got %q", DefaultAPIVersion, v)
	}
	if p := <-gotPath; p != "/rest/tenants" {
		t.Fatalf("expected path %q, got %q", "/rest/tenants", p)
	}
}

func TestListTenants_DefaultVersionWhenParamsVersionEmpty(t *testing.T) {
	t.Parallel()

	gotVersion := make(chan string, 1)
	gotPath := make(chan string, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVersion <- r.URL.Query().Get("version")
		gotPath <- r.URL.Path

		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"data":[],"jsonapi":{"version":"1.0"},"links":{}}`)); err != nil {
			t.Fatal(err)
		}
	}))
	defer srv.Close()

	client, err := NewClientWithResponses(srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("NewClientWithResponses: %v", err)
	}

	params := &ListTenantsParams{}
	_, err = ListTenants(context.Background(), client, params)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}

	if v := <-gotVersion; v != DefaultAPIVersion {
		t.Fatalf("expected version %q, got %q", DefaultAPIVersion, v)
	}
	if p := <-gotPath; p != "/rest/tenants" {
		t.Fatalf("expected path %q, got %q", "/rest/tenants", p)
	}
}

func TestListTenants_RespectsProvidedVersion(t *testing.T) {
	t.Parallel()

	gotVersion := make(chan string, 1)
	gotPath := make(chan string, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVersion <- r.URL.Query().Get("version")
		gotPath <- r.URL.Path

		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"data":[],"jsonapi":{"version":"1.0"},"links":{}}`)); err != nil {
			t.Fatal(err)
		}
	}))
	defer srv.Close()

	client, err := NewClientWithResponses(srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("NewClientWithResponses: %v", err)
	}

	expected := Version("2025-01-01")
	params := &ListTenantsParams{Version: expected}
	_, err = ListTenants(context.Background(), client, params)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}

	if v := <-gotVersion; v != expected {
		t.Fatalf("expected version %q, got %q", expected, v)
	}
	if p := <-gotPath; p != "/rest/tenants" {
		t.Fatalf("expected path %q, got %q", "/rest/tenants", p)
	}
}

func TestListTenants_ServerAlreadyContainsRest(t *testing.T) {
	t.Parallel()

	gotPath := make(chan string, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath <- r.URL.Path

		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"data":[],"jsonapi":{"version":"1.0"},"links":{}}`)); err != nil {
			t.Fatal(err)
		}
	}))
	defer srv.Close()

	client, err := NewClientWithResponses(srv.URL+"/rest", srv.Client())
	if err != nil {
		t.Fatalf("NewClientWithResponses: %v", err)
	}

	_, err = ListTenants(context.Background(), client, nil)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}

	if p := <-gotPath; p != "/rest/tenants" {
		t.Fatalf("expected path %q, got %q", "/rest/tenants", p)
	}
}
