package v20240319

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/oklog/ulid"
)

// Enum of PAT type.
const (
	TypePAT Type = iota + 1
)

var (
	typeToString = map[Type]string{
		TypePAT: "personal_access_token",
	}

	stringToType = map[string]Type{
		"personal_access_token": TypePAT,
	}
)

// Type represents the different types of PAT.
type Type int

// ParseType parses a string representing a type and returns a Type if valid.
// It returns an error if the string representation is not a valid type.
func ParseType(str string) (t Type, err error) {
	t, ok := stringToType[str]
	if !ok {
		err = fmt.Errorf("invalid PAT type: %q", str)
	}
	return
}

// IsValid returns true if Type is valid.
func (t Type) IsValid() bool {
	_, ok := typeToString[t]
	return ok
}

// MarshalJSON makes Type implement the json.Marshaler interface.
func (t Type) MarshalJSON() ([]byte, error) {
	str, ok := typeToString[t]
	if !ok {
		return nil, fmt.Errorf("unknown PAT type: %d", t)
	}
	return []byte(`"` + str + `"`), nil
}

// String returns a string representation of the Type.
func (t Type) String() string {
	str, ok := typeToString[t]
	if !ok {
		return fmt.Sprintf("unknown PAT type %d", t)
	}
	return str
}

// UnmarshalJSON makes Type implement the json.Unmarshaler interface.
func (t *Type) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err //nolint:wrapcheck // no need to wrap
	}

	ptype, err := ParseType(s)
	if err != nil {
		return err
	}

	*t = ptype

	return nil
}

type (
	// Meta represents non-standard meta-information as defined in
	// https://jsonapi.org/format/#document-meta.
	Meta map[string]interface{}

	// Links represents links on a resource document.
	Links struct {
		Self    *Link `json:"self,omitempty"`
		Related *Link `json:"related,omitempty"`
	}

	// Link represents a links object as defined in
	// https://jsonapi.org/format/#document-links.
	Link struct {
		href string
		meta Meta
	}

	// CreatePATRequestBody request body.
	CreatePATRequestBody struct {
		// Data contained in request body.
		Data CreatePATRequestData `json:"data"`
	}

	// CreatePATRequestData request body data.
	CreatePATRequestData struct {
		// Attributes of the data object.
		Attributes CreatePATRequestAttributes `json:"attributes"`
		// Type of resource.
		Type Type `json:"type"`
	}

	// CreatePATRequestAttributes request attributes.
	CreatePATRequestAttributes struct {
		// ExpiresAt expiration for PAT.
		ExpiresAt time.Time `json:"expires_at"`
		// Label for PAT.
		Label string `json:"label"`
	}
)

type (
	// JSONAPI describes a service's implementation of the JSON API specification.
	JSONAPI struct {
		Version string `json:"version"`
	}

	// CreatePATResponseBody response body.
	CreatePATResponseBody struct {
		// JSONAPI represents the JSON API version.
		JSONAPI JSONAPI `json:"jsonapi"`
		// Data contained in response.
		Data CreatePATResponseData `json:"data"`
		// Links contained in response.
		Links Links `json:"links"`
	}

	// CreatePATResponseData response body data.
	CreatePATResponseData struct {
		// Attributes of resource.
		Attributes CreatePATResponseAttributes `json:"attributes"`
		// ID of the resource.
		ID ulid.ULID `json:"id"`
		// Type of the resource.
		Type Type `json:"type"`
	}

	// CreatePATResponseAttributes response attributes.
	CreatePATResponseAttributes struct {
		// CreatedAt timestamp for PAT.
		CreatedAt time.Time `json:"created_at"`
		// ExpiresAt timestamp for PAT.
		ExpiresAt time.Time `json:"expires_at"`
		// Label for PAT.
		Label string `json:"label"`
		// Token is the actual PAT.
		Token string `json:"token"`
	}

	// GetPATMetadataResponseBody response body.
	GetPATMetadataResponseBody struct {
		// JSONAPI represents the JSON API version.
		JSONAPI JSONAPI `json:"jsonapi"`
		// Data contained in response.
		Data GetPATMetadataResponseData `json:"data"`
		// Links contained in response.
		Links Links `json:"links"`
	}

	// GetPATMetadataResponseData response body data.
	GetPATMetadataResponseData struct {
		// Attributes of resource.
		Attributes GetPATMetadataResponseAttributes `json:"attributes"`
		// ID of the resource.
		ID ulid.ULID `json:"id"`
		// Type of the resource.
		Type Type `json:"type"`
	}

	// GetPATMetadataResponseAttributes response attributes.
	GetPATMetadataResponseAttributes struct {
		// Hostname returns the hostname of the environment the token belongs to. An empty string
		// is returned if it is not associated with an environment.
		Hostname string `json:"hostname"`
	}
)
