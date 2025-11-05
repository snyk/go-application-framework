package testapi

import "encoding/json"

// problemCommonFields represents the common fields shared by most Problem union variants.
// Used for efficient access without full type unmarshaling.
type problemCommonFields struct {
	ID string `json:"id"`
}

// GetID extracts the ID field from a Problem without full unmarshaling.
// Returns empty string if the Problem variant doesn't have an ID field (e.g., "other" type).
// This is more efficient than calling discriminator + type-specific As* methods.
func (p Problem) GetID() string {
	var common problemCommonFields
	if err := json.Unmarshal(p.union, &common); err != nil {
		return ""
	}
	return common.ID
}

// HasID returns true if this Problem variant has an ID field.
// Most Problem types have an ID except for "other".
func (p Problem) HasID() bool {
	return p.GetID() != ""
}
