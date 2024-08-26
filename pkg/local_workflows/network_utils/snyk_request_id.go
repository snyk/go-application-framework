package network_utils

import (
	"github.com/google/uuid"

	"github.com/snyk/go-application-framework/pkg/networking"
)

// AddSnykRequestId adds a snyk-request-id header to the request.
//
// If the header is already present, it will not be overwritten.
// If the header is not present, a new UUID will be generated and added.
// This is usefud for tracking requests across services.
func AddSnykRequestId(n networking.NetworkAccess) {
	n.AddDynamicHeaderField("snyk-request-id", func(values []string) []string {
		if len(values) > 0 {
			return values
		}
		return []string{uuid.NewString()}
	})
}
