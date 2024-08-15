package network_utils

import (
	"github.com/google/uuid"

	"github.com/snyk/go-application-framework/pkg/networking"
)

func AddSnykRequestId(n networking.NetworkAccess) {
	n.AddDynamicHeaderField("snyk-request-id", func(values []string) []string {
		if len(values) > 0 {
			return values
		}
		return []string{uuid.NewString()}
	})
}
