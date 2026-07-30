package configtypes

import (
	"context"
	"time"
)

//go:generate go tool github.com/golang/mock/mockgen -source=storage.go -destination ../../mocks/config_storage.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/configuration/configtypes/

// Storage persists configuration values that outlive a single process run.
type Storage interface {
	Set(key string, value any) error
	Refresh(config Configuration, key string) error
	Lock(ctx context.Context, retryDelay time.Duration) error
	Unlock() error
}
