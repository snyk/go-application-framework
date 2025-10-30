package filters

import (
	"context"

	"github.com/google/uuid"
)

type FakeClient struct {
	getFilters func(ctx context.Context, orgID uuid.UUID) (AllowList, error)
}

var _ Client = (*FakeClient)(nil)

func NewFakeClient(allowList AllowList, err error) *FakeClient {
	return &FakeClient{
		getFilters: func(ctx context.Context, orgID uuid.UUID) (AllowList, error) {
			return allowList, err
		},
	}
}

func (f *FakeClient) GetFilters(ctx context.Context, orgID uuid.UUID) (AllowList, error) {
	return f.getFilters(ctx, orgID)
}
