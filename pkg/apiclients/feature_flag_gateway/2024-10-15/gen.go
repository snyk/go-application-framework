package v20241015

//go:generate go tool github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen -package=v20241015 -config spec.config.yaml spec.yaml
//go:generate go tool github.com/golang/mock/mockgen -source=feature_flag_gateway.go -destination ../mocks/feature_flag_gateway.go -package mocks -imports v20241015=github.com/snyk/go-application-framework/pkg/apiclients/feature_flag_gateway/2024-10-15
