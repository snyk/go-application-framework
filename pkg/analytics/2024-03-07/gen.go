package v20240307

//go:generate oapi-codegen -config spec.config.yaml spec.yaml

// We can't pull the spec from the remote as analytics-service is a private repo
// //go:generate bash -c "mkdir -p 2024-03-07 && curl -s https://raw.githubusercontent.com/snyk/analytics-service/main/internal/hidden/resources/analytics/2024-03-07/spec.yaml | oapi-codegen -package=v20240307 -generate=types,client,spec -o=v20240307/client-gen.go /dev/stdin"
