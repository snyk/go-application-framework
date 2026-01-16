# Feature Flag Gateway API Client

This Feature Flag Gateway client is based off of the OpenAPI specification for the [Feature Flag Gateway API](https://github.com/snyk/feature-flag-gateway).


## Intent

This Go client provides API-level interactions with the Feature Flag Gateway. 

## Directory Contents

This directory contains the following files that enable the above intent:

- `spec.config.yaml`: Configuration file for the codegen utility; defines the resulting package name, output file name, and which components to generate (models and client).
- `gen.go`: defines the `go:generate` step to create the API client.
- `feature_flag_gateway.go`: Generated Go API client and models for the Feature Flag Gateway Service.
- `spec.yaml`: OpenAPI specification for the most recent version of the Feature Flag Gateway API.

## Usage

- Run `./scripts/pull-down-ffg-sync-api.sh` to fetch the latest Feature Flag Gateway OpenAPI spec into <repo>/pkg/apiclients/feature-flag-gateway/< version>/spec.yaml.
    - Note: read access to the internal Feature Flag Gateway API repo is required.
- `cd <repo>/pkg/apiclients/feature-flag-gateway/`
- Run `go generate` to create the `feature_flag_gateway.go` API functions.
