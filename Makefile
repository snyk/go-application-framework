LOG_PREFIX = --
GOOS = $(shell go env GOOS)
GOARCH = $(shell go env GOARCH)

GO_BIN := $(shell pwd)/.bin
OVERRIDE_GOCI_LINT_V := v1.60.1
SHELL := env PATH="$(GO_BIN):$(PATH)" $(SHELL)

.PHONY: format
format:
	@echo "Formatting..."
	@gofmt -w -l -e .

.PHONY: lint
lint: $(GO_BIN)/golangci-lint $(GO_BIN)/cue
	@echo "Linting..."
	@./scripts/lint.sh
	$(GO_BIN)/golangci-lint run ./...

.PHONY: build
build:
	@echo "Building for $(GOOS)_$(GOARCH)..."
	@GOOS=$(GOOS) GOARCH=$(GOARCH) go build ./...

.PHONY: clean
clean:
	@echo "Cleaning up..."
	@GOOS=$(GOOS) GOARCH=$(GOARCH) go clean -testcache

.PHONY: test
test:
	@echo "Testing..."
	@go test -cover ./... -race

.PHONY: testv
testv:
	@echo "Testing verbosely..."
	@go test -v ./... -race

.PHONY: generate
generate: tools
	@echo "Generating generated files..."
	@go generate ./...
	@make format

.PHONY: tools
tools: $(GO_BIN)/cue $(GO_BIN)/golangci-lint $(GO_BIN)/oapi-codegen $(GO_BIN)/mockgen
	@echo "Installing tools..."

$(GO_BIN)/cue:
	GOBIN=$(GO_BIN) go install cuelang.org/go/cmd/cue@v0.10.0

$(GO_BIN)/golangci-lint:
	curl -sSfL 'https://raw.githubusercontent.com/golangci/golangci-lint/${OVERRIDE_GOCI_LINT_V}/install.sh' | sh -s -- -b ${GO_BIN} ${OVERRIDE_GOCI_LINT_V}

$(GO_BIN)/mockgen:
	GOBIN=$(GO_BIN) go install github.com/golang/mock/mockgen@v1.6.0

$(GO_BIN)/oapi-codegen:
	GOBIN=$(GO_BIN) go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.3.0

.PHONY: update-local-findings
update-local-findings:
	@scripts/pull-down-test-api-spec.sh
	@make generate

.PHONY: help
help:
	@echo "Main targets:"
	@echo "$(LOG_PREFIX) tools                      Installs the tools required for development and testing"
	@echo "$(LOG_PREFIX) format"
	@echo "$(LOG_PREFIX) lint"
	@echo "$(LOG_PREFIX) build"
	@echo "$(LOG_PREFIX) generate                   Regenerates generated files (e.g. mocks)"
	@echo "$(LOG_PREFIX) test"
	@echo "$(LOG_PREFIX) testv                      Test versbosely"
	@echo "$(LOG_PREFIX) GOOS                       Specify Operating System to compile for (see golang GOOS, default=$(GOOS))"
	@echo "$(LOG_PREFIX) GOARCH                     Specify Architecture to compile for (see golang GOARCH, default=$(GOARCH))"
