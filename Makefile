LOG_PREFIX = --
GOOS = $(shell go env GOOS)
GOARCH = $(shell go env GOARCH)

GO_BIN := $(shell pwd)/.bin
OVERRIDE_GOCI_LINT_V := v1.55.2
SHELL := env PATH=$(GO_BIN):$(PATH) $(SHELL)

.PHONY: format
format:
	@echo "Formatting..."
	@gofmt -w -l -e .

.PHONY: lint
lint: $(GO_BIN)/golangci-lint
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
	npm run clean

.PHONY: test
test:
	@echo "Testing..."
	@go test -cover ./...

.PHONY: testv
testv:
	@echo "Testing verbosely..."
	@go test -v ./...

.PHONY: generate
generate:
	@go generate ./...
	npm run build

.PHONY: tools
tools: $(GO_BIN)/golangci-lint $(GO_BIN)/mockgen $(GO_BIN)/oapi-codegen typespec-tools

$(GO_BIN)/golangci-lint:
	curl -sSfL 'https://raw.githubusercontent.com/golangci/golangci-lint/${OVERRIDE_GOCI_LINT_V}/install.sh' | sh -s -- -b ${GO_BIN} ${OVERRIDE_GOCI_LINT_V}

$(GO_BIN)/mockgen:
	GOBIN=$(GO_BIN) go install github.com/golang/mock/mockgen@latest

$(GO_BIN)/oapi-codegen:
	GOBIN=$(GO_BIN) go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen@latest

.PHONY: typespec-tools
typespec-tools: node_modules/.bin/typespec

node_modules/.bin/typespec:
	npm clean-install

.PHONY: help
help:
	@echo "Main targets:"
	@echo "$(LOG_PREFIX) format"
	@echo "$(LOG_PREFIX) lint"
	@echo "$(LOG_PREFIX) build"
	@echo "$(LOG_PREFIX) test"
	@echo "$(LOG_PREFIX) testv                      Test versbosely"
	@echo "$(LOG_PREFIX) GOOS                       Specify Operating System to compile for (see golang GOOS, default=$(GOOS))"
	@echo "$(LOG_PREFIX) GOARCH                     Specify Architecture to compile for (see golang GOARCH, default=$(GOARCH))"
