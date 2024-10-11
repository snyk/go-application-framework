LOG_PREFIX = --
GOOS = $(shell go env GOOS)
GOARCH = $(shell go env GOARCH)

GO_BIN := $(shell pwd)/.bin
OVERRIDE_GOCI_LINT_V := v1.59.1
SHELL := env PATH=$(GO_BIN):$(PATH) $(SHELL)

.PHONY: format
format:
	@echo "Formatting..."
	@cue fmt internal/cueutils/**/**/*.cue internal/cueutils/**/*.cue
	@gofmt -w -l -e .

.PHONY: lint
lint: $(GO_BIN)/golangci-lint $(GO_BIN)/cue
	@echo "Linting..."
	@cue fmt --all-errors --check internal/cueutils/**/**/*.cue internal/cueutils/**/*.cue
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
	@go test -cover ./...

.PHONY: testv
testv:
	@echo "Testing verbosely..."
	@go test -v ./...

.PHONY: generate
generate:
	@go generate ./...

.PHONY: tools
tools: $(GO_BIN)/golangci-lint $(GO_BIN)/cue
	GOBIN=$(GO_BIN) go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.3.0
	GOBIN=$(GO_BIN) go install github.com/golang/mock/mockgen@v1.6.0

$(GO_BIN)/cue:
	GOBIN=$(GO_BIN) go install cuelang.org/go/cmd/cue@v0.10.0

$(GO_BIN)/golangci-lint:
	curl -sSfL 'https://raw.githubusercontent.com/golangci/golangci-lint/${OVERRIDE_GOCI_LINT_V}/install.sh' | sh -s -- -b ${GO_BIN} ${OVERRIDE_GOCI_LINT_V}

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
