LOG_PREFIX = --
GOOS = $(shell go env GOOS)
GOARCH = $(shell go env GOARCH)

GO_BIN := $(shell pwd)/.bin

GOCI_LINT_V := v2.3.0
GOCI_LINT_TARGETS := $(GO_BIN)/golangci-lint $(GO_BIN)/.golangci-lint_$(GOCI_LINT_V)

SHELL := env PATH=$(GO_BIN):$(shell go env GOROOT)/bin:$(PATH) $(SHELL)

.PHONY: format
format:
	@echo "Formatting..."
	@gofmt -w -l -e .

.PHONY: lint
lint: $(GOCI_LINT_TARGETS)
	@echo "Linting..."
	@./scripts/lint.sh
	$(GO_BIN)/golangci-lint run --timeout=10m ./...

.PHONY: build
build:
	@echo "Building for $(GOOS)_$(GOARCH)..."
	@GOOS=$(GOOS) GOARCH=$(GOARCH) go build ./...

.PHONY: clean
clean:
	@echo "Cleaning up..."
	@GOOS=$(GOOS) GOARCH=$(GOARCH) go clean -testcache
	@rm -rf $(GO_BIN)

.PHONY: test
test:
	@echo "Testing..."
	@go test -cover ./... -race

.PHONY: testv
testv:
	@echo "Testing verbosely..."
	@go test -v ./... -race

.PHONY: generate
generate:
	@go generate ./...
	@make format

.PHONY: tools
tools: $(GOCI_LINT_TARGETS)

$(GOCI_LINT_TARGETS):
	@rm -f $(GO_BIN)/.golangci-lint_*
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/$(GOCI_LINT_V)/install.sh | sh -s -- -b $(GO_BIN) $(GOCI_LINT_V)
	@touch $(GO_BIN)/.golangci-lint_$(GOCI_LINT_V)

.PHONY: update-dragonfly
update-dragonfly:
	@scripts/pull-down-dragonfly-api-spec.sh
	@make generate


.PHONY: update-local-findings
update-local-findings:
	@scripts/pull-down-test-api-spec.sh
	@make generate

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
