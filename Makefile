LOG_PREFIX = --
GOOS = $(shell go env GOOS)
GOARCH = $(shell go env GOARCH)

GO_BIN := $(shell pwd)/.bin
OVERRIDE_GOCI_LINT_V := v2.10.1
SHELL := env PATH=$(GO_BIN):$(shell go env GOROOT)/bin:$(PATH) $(SHELL)

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
tools: $(GO_BIN)/golangci-lint

$(GO_BIN)/golangci-lint:
	curl -sSfL 'https://golangci-lint.run/install.sh' | sh -s -- -b ${GO_BIN} ${OVERRIDE_GOCI_LINT_V}

.PHONY: update-dragonfly
update-dragonfly:
	@scripts/pull-down-dragonfly-api-spec.sh
	@make generate


.PHONY: update-local-findings
update-local-findings:
	@scripts/pull-down-test-api-spec.sh
	@make generate

# Default scan for fixture generation — override on the CLI: SCAN_CMD="test ."
SNYK_FIXTURE_SCAN ?= secrets test .
.PHONY: generate-fixture
generate-fixture:
	@PROJECT="$(PROJECT)" ORG="$(ORG)" NAME="$(NAME)" SNYK_BIN="$(SNYK_BIN)" DUMP_DIR="$(DUMP_DIR)" OUT_DIR="$(OUT_DIR)" SCAN_CMD="$(SCAN_CMD)" REPORT="$(REPORT)" REDACT="$(REDACT)" DEFAULT_SCAN_CMD="$(SNYK_FIXTURE_SCAN)" ./scripts/generate-fixture.sh

.PHONY: redact-fixture
redact-fixture:
	@go run ./cmd/ufm-fixture-tool --input=$(INPUT) $(if $(OUTPUT),--output=$(OUTPUT),)

.PHONY: regenerate-expected
regenerate-expected:
	@UFM_REGEN=1 go test ./internal/presenters/... -run 'Test_UfmPresenter' -count=1

.PHONY: help
help:
	@echo "Main targets:"
	@echo "$(LOG_PREFIX) tools                      Install linter and dev dependencies"
	@echo "$(LOG_PREFIX) format"
	@echo "$(LOG_PREFIX) lint"
	@echo "$(LOG_PREFIX) build"
	@echo "$(LOG_PREFIX) generate                   Regenerate generated files (e.g. mocks)"
	@echo "$(LOG_PREFIX) test"
	@echo "$(LOG_PREFIX) testv                      Test verbosely"
	@echo ""
	@echo "Fixture targets:"
	@echo "$(LOG_PREFIX) generate-fixture PROJECT=/path ORG=slug NAME=name [SNYK_BIN=snyk] [REPORT=1] [REDACT=1]"
	@echo "$(LOG_PREFIX)   Optional: OUT_DIR=$(CURDIR)/dumps SNYK_FIXTURE_SCAN='secrets test .' SCAN_CMD='...'"
	@echo "$(LOG_PREFIX) redact-fixture INPUT=path [OUTPUT=path]  Redact a workflow dump into a stable test fixture"
	@echo "$(LOG_PREFIX) regenerate-expected        Regenerate expected SARIF + human-readable files from existing fixtures"
	@echo ""
	@echo "$(LOG_PREFIX) GOOS                       Specify Operating System to compile for (see golang GOOS, default=$(GOOS))"
	@echo "$(LOG_PREFIX) GOARCH                     Specify Architecture to compile for (see golang GOARCH, default=$(GOARCH))"
