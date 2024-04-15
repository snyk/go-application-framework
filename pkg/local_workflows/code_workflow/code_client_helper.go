package code_workflow

import (
	"context"
	"strings"

	"github.com/snyk/code-client-go/observability"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

type codeClientConfig struct {
	localConfiguration configuration.Configuration
}

func (c *codeClientConfig) Organization() string {
	return c.localConfiguration.GetString(configuration.ORGANIZATION)
}

func (c *codeClientConfig) IsFedramp() bool {
	return c.localConfiguration.GetBool(configuration.IS_FEDRAMP)
}

func (c *codeClientConfig) SnykCodeApi() string {
	return strings.Replace(c.localConfiguration.GetString(configuration.API_URL), "api", "deeproxy", -1)
}

func (c *codeClientConfig) SnykApi() string {
	return c.localConfiguration.GetString(configuration.API_URL)
}

type codeClientErrorReporter struct{}

func (c *codeClientErrorReporter) FlushErrorReporting() {}
func (c *codeClientErrorReporter) CaptureError(err error, options observability.ErrorReporterOptions) bool {
	return true
}

type codeClientSpan struct {
	transactionName string
	operationName   string
}

func (c *codeClientSpan) SetTransactionName(name string) { c.transactionName = name }
func (c *codeClientSpan) StartSpan(ctx context.Context)  {}
func (c *codeClientSpan) Finish()                        {}
func (c *codeClientSpan) GetOperation() string           { return c.operationName }
func (c *codeClientSpan) GetTxName() string              { return c.transactionName }
func (c *codeClientSpan) GetTraceId() string             { return "" } // TODO: interaction id
func (c *codeClientSpan) Context() context.Context       { return context.Background() }
func (c *codeClientSpan) GetDurationMs() int64           { return 0 }

type codeClientInstrumentor struct{}

func (c *codeClientInstrumentor) StartSpan(ctx context.Context, operation string) observability.Span {
	return &codeClientSpan{operationName: operation}
}
func (c *codeClientInstrumentor) NewTransaction(ctx context.Context, txName string, operation string) observability.Span {
	return &codeClientSpan{operationName: operation, transactionName: txName}
}
func (c *codeClientInstrumentor) Finish(span observability.Span) {
	span.Finish()
}
