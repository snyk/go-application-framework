package workflow

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/snyk/go-application-framework/pkg/analytics"
)

func NewAnalyticsWrapper(a analytics.Analytics, prefix string) analytics.Analytics {
	return &analyticsWrapper{a, prefix}
}

type analyticsWrapper struct {
	next   analytics.Analytics
	prefix string
}

func (a *analyticsWrapper) SetCmdArguments(args []string) {
	a.next.SetCmdArguments(args)
}

func (a *analyticsWrapper) SetOrg(org string) {
	a.next.SetOrg(org)
}

func (a *analyticsWrapper) SetVersion(version string) {
	a.next.SetVersion(version)
}

func (a *analyticsWrapper) SetApiUrl(apiUrl string) {
	a.next.SetApiUrl(apiUrl)
}

func (a *analyticsWrapper) SetIntegration(name string, version string) {
	a.next.SetIntegration(name, version)
}

func (a *analyticsWrapper) SetCommand(command string) {
	a.next.SetCommand(command)
}

func (a *analyticsWrapper) SetOperatingSystem(os string) {
	a.next.SetOperatingSystem(os)
}

func (a *analyticsWrapper) AddError(err error) {
	a.next.AddError(err)
}

func (a *analyticsWrapper) AddHeader(headerFunc func() http.Header) {
	a.next.AddHeader(headerFunc)
}

func (a *analyticsWrapper) SetClient(clientFunc func() *http.Client) {
	a.next.SetClient(clientFunc)
}

func (a *analyticsWrapper) IsCiEnvironment() bool {
	return a.next.IsCiEnvironment()
}

func (a *analyticsWrapper) GetRequest() (*http.Request, error) {
	return a.next.GetRequest()
}

func (a *analyticsWrapper) Send() (*http.Response, error) {
	return a.next.Send()
}

func (a *analyticsWrapper) GetInstrumentation() analytics.InstrumentationCollector {
	return a.next.GetInstrumentation()
}

func (a *analyticsWrapper) AddExtension(key string, value interface{}) error {
	hasPrefix := strings.HasPrefix(key, fmt.Sprintf("%s:", a.prefix))
	if len(a.prefix) > 0 && !hasPrefix {
		key = fmt.Sprintf("%s:%s", a.prefix, key)
	}

	return a.next.AddExtension(key, value)
}
