package workflow

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/snyk/go-application-framework/pkg/analytics"
)

const analyticsPrefixSeparator = "::"

func NewAnalyticsWrapper(a analytics.Analytics, prefix string) analytics.Analytics {
	return &analyticsWrapper{wrappedAnalytics: a, prefix: fmt.Sprintf("%s%s", prefix, analyticsPrefixSeparator)}
}

type analyticsWrapper struct {
	wrappedAnalytics analytics.Analytics
	prefix           string
}

func (a *analyticsWrapper) SetCmdArguments(args []string) {
	a.wrappedAnalytics.SetCmdArguments(args)
}

func (a *analyticsWrapper) SetOrg(org string) {
	a.wrappedAnalytics.SetOrg(org)
}

func (a *analyticsWrapper) SetVersion(version string) {
	a.wrappedAnalytics.SetVersion(version)
}

func (a *analyticsWrapper) SetApiUrl(apiUrl string) {
	a.wrappedAnalytics.SetApiUrl(apiUrl)
}

func (a *analyticsWrapper) SetIntegration(name string, version string) {
	a.wrappedAnalytics.SetIntegration(name, version)
}

func (a *analyticsWrapper) SetCommand(command string) {
	a.wrappedAnalytics.SetCommand(command)
}

func (a *analyticsWrapper) SetOperatingSystem(os string) {
	a.wrappedAnalytics.SetOperatingSystem(os)
}

func (a *analyticsWrapper) AddError(err error) {
	a.wrappedAnalytics.AddError(err)
}

func (a *analyticsWrapper) AddHeader(headerFunc func() http.Header) {
	a.wrappedAnalytics.AddHeader(headerFunc)
}

func (a *analyticsWrapper) SetClient(clientFunc func() *http.Client) {
	a.wrappedAnalytics.SetClient(clientFunc)
}

func (a *analyticsWrapper) IsCiEnvironment() bool {
	return a.wrappedAnalytics.IsCiEnvironment()
}

func (a *analyticsWrapper) GetRequest() (*http.Request, error) {
	return a.wrappedAnalytics.GetRequest()
}

func (a *analyticsWrapper) Send() (*http.Response, error) {
	return a.wrappedAnalytics.Send()
}

func (a *analyticsWrapper) GetInstrumentation() analytics.InstrumentationCollector {
	return a.wrappedAnalytics.GetInstrumentation()
}

func (a *analyticsWrapper) AddExtensionIntegerValue(key string, value int) {
	key = a.getPrefix(key)
	a.wrappedAnalytics.AddExtensionIntegerValue(key, value)
}

func (a *analyticsWrapper) AddExtensionStringValue(key string, value string) {
	key = a.getPrefix(key)
	a.wrappedAnalytics.AddExtensionStringValue(key, value)
}

func (a *analyticsWrapper) AddExtensionBoolValue(key string, value bool) {
	key = a.getPrefix(key)
	a.wrappedAnalytics.AddExtensionBoolValue(key, value)
}

func (a *analyticsWrapper) getPrefix(key string) string {
	hasPrefix := strings.HasPrefix(key, a.prefix)
	if len(a.prefix) > 0 && !hasPrefix {
		key = fmt.Sprintf("%s%s", a.prefix, key)
	}
	return key
}
