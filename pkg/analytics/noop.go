package analytics

import "net/http"

var Noop Analytics = &noOpAnalytics{}

// noOpAnalytics is a no-op implementation of the Analytics interface.
// It is used when analytics are disabled. It does not raise any error, and only returns default values.
type noOpAnalytics struct{}

func (n *noOpAnalytics) SetCmdArguments(_ []string)         {}
func (n *noOpAnalytics) SetOrg(_ string)                    {}
func (n *noOpAnalytics) SetVersion(_ string)                {}
func (n *noOpAnalytics) SetApiUrl(_ string)                 {}
func (n *noOpAnalytics) SetIntegration(_ string, _ string)  {}
func (n *noOpAnalytics) SetCommand(_ string)                {}
func (n *noOpAnalytics) SetOperatingSystem(_ string)        {}
func (n *noOpAnalytics) AddError(_ error)                   {}
func (n *noOpAnalytics) AddHeader(_ func() http.Header)     {}
func (n *noOpAnalytics) SetClient(_ func() *http.Client)    {}
func (n *noOpAnalytics) IsCiEnvironment() bool              { return false }
func (n *noOpAnalytics) GetRequest() (*http.Request, error) { return nil, nil }
func (n *noOpAnalytics) Send() (*http.Response, error)      { return nil, nil }
func (n *noOpAnalytics) GetOutputData() *analyticsOutput    { return nil }
