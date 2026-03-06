package connectivity

type envVarSpec struct {
	names []string
	set   func(*ProxyConfig, string, string)
}

var envVarSpecs = []envVarSpec{
	{
		names: []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"},
		set: func(config *ProxyConfig, variable string, value string) {
			config.Detected = true
			config.URL = value
			config.Variable = variable
		},
	},
	{
		names: []string{"NO_PROXY", "no_proxy"},
		set: func(config *ProxyConfig, _ string, value string) {
			config.NoProxy = value
		},
	},
	{
		names: []string{"NODE_EXTRA_CA_CERTS"},
		set: func(config *ProxyConfig, _ string, value string) {
			config.NodeExtraCACerts = value
		},
	},
	{
		names: []string{"KRB5_CONFIG"},
		set: func(config *ProxyConfig, _ string, value string) {
			config.KRB5Config = value
		},
	},
	{
		names: []string{"KRB5CCNAME"},
		set: func(config *ProxyConfig, _ string, value string) {
			config.KRB5CCName = value
		},
	},
}
