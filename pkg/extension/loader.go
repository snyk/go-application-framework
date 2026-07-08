package extension

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"sync"

	hclog "github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/configuration"
	extensionpb "github.com/snyk/go-application-framework/pkg/extension/proto"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// ConfigurationKeyPaths is the configuration key holding the list of extension
// binary paths to load. A CLI typically binds a repeatable --plugin-path flag
// and/or the SNYK_INTERNAL_EXTENSION_PATHS environment variable to this key so
// extensions can be loaded for local development without rebuilding the CLI.
const ConfigurationKeyPaths = "internal_extension_paths"

// ConfigurationKeyAllowOverride is the configuration key that, when set to true,
// permits a dynamically loaded extension to replace a workflow that is already
// registered (a bundled extension, or one from an earlier-loaded binary). It is
// false by default: bundled extensions take precedence and a colliding dynamic
// workflow is skipped, so dropping a binary on the plugin path can never
// silently shadow built-in behaviour.
const ConfigurationKeyAllowOverride = "internal_extension_allow_override"

// dialer launches (or connects to) the extension binary at path and returns a
// connection plus a cleanup func that terminates it. It is a field on Loader so
// tests can inject an in-memory connection instead of spawning a process.
type dialer func(ctx context.Context, path string) (conn pluginConn, cleanup func(), err error)

// Loader discovers out-of-process extensions and registers the workflows they
// provide with a workflow.Engine. Its Init method satisfies
// workflow.ExtensionInit, so it plugs into the engine exactly like a built-in
// extension initializer.
type Loader struct {
	paths         []string
	dialer        dialer
	logger        *zerolog.Logger
	allowOverride bool

	mu       sync.Mutex
	cleanups []func()
}

// LoaderOption configures a Loader.
type LoaderOption func(*Loader)

// WithPaths sets the extension binary paths to load. Each path is an explicit,
// operator-supplied executable; the Loader never scans arbitrary directories on
// its own.
func WithPaths(paths ...string) LoaderOption {
	return func(l *Loader) {
		l.paths = append(l.paths, paths...)
	}
}

// WithLogger sets the logger used for diagnostics.
func WithLogger(logger *zerolog.Logger) LoaderOption {
	return func(l *Loader) {
		l.logger = logger
	}
}

// WithAllowOverride controls whether a dynamically loaded extension may replace
// an already-registered workflow. Default false: colliding workflows are
// skipped so bundled extensions win.
func WithAllowOverride(allow bool) LoaderOption {
	return func(l *Loader) {
		l.allowOverride = allow
	}
}

// withDialer overrides the process-launching dialer. Used by tests.
func withDialer(d dialer) LoaderOption {
	return func(l *Loader) {
		l.dialer = d
	}
}

// NewLoader builds a Loader. By default it launches extensions as gRPC
// subprocesses via hashicorp/go-plugin.
func NewLoader(opts ...LoaderOption) *Loader {
	nop := zerolog.Nop()
	l := &Loader{logger: &nop}
	for _, opt := range opts {
		opt(l)
	}
	if l.dialer == nil {
		l.dialer = grpcDialer(l.logger)
	}
	return l
}

// Init loads every configured extension and registers its workflows with the
// engine. It satisfies workflow.ExtensionInit.
//
// A failing extension (cannot launch, handshake mismatch, discovery error) is
// logged and skipped rather than aborting engine initialization: a broken or
// incompatible third-party extension must never prevent the CLI from starting.
func (l *Loader) Init(engine workflow.Engine) error {
	for _, path := range l.paths {
		if err := l.loadOne(engine, path); err != nil {
			l.logger.Warn().Err(err).Str("path", path).Msg("skipping extension that failed to load")
		}
	}
	return nil
}

func (l *Loader) loadOne(engine workflow.Engine, path string) error {
	conn, cleanup, err := l.dialer(context.Background(), path)
	if err != nil {
		return fmt.Errorf("launching extension: %w", err)
	}
	l.mu.Lock()
	l.cleanups = append(l.cleanups, cleanup)
	l.mu.Unlock()

	specs, err := conn.Discover(context.Background())
	if err != nil {
		return fmt.Errorf("discovering workflows: %w", err)
	}

	for _, spec := range specs {
		if err := l.registerWorkflow(engine, conn, spec); err != nil {
			l.logger.Warn().Err(err).Str("identifier", spec.GetIdentifier()).Msg("skipping extension workflow")
			continue
		}
		l.logger.Debug().Str("identifier", spec.GetIdentifier()).Str("path", path).Msg("registered extension workflow")
	}
	return nil
}

func (l *Loader) registerWorkflow(engine workflow.Engine, conn pluginConn, spec *extensionpb.WorkflowSpec) error {
	id, err := url.Parse(spec.GetIdentifier())
	if err != nil {
		return fmt.Errorf("parsing identifier %q: %w", spec.GetIdentifier(), err)
	}

	// By default a dynamic extension must not shadow an already-registered
	// workflow (a bundled extension, or one from an earlier-loaded binary).
	if _, exists := engine.GetWorkflow(id); exists && !l.allowOverride {
		l.logger.Warn().
			Str("identifier", spec.GetIdentifier()).
			Msgf("extension workflow skipped: identifier already registered (set %s=true to override)", ConfigurationKeyAllowOverride)
		return nil
	}

	flagset := specsToFlagSet(id.Host, spec.GetFlags())
	configOptions := workflow.ConfigurationOptionsFromFlagset(flagset)

	entry, err := engine.Register(id, configOptions, l.makeProxy(conn, spec))
	if err != nil {
		return err
	}
	entry.SetVisibility(spec.GetVisible())
	return nil
}

// makeProxy builds the in-process workflow.Callback that forwards an invocation
// to the out-of-process extension. The only configuration values exported to
// the extension are the keys it declared via FlagSpec. For the duration of the
// call it stands up a loopback auth proxy (option C) so the extension can reach
// the host's authenticated network access without ever holding credentials.
func (l *Loader) makeProxy(conn pluginConn, spec *extensionpb.WorkflowSpec) workflow.Callback {
	return func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		config := invocation.GetConfiguration()

		req := executeRequest{
			identifier: spec.GetIdentifier(),
			config:     make(map[string]string, len(spec.GetFlags())),
			invocation: invocation,
		}
		for _, flag := range spec.GetFlags() {
			req.config[flag.GetName()] = config.GetString(flag.GetName())
		}

		// Bridge the host's authenticated network access for this invocation.
		if proxy, cleanup := l.startAuthProxy(invocation); proxy != nil {
			defer cleanup()
			req.networkProxyURL = proxy.baseURL
			req.networkProxyToken = proxy.secret
		}

		var err error
		if req.input, err = dataSliceToMsgs(input); err != nil {
			return nil, fmt.Errorf("serializing input for %q: %w", spec.GetIdentifier(), err)
		}

		outMsgs, err := conn.Execute(invocation.Context(), req)
		if err != nil {
			return nil, fmt.Errorf("executing extension workflow %q: %w", spec.GetIdentifier(), err)
		}

		return msgsToDataSlice(outMsgs, config)
	}
}

// startAuthProxy launches the loopback auth proxy backed by the invocation's
// network access. It returns (nil, noop) when network access is unavailable so
// invocation still proceeds without the network bridge.
func (l *Loader) startAuthProxy(invocation workflow.InvocationContext) (*authProxy, func()) {
	noop := func() {}

	network := invocation.GetNetworkAccess()
	if network == nil {
		return nil, noop
	}
	upstream := invocation.GetConfiguration().GetString(configuration.API_URL)
	if upstream == "" {
		return nil, noop
	}

	proxy, err := newAuthProxy(upstream, network.GetRoundTripper(), l.logger)
	if err != nil {
		l.logger.Warn().Err(err).Msg("extension network access disabled: failed to start auth proxy")
		return nil, noop
	}
	return proxy, func() { _ = proxy.stop() }
}

// Close terminates every extension process the Loader launched. Call it during
// CLI shutdown.
func (l *Loader) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, cleanup := range l.cleanups {
		cleanup()
	}
	l.cleanups = nil
}

// grpcDialer is the production dialer: it launches the extension binary and
// connects to it over gRPC via hashicorp/go-plugin.
func grpcDialer(logger *zerolog.Logger) dialer {
	return func(_ context.Context, path string) (pluginConn, func(), error) {
		client := plugin.NewClient(&plugin.ClientConfig{
			HandshakeConfig:  handshake,
			Plugins:          pluginMap(nil),
			Cmd:              exec.Command(path),
			AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
			Logger: hclog.New(&hclog.LoggerOptions{
				Name:   "extension",
				Output: io.Discard,
			}),
		})

		rpcClient, err := client.Client()
		if err != nil {
			client.Kill()
			return nil, nil, err
		}

		raw, err := rpcClient.Dispense(pluginName)
		if err != nil {
			client.Kill()
			return nil, nil, err
		}

		conn, ok := raw.(pluginConn)
		if !ok {
			client.Kill()
			return nil, nil, fmt.Errorf("extension %q does not implement the expected gRPC contract", path)
		}

		return conn, client.Kill, nil
	}
}
