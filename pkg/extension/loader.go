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

	extensionpb "github.com/snyk/go-application-framework/pkg/extension/proto"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// ConfigurationKeyPaths is the configuration key holding the list of extension
// binary paths to load. A CLI typically binds a repeatable --plugin-path flag
// and/or the SNYK_INTERNAL_EXTENSION_PATHS environment variable to this key so
// extensions can be loaded for local development without rebuilding the CLI.
const ConfigurationKeyPaths = "internal_extension_paths"

// dialer launches (or connects to) the extension binary at path and returns a
// connection plus a cleanup func that terminates it. It is a field on Loader so
// tests can inject an in-memory connection instead of spawning a process.
type dialer func(ctx context.Context, path string) (conn pluginConn, cleanup func(), err error)

// Loader discovers out-of-process extensions and registers the workflows they
// provide with a workflow.Engine. Its Init method satisfies
// workflow.ExtensionInit, so it plugs into the engine exactly like a built-in
// extension initializer.
type Loader struct {
	paths  []string
	dialer dialer
	logger *zerolog.Logger

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
// the extension are the keys it declared via FlagSpec.
func (l *Loader) makeProxy(conn pluginConn, spec *extensionpb.WorkflowSpec) workflow.Callback {
	return func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		config := invocation.GetConfiguration()

		snapshot := make(map[string]string, len(spec.GetFlags()))
		for _, flag := range spec.GetFlags() {
			snapshot[flag.GetName()] = config.GetString(flag.GetName())
		}

		inMsgs, err := dataSliceToMsgs(input)
		if err != nil {
			return nil, fmt.Errorf("serializing input for %q: %w", spec.GetIdentifier(), err)
		}

		outMsgs, err := conn.Execute(invocation.Context(), spec.GetIdentifier(), snapshot, inMsgs)
		if err != nil {
			return nil, fmt.Errorf("executing extension workflow %q: %w", spec.GetIdentifier(), err)
		}

		return msgsToDataSlice(outMsgs, config)
	}
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
			HandshakeConfig:  Handshake,
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
