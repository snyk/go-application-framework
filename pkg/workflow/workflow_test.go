package workflow

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/require"
)

func TestWorkflowRegister(t *testing.T) {
	w := newNoOpWorkflow()
	config := configuration.New()
	e := NewWorkFlowEngine(config)
	require.NoError(t, Register(w, e))

	entry, ok := e.GetWorkflow(w.Identifier())
	require.True(t, ok)
	require.Equal(t, w.IsVisible(), entry.IsVisible())
	require.NoError(t, e.Init())

	config.Set(w.Flags().NoOpOutput.Name, "test-output")

	data, err := e.InvokeWithConfig(w.Identifier(), config)
	require.NoError(t, err)
	require.Equal(t, "test-output", data[0].GetPayload().(string))
}

func TestFlagWithNonZeroDefaultValue(t *testing.T) {
	f := Flag[string]{
		Name:         "hello",
		Shorthand:    "h",
		Usage:        "say hello",
		DefaultValue: "hi!",
	}

	config := configuration.New()

	arg, ok := f.AsArgument(config)
	require.True(t, ok)
	require.Equal(t, "--hello=hi!", arg)
	// if the DefaultValue is not the zero-value for a type, we expect that to be returned.
	require.Equal(t, "hi!", f.Value(config))

	config.Set(f.Name, "hallo!")
	require.Equal(t, f.Value(config), "hallo!")
	arg, ok = f.AsArgument(config)
	require.True(t, ok)
	require.Equal(t, arg, "--hello=hallo!")
}

func TestFlagWithZeroValue(t *testing.T) {
	f := Flag[string]{
		Name:         "hello",
		Usage:        "say hello",
		DefaultValue: "",
	}
	config := configuration.New()
	_, ok := f.AsArgument(config)
	require.False(t, ok)

	require.Equal(t, "", f.Value(config))

	config.Set(f.Name, "hallo!")
	require.Equal(t, f.Value(config), "hallo!")
	arg, ok := f.AsArgument(config)
	require.True(t, ok)
	require.Equal(t, arg, "--hello=hallo!")

	require.Equal(t, f.Value(config), "hallo!")
}

type noOpWorkflow struct{ *Workflow }
type noOpWorkflowFlags struct {
	NoOpOutput Flag[string]
}

func (n noOpWorkflowFlags) GetFlags() Flags {
	return Flags{n.NoOpOutput}
}

func (n noOpWorkflow) Flags() noOpWorkflowFlags {
	return n.Workflow.Flags.(noOpWorkflowFlags)
}

func newNoOpWorkflow() noOpWorkflow {
	return noOpWorkflow{&Workflow{
		Name:     "no-op",
		TypeName: "no-op",
		Visible:  true,
		Flags: noOpWorkflowFlags{
			NoOpOutput: Flag[string]{
				Name:         "no-op-output",
				DefaultValue: "",
			},
		},
	}}
}

func (n noOpWorkflow) Entrypoint(ictx InvocationContext, _ []Data) ([]Data, error) {
	output := n.Flags().NoOpOutput.Value(ictx.GetConfiguration())
	return []Data{
		NewData(n.TypeIdentifier(), "", output),
	}, nil
}
