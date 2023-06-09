package workflow

import (
	"log"
	"net/url"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/spf13/pflag"
)

// A WorkflowRegisterer is a Workflow that has been extended with an Entrypoint method that defines
// the Workflow's action.
type WorkflowRegisterer interface {
	Identifier() *url.URL
	GetName() string
	GetFlags() Flags
	// IsVisible defines whether this workflow should be visible to users or not.
	IsVisible() bool
	Logger(InvocationContext) *log.Logger

	Entrypoint(invocation InvocationContext, input []Data) ([]Data, error)
}

// Register a given Workflow with the engine.
func Register(w WorkflowRegisterer, e Engine) error {
	fs := pflag.NewFlagSet(w.GetName(), pflag.ExitOnError)
	w.GetFlags().AddToFlagSet(fs)

	entry, err := e.Register(w.Identifier(), ConfigurationOptionsFromFlagset(fs), w.Entrypoint)
	if err != nil {
		return err
	}

	entry.SetVisibility(w.IsVisible())
	return nil
}

type Workflow struct {
	// Name is the name of the workflow. It also defines the command where this workflow will be
	// made available. For example, the name "x y" would make the workflow available at `snyk x y`.
	Name     string
	TypeName string
	// Visible defines whether this workflow should be visible to users or not.
	Visible bool
	// Flags for this workflow.
	Flags Flagger
}

func (w *Workflow) GetName() string            { return w.Name }
func (w *Workflow) GetFlags() Flags            { return w.Flags.GetFlags() }
func (w *Workflow) IsVisible() bool            { return w.Visible }
func (w *Workflow) Identifier() Identifier     { return NewWorkflowIdentifier(w.Name) }
func (w *Workflow) TypeIdentifier() Identifier { return NewTypeIdentifier(w.Identifier(), w.TypeName) }

// Logger returns a log.Logger that is prefixed with the workflow name for identification.
func (w *Workflow) Logger(ictx InvocationContext) *log.Logger {
	l := ictx.GetLogger()
	l.SetPrefix(w.Name + " workflow: ")
	return l
}

// Flagger returns a list of flags. The `Flags` type itself implements the Flagger interface as
// well. However, for easier access of specific flags, we recommend creating an intermediate type to
// hold your flags and implementing the Flagger interface yourself, e.g.:
//
//	type MyFlags struct {
//	    One Flag[bool]
//	}
//
//	func (m MyFlags) GetFlags() Flags {
//	  return Flags{m.One}
//	 }
type Flagger interface {
	GetFlags() Flags
}

// Flags is a list of Flags, and because we can't mix generic types (e.g. flag[string] and
// flag[bool]) in a single flag[T] slice, we need to use an interface instead.
// It implements the Flagger interface, so can be used to specify a simple list of flags.
//
//	f := Flags{
//	  Flag[bool]{...},
//	}
type Flags []interface {
	// AddToFlagSet adds a flag to the given flagset, registering the helptext and default values.
	AddToFlagSet(*pflag.FlagSet)
	// AsArgument returns the given flag plus a potential value extracted from the configuration.
	// For example, if there is a string flag "x", and the configuration has a value "y" set,
	// AsArgument would return "--x=y".
	// If the value is not set in the config, ok will be false to indicate the flag is not set.
	AsArgument(configuration.Configuration) (arg string, ok bool)
}

// https://preview.redd.it/bekphnqftcb41.jpg?auto=webp&s=26c9684c7326870bfa6680be462341be38bb0635
func (f Flags) GetFlags() Flags { return f }

// AddToFlagSet adds all flags to the given flag set.
func (f Flags) AddToFlagSet(fs *pflag.FlagSet) {
	for _, flag := range f {
		flag.AddToFlagSet(fs)
	}
}

// Flag is a generic flag type.
type Flag[T string | bool] struct {
	// Name is the name of the flag.
	Name string
	// Shorthand of the flag, optional.
	Shorthand string
	// Usage text for this flag.
	Usage string
	// DefaultValue of this flag.
	DefaultValue T
}

func (f Flag[T]) AddToFlagSet(fs *pflag.FlagSet) {
	// The "any().(type)" statements are a workaround for https://github.com/golang/go/issues/49206,
	// which once implemented could be removed.
	switch any(f.DefaultValue).(type) {
	case string:
		if f.Shorthand != "" {
			fs.StringP(f.Name, f.Shorthand, any(f.DefaultValue).(string), f.Usage)
		} else {
			fs.String(f.Name, any(f.DefaultValue).(string), f.Usage)
		}
	case bool:
		if f.Shorthand != "" {
			fs.BoolP(f.Name, f.Shorthand, any(f.DefaultValue).(bool), f.Usage)
		} else {
			fs.Bool(f.Name, any(f.DefaultValue).(bool), f.Usage)
		}
	}
}

// AsArgument returns the flag including it's value as rendered on a command line. ok will be true
// if the flag is being set, and false otherwise. For boolean values, it treats the flag as a simple
// "switch" and will return ("", false) if the flag's value is "false" (instead of returning
// something like `-x=false`).
func (f Flag[T]) AsArgument(c configuration.Configuration) (arg string, ok bool) {
	val := f.Value(c)
	// Workaround for https://github.com/golang/go/issues/49206
	switch any(f.DefaultValue).(type) {
	case string:
		if s := any(val).(string); s != "" {
			return "--" + f.Name + "=" + s, true
		}

	case bool:
		if any(val).(bool) {
			return "--" + f.Name, true
		}
	}

	return "", false
}

// Value returns the value for this flag as stored in the configuration. If the flag is not set
// (e.g. is the zero-value for the respective type), the flag's DefaultValue will be returned.
func (f Flag[T]) Value(c configuration.Configuration) (val T) {
	// Workaround for https://github.com/golang/go/issues/49206
	switch any(f.DefaultValue).(type) {
	case string:
		if s := c.GetString(f.Name); s != "" {
			return any(s).(T)
		}

		if any(f.DefaultValue).(string) != "" {
			return f.DefaultValue
		}

	case bool:
		return any(c.GetBool(f.Name)).(T)
	}

	// return the zero value for the given type.
	return val
}
