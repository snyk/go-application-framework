package clibilling

import "github.com/snyk/go-application-framework/pkg/workflow"

// EnableIfConfigured registers contributor billing on the engine.
// Deprecated: use RegisterWithEngine from app engine bootstrap instead.
func EnableIfConfigured(engine workflow.Engine) workflow.Engine {
	RegisterWithEngine(engine)
	return engine
}
