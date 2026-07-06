// Package cache implements a live check that verifies the CLI cache directory
// is available and writable.
package cache

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/diagnosis"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// CacheStatus is the outcome of the cache directory check.
type CacheStatus struct {
	OK           bool
	Path         string
	ErrorMessage string
}

// Check verifies that the configured cache directory exists and is writable by
// creating (and immediately removing) a temporary file inside it.
func Check(invocationCtx workflow.InvocationContext) CacheStatus {
	cachePath := invocationCtx.GetConfiguration().GetString(configuration.CACHE_PATH)
	if cachePath == "" {
		return CacheStatus{ErrorMessage: "cache path is not configured"}
	}

	info, err := os.Stat(cachePath)
	if err != nil {
		return CacheStatus{
			Path:         cachePath,
			ErrorMessage: fmt.Sprintf("cache directory does not exist: %s", cachePath),
		}
	}
	if !info.IsDir() {
		return CacheStatus{
			Path:         cachePath,
			ErrorMessage: fmt.Sprintf("cache path is not a directory: %s", cachePath),
		}
	}

	// Probe writability by creating and removing a temp file.
	probe := filepath.Join(cachePath, ".snyk-doctor-probe")
	f, err := os.Create(probe)
	if err != nil {
		return CacheStatus{
			Path:         cachePath,
			ErrorMessage: fmt.Sprintf("cache directory is not writable: %s", cachePath),
		}
	}
	_ = f.Close()
	_ = os.Remove(probe)

	return CacheStatus{OK: true, Path: cachePath}
}

// Findings maps the cache status into the generic Finding contract.
func (c CacheStatus) Findings() []diagnosis.Finding {
	if c.OK {
		return []diagnosis.Finding{{
			Producer: diagnosis.ProducerEnvironment,
			Kind:     diagnosis.KindCacheOK,
			Severity: diagnosis.SeverityInfo,
			Message:  "Cache directory is available and writable",
			Fields:   map[string]string{"path": c.Path},
		}}
	}
	return []diagnosis.Finding{{
		Producer: diagnosis.ProducerEnvironment,
		Kind:     diagnosis.KindCacheFailure,
		Severity: diagnosis.SeverityWarning,
		Title:    "Cache directory issue",
		Message:  c.ErrorMessage,
		Fields:   map[string]string{"path": c.Path},
	}}
}
