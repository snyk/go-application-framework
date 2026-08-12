package contributors

import (
	"os"
	"testing"
	"time"
)

// BenchmarkCollectContributors times collectContributors against a local git
// repository. Point it at a repo via CONTRIBUTOR_BENCH_REPO:
//
//	CONTRIBUTOR_BENCH_REPO=/path/to/repo go test ./internal/contributors/... \
//	  -run '^$' -bench BenchmarkCollectContributors -benchtime 5x
//
// The benchmark is skipped when the env var is unset, so it never runs as part
// of the normal test suite.
func BenchmarkCollectContributors(b *testing.B) {
	path := os.Getenv("CONTRIBUTOR_BENCH_REPO")
	if path == "" {
		b.Skip("set CONTRIBUTOR_BENCH_REPO to a git repository path to run this benchmark")
	}

	now := time.Now()

	for b.Loop() {
		if _, err := collectContributors(path, now); err != nil {
			b.Fatal(err)
		}
	}
}
