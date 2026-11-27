package presenters

import "testing"

// NewGitCheckout is exported for tests in the external presenters_test package.
func NewGitCheckout(t *testing.T) string {
	t.Helper()
	return newGitRepoWithOrigin(t, "https://github.com/acme/project.git")
}
