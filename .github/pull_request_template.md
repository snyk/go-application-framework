### Description

_Provide description of this PR and changes._

### Checklist

- [ ] Tests added and all succeed (`make test`)
- [ ] Regenerated mocks, etc. (`make generate`)
- [ ] Linted (`make lint`)
- [ ] Test your changes work for the [CLI](https://github.com/snyk/cli)
  1. Uncomment the line near the bottom of [go.mod](https://github.com/snyk/cli/blob/main/cliv2/go.mod) to point to your local GAF code.
  2. Run `go mod tidy` in the `cliv2` directory.
  3. Run the CLI tests and do any required manual testing.
  - Once this PR is merged, make a PR in the [CLI](https://github.com/snyk/cli/pulls) repo to increment the version of GAF in the [go.mod](https://github.com/snyk/cli/blob/main/cliv2/go.mod).
