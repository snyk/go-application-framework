### Description

_Provide description of this PR and changes._

### Checklist

- [ ] Tests added and all succeed (`make test`)
- [ ] Regenerated mocks, etc. (`make generate`)
- [ ] Linted (`make lint`)
- [ ] Test your changes work for the CLI
  1. Clone / pull the latest [CLI](https://github.com/snyk/cli) main.
  2. Run `go get github.com/snyk/go-application-framework@YOUR_LATEST_GAF_COMMIT` in the `cliv2` directory.
      - Tip: for local testing, you can uncomment the line near the bottom of the CLI's [`go.mod`](https://github.com/snyk/cli/blob/main/cliv2/go.mod) to point to your local GAF code.
  3. Run `go mod tidy` in the `cliv2` directory.
  4. Run the CLI tests and do any required manual testing.
  5. Open a PR in the CLI repo **now** with the `go.mod` and `go.sum` changes.
  - Once this PR is merged, repeat these steps, but pointing to the latest GAF commit on main and update your CLI PR.
