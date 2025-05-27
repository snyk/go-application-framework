# testapi-example script

This is a developer script that loads a dependency graph, runs a Snyk test on it, and displays the test findings.

## Intent

This script demonstrates usage of the unified Test API client in /internal/api/testapi. It also serves as a basic test of the API by executing a single happy path.

## Directory Contents

This directory contains:

- `README.md`: this file.
- `main.go`: app showing usage of testapi when passed a DepGraph filename.
- `cli.sh`: script to run `snyk depgraph --json --file=<package manifest>`, format its output for the test API, and run it through `main.go`.

## Usage

### 1. Environment

- Set the following environment variables:

```bash
export SNYK_API=https://api.snyk.io         # Base URL for the API
export SNYK_CFG_ORG=<Snyk Org UUID>         # Snyk Org ID
export SNYK_TOKEN=<Snyk API token>          # Snyk Token with necessary permissions to perform tests within that org
```

Notes:
* SNYK_CFG_ORG - Snyk organization UUID. Get this from "Org settings" in the Snyk UI.
* SNYK_TOKEN - Snyk API token for a service account in the Org above. This can be created from the Org settings page in the Snyk UI. Contact an administrator if you do not have permissions to create Service Accounts.

### 2. Run the Script

This requires that you have a Snyk CLI installed -- see [public docs](https://docs.snyk.io/snyk-cli) on setting that up.

```
./scripts/testapi-example/cli.sh <path to package manifest> [additional cli options]
```

This script will extract a dep-graph using the Snyk CLI and test it with the Unified Test API.

`<path to package manifest>` can be any package manifest file that Snyk supports with `snyk test --file=<filename>`: `package.json`, `package-lock.json`, `pom.xml`, `go.mod`, etc.

The script uses `snyk depgraph --json --file=<filename> [additional options]` to extract a depgraph for uploading, so you can try running that directly if you have trouble getting a depgraph. See cli.sh for how to reformat the depgraph before passing to the test API.

## Expected output

- A successful run prints "test complete" with the number of findings.
