# Snyk Connectivity Check Extension

A Go-based extension for the Snyk CLI that performs comprehensive network connectivity diagnostics. This tool helps troubleshoot connectivity issues between your environment and Snyk's services.

## Features

- **Comprehensive Endpoint Testing**: Tests connectivity to all Snyk API endpoints and services
- **Proxy Detection & Validation**: Automatically detects and validates proxy configurations
- **Organization Listing**: Displays your Snyk organizations when authenticated (with default organization highlighted)
- **Multiple Output Formats**: Human-readable (with color support) and JSON formats
- **Actionable Diagnostics**: Provides specific recommendations based on connectivity issues
- **Integration Ready**: Built as a workflow extension for the Snyk CLI using go-application-framework

### Environment Variables

The tool respects standard proxy environment variables:
- `HTTPS_PROXY` / `https_proxy`
- `HTTP_PROXY` / `http_proxy`
- `NO_PROXY` / `no_proxy`

For custom certificates:
- `NODE_EXTRA_CA_CERTS` - Path to additional CA certificates bundle

### Authentication

The tool uses Snyk authentication from the go-application-framework configuration:
- API tokens via `snyk auth`
- OAuth tokens
- Bearer tokens

When authenticated, the tool will display your organizations with their IDs. The default organization is highlighted with a `[DEFAULT]` marker.

## Output Examples

### Human-Readable Output

```
Checking for proxy configuration...

Environment variables:
  HTTPS_PROXY: (not set)
  https_proxy: (not set)
  HTTP_PROXY:  (not set)
  http_proxy:  (not set)
  NO_PROXY:    (not set)
  no_proxy:    (not set)

ℹ No proxy detected - Testing direct connection...

Testing connectivity to Snyk endpoints...

Host                          Result
----------------------------------------------------------------------
api.snyk.io                   OK (HTTP 204)
app.snyk.io                   OK (HTTP 200)
api.eu.snyk.io                OK (HTTP 204)
app.eu.snyk.io                OK (HTTP 200)
api.us.snyk.io                OK (HTTP 204)
app.us.snyk.io                OK (HTTP 200)
api.au.snyk.io                OK (HTTP 204)
app.au.snyk.io                OK (HTTP 200)
api.snykgov.io                OK (HTTP 204)
app.snykgov.io                OK (HTTP 200)
deeproxy.snyk.io/filters      OK (HTTP 200)
downloads.snyk.io:443/cli/wasm/bundle.tar.gz OK (HTTP 200)
learn.snyk.io                 OK (HTTP 200)
static.snyk.io/cli/latest/version OK (HTTP 200)
snyk.io                       OK (HTTP 200)
sentry.io                     REACHABLE (HTTP 405)

--- Actionable TODOs ---
All checks passed. Your network configuration appears to be compatible with Snyk CLI.

ℹ Certificate Configuration:
If you need to trust custom certificates, set NODE_EXTRA_CA_CERTS environment variable
pointing to your CA bundle file.

--- Snyk Token and Organizations ---
✓ Authentication token is configured

Found 2 organizations:
Organization ID                         Organization Name      Default
----------------------------------------------------------------------
a1b2c3d4-e5f6-7890-abcd-ef1234567890  My Organization       Yes
b2c3d4e5-f6a7-8901-bcde-f23456789012  Another Org
```

### JSON Output

```bash
snyk connectivity-check --json
```

```json
{
  "proxyConfig": {
    "detected": false,
    "url": "",
    "variable": ""
  },
  "hostResults": [
    {
      "host": "api.snyk.io",
      "displayHost": "api.snyk.io",
      "url": "https://api.snyk.io",
      "statusCode": 204,
      "status": 0,
      "responseTime": 150000000
    }
  ],
  "todos": [],
  "organizations": [
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "name": "My Organization",
      "isDefault": true
    },
    {
      "id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
      "name": "Another Org",
      "isDefault": false
    }
  ],
  "tokenPresent": true,
  "startTime": "2024-01-15T10:00:00Z",
  "endTime": "2024-01-15T10:00:05Z"
}
```

## Troubleshooting

### Common Issues

#### Proxy Authentication Required
If you see "PROXY AUTH REQUIRED", the tool has detected your proxy but needs authentication:
- For NTLM/Negotiate proxies: The Snyk CLI supports these authentication methods
- For other proxy auth types: Configure proxy credentials in your proxy URL

#### DNS Errors
If you see "DNS_ERROR" for multiple hosts:
- Check your DNS configuration
- Verify you can resolve external domains
- Check if you need to use a corporate DNS server

#### TLS/SSL Errors
If you see "TLS/SSL_ERROR":
- You may need to configure custom CA certificates
- Set `NODE_EXTRA_CA_CERTS` to point to your CA bundle
- Ensure your proxy (if any) isn't intercepting SSL

#### No Organizations Displayed
If authenticated but no organizations shown:
- Verify your token has the correct permissions
- Check if you belong to any organizations
- Try re-authenticating with `snyk auth`

### Status Meanings

- **OK**: Full connectivity verified
- **REACHABLE**: Host is reachable but returned unexpected status
- **BLOCKED**: Connection refused or blocked
- **DNS_ERROR**: Cannot resolve hostname
- **TLS/SSL_ERROR**: Certificate or TLS handshake issues
- **TIMEOUT**: Connection timed out
- **PROXY AUTH REQUIRED (SUPPORTED)**: Proxy needs auth, type is supported
- **PROXY AUTH REQUIRED (UNSUPPORTED)**: Proxy needs auth, type not supported