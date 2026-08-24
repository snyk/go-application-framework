#!/usr/bin/env bash
# Source in the tab where you run snyk-billing through mitmweb.
# Prerequisite (other tab): mitmweb --listen-port 8080 --ssl-insecure

unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy
unset ALL_PROXY all_proxy
unset NO_PROXY no_proxy

export MITM_PORT="${MITM_PORT:-8080}"
export HTTP_PROXY="http://127.0.0.1:${MITM_PORT}"
export HTTPS_PROXY="http://127.0.0.1:${MITM_PORT}"
export NO_PROXY=localhost,127.0.0.1,::1

export NODE_EXTRA_CA_CERTS="${NODE_EXTRA_CA_CERTS:-$HOME/.mitmproxy/mitmproxy-ca-cert.pem}"
export SNYK_BILLING_BIN="${SNYK_BILLING_BIN:-$HOME/bin/snyk-billing}"
export SNYK_FORCE_LEGACY_CLI=true

if [[ ! -f "$NODE_EXTRA_CA_CERTS" ]]; then
  echo "WARN: $NODE_EXTRA_CA_CERTS missing — run mitmweb once, then Ctrl+C" >&2
fi

echo "mitm env ready: HTTPS_PROXY=$HTTPS_PROXY SNYK_BILLING_BIN=$SNYK_BILLING_BIN"
