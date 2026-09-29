# Machine identity in the framework

Status: draft for review. Ticket IDE-2600.

## What this adds

Today the framework knows two ways to authenticate a request to the Snyk API: an OAuth token for a
person, or an API token or PAT. Both are user identities. This change adds a third authenticator,
the machine identity, so that a workstation, a CI runner or a daemon can call the API as itself
after it has joined the Snyk identity plane.

Machine identity is available to every workflow through the engine. An extension asks the network
access it already has for an http client and picks which identity that client presents. Nothing in
the framework holds a private key; the framework only asks the key's owner for a certificate or a
signed proof.

## The authenticator

The machine identity authenticator is an ordinary auth.Authenticator. Authenticate reports whether a
machine identity is present, AddAuthenticationHeader attaches a DPoP proof bound to the request
method and URL, and IsSupported answers true once a source reports a machine identifier. Joining a
machine is not the framework's job; that stays in the host's join workflow.

The authenticator is backed by a small interface the host supplies:

```go
type MachineIdentitySource interface {
	MachineID() string
	ClientCertificate() (*tls.Certificate, error)
	SignProof(method, url string) (string, error)
}
```

The certificate is presented during the TLS handshake through the transport's client certificate
callback, so a renewed certificate is picked up on the next connection. The proof travels in the
DPoP header as a compact JWS. Both halves are sent together and the identity plane accepts either,
so one mechanism always works while the other is rolled out.

## Selecting the identity

A configuration key, snyk identity mode, selects the default identity for the whole network stack.
Its values are user and machine, and the default is user, so nothing changes for existing hosts.
The key is read by auth.CreateAuthenticator, which now returns the machine authenticator when the
mode is machine and a source has been registered.

Machine mode never falls back to user credentials. When the mode is machine and no source is
present the authenticator reports that it is not supported and no user token is attached. That is
deliberate: a workload that was configured to act as a machine must not quietly start acting as the
person who installed it.

## Registering a source

The host owns the key material and registers it once on the network access:

```go
engine.GetNetworkAccess().SetMachineIdentitySource(daemon.IdentitySource())
```

Anything that implements the three methods above is a valid source: the daemon's identity
directory, a keychain entry or a TPM. Clone copies the source reference, so every invocation
context sees the same identity.

## Choosing per call

Some extensions need both identities in one process: report a finding as the machine, then read an
organisation setting as the user. For that the network access has a client per identity mode, and
the choice is made at the call site:

```go
package myext

import (
	"fmt"
	"net/http"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func heartbeat(ic workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	cfg := ic.GetConfiguration()
	url := cfg.GetString("snyk_api") + "/hidden/self/heartbeat"

	// this request is signed by the machine, whatever the configured default is
	client := ic.GetNetworkAccess().GetHttpClientForIdentity(auth.IdentityModeMachine)
	req, err := http.NewRequestWithContext(ic.Context(), http.MethodPost, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	rsp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("heartbeat: %w", err)
	}
	defer rsp.Body.Close()

	// the next call can use the user again with GetHttpClient or
	// GetHttpClientForIdentity(auth.IdentityModeUser)
	return nil, nil
}
```

GetHttpClient keeps its current meaning: the identity the configuration selects. Existing
extensions and snyk-ls inherit machine identity as soon as a host sets the mode and registers a
source.

## Planned shared module for the join flow

The ambient canary daemon currently carries the identity flags (identity server, join token, join
method, tenant, source, audience and the per provider assertion sources) and the enrol, renew,
heartbeat and revoke loop inside its own daemon workflow. The CLI needs the same flags and the same
loop for a snyk machine join command, and defining them twice would let the two surfaces drift.

The proposal is one shared extension module that both the daemon binary and the CLI import. It
would own the flag set, the join workflow, the renewal loop and a MachineIdentitySource
implementation over the identity directory, and register the source on the engine's network access
in its Init. Two homes are possible:

1. pkg/local_workflows/identity in this repository, next to auth and whoami. Every host gets it for
   free, but the framework then depends on the join protocol and its release cadence.
2. A separate repository, cli-extension-identity, wired into cliv2 like every other extension and
   imported by the daemon. The framework stays protocol free; hosts add one require line.

Reviewers are asked to decide between these two. The authenticator, the mode key and the source
registration in this change do not depend on the answer.

## Decisions requested

1. Source registration: a setter on NetworkAccess as implemented, or a functional option on
   NewNetworkAccess and CreateAppEngineWithOptions.
2. Location of the shared join module: local workflow in this repository or a separate extension.
3. Whether the per call client is enough, or whether hosts also want a per workflow default in the
   registered configuration options.
