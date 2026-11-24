# T3 client isolation

Status: design and deployment requirements; not production-ready.

Expose a dedicated inference gateway, never the raw CPA port, to T3. Keep CPA loopback-only on a separate host. Allow only POST /v1/responses and explicitly reviewed ancillary routes; deny upgrades, tunnels, management, alternate API aliases and arbitrary forwarding. Use separate random client credentials stored as hashes, not CPA keys. Gateway authenticates before parsing and injects its own backend key. Strip untrusted headers and queries. Use TLS and network ACLs. Do not expose the CPA management key to T3.

## Required implementation

* Persist per-client request admission and token reservations transactionally before forwarding; fail closed on storage errors. Count retries as separate upstream attempts or disable them. Reserve a verified upper bound on upstream tokens, including hidden context and reasoning; if the provider cannot enforce such bounds, do not label the budget a hard token cap. Keep reservations on disconnect or missing usage. Reconcile only authoritative usage.
* Enforce per-client rate, concurrency, exact model allowlists and dedicated upstream provider routing. Disable model aliases, fallback and plugins that can bypass policy.
* Separate admin and read-only monitoring credentials; expose only sanitized client counters, no raw configuration or credentials. Support per-client revocation, absolute session expiration and global deny switch. Cancel in-flight work on revocation where supported; already consumed tokens cannot be undone.
* Record structured admission and completion metadata without prompts, headers or secrets. Pin deployment images and disable automatic updates. Isolate T3 from existing Codex credentials and credential stores, and restrict outbound network access; do not run on a shared trusted account.
* Verify upstream terms and supported authorization before enabling subscription-backed traffic. Use API credentials for testing.

## Acceptance tests

Reject unknown/revoked/expired keys, unauthorized model and route, encoded path variants, duplicate authorization headers, upgrades, request smuggling, management and alternate aliases. Race admission at quota and concurrency boundaries. Restart with spent budget; simulate storage failure, client disconnect, missing usage, upstream retry and kill switch. Confirm monitoring cannot mutate configuration or obtain secrets. Verify actual T3 HTTP streaming compatibility and that no direct Codex credentials are available. Do not deploy until tests pass.

## Gateway deployment (staging only)

Build from a reviewed commit using `go build -trimpath -o t3-gateway ./cmd/t3-gateway` and run `go vet ./cmd/t3-gateway && go test -race ./cmd/t3-gateway` before installation. Install the binary root-owned at /usr/local/bin/t3-gateway. Create a dedicated system user/group t3-gateway with no interactive shell. Install the service in /etc/systemd/system and configuration in /etc/t3-gateway (root-owned directory 0750, gateway group; policy 0640; backend.env root-only 0600). StateDirectory provisions persistent private state. Never delete or recreate state as a routine restart. Back up the DB using an offline copy with the service stopped. No updater is installed.

The example policy starts disabled. Generate separate random 32-byte secrets for inference and monitoring (openssl rand -hex 32), hash the exact strings with SHA-256, and supply only the digests in KeyHash and MonitorHash. Keep plaintext client secrets out of the repository. Each Clients entry requires ID, KeyHash, MonitorHash, Models, Expires (RFC3339 UTC), RequestsPerDay, RequestsPerMinute, Concurrent and MaxBodyBytes. Set positive MaxDailyInputBytes, MaxOutputTokens and MaxDailyRequestedOutputTokens to enable corresponding admission limits. Use atomic replacement of the policy file, not in-place edits. Never reuse a client ID for a different security principal. Disabled=true denies new traffic and cancels active contexts on the next policy check.

Set T3_GATEWAY_BACKEND_MODE explicitly. openai-api sends only to the official HTTPS API endpoint and needs an API key, not subscription OAuth. isolated-cpa sends only to localhost:8317 and needs a separate CPA inference key. It requires a dedicated CPA instance with one approved upstream provider/credential, separate auth storage, disabled plugins, no model aliases or fallback credentials, zero retry rounds and max-retry-credentials: 1. Verify effective runtime routing and retry behavior before deployment; the gateway does not attest CPA internals. Do not use an existing shared multiprovider CPA instance as the isolated backend. Restrict access to port 8317 and all management endpoints to trusted host principals; loopback alone is not isolation from other users on that host. Expose only port 8318 through a TLS reverse proxy with authenticated network ACLs, streaming enabled and buffering disabled. Do not expose an unrestricted Tailscale Serve or Funnel endpoint. Do not run T3 on this host.

After staging configuration review, systemctl daemon-reload and systemctl start t3-gateway. Enable at boot only after acceptance tests. No production deployment is authorized by the example files.

## Accounting limitations

Daily admitted input bytes and requested output tokens are not actual subscription quota. Reported usage is observed only from successful complete upstream JSON or SSE responses with valid totals; unknown or interrupted responses retain admission reservations. A crash can leave an admission record without a completion record; treat it as unresolved, not zero consumption. Reported totals are attributed to admission day UTC. Completion-write failure suspends admissions in the current process; restarting requires inspection of unresolved admissions. Audit storage is append-only by gateway code but not tamper-proof against host administrators, and needs capacity monitoring and a retention/export policy. No hard cap on actual provider billing or hidden context is claimed. The gateway does not yet provide a T3-native management monitoring API.

## Remaining gates

Provider isolation in CPA, upstream subscription authorization, T3 client configuration/credential isolation, actual streaming compatibility and successful CI remain unverified. Do not connect subscription credentials until these gates are satisfied.
