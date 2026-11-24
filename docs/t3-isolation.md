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
