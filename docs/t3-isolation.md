# T3 client isolation

Status: implementation and staging assets committed; build, real T3 compatibility, and production deployment not yet verified.

## Threat model

Assume T3 is compromised and can use or disclose any credential available to its process. Give it only a separately revocable gateway inference secret. Never expose the raw CPA listener, its management endpoints, upstream credentials, or a native Codex login to T3. A compromised client can still consume its authorized budget; the gateway bounds admission and provides independent monitoring, not proof of human intent.

The gateway listens on localhost:8318. Expose only this listener through a private TLS reverse proxy with streaming enabled, response buffering disabled, and restrictive network ACLs. Keep the CPA listener on localhost:8317 on the trusted proxy host. Do not run T3 on the proxy host.

## Build and test

Build from a reviewed commit with the Go version in go.mod:

```sh
go vet ./cmd/t3-gateway
go test -race -count=3 ./cmd/t3-gateway
go test -race -run TestT3 ./internal/config ./internal/api ./internal/runtime/executor
go build -trimpath -o t3-gateway ./cmd/t3-gateway
go build -trimpath -o CLIProxyAPI ./cmd/server
```

The security CI workflow runs these suites and builds both binaries. Do not interpret missing CI results as a passing build.

## Gateway deployment (staging only)

Install reviewed binaries root-owned under /usr/local/bin. Create a dedicated system user/group t3-gateway with no interactive shell. Install the gateway service under /etc/systemd/system and configuration under /etc/t3-gateway (root-owned directory 0750, gateway group; policy 0640; backend.env root-only 0600). StateDirectory provisions persistent private state. Never delete or recreate state as a routine restart. Back up the DB using an offline copy with the service stopped. No updater is installed.

The example policy starts disabled. Generate independent random 32-byte secrets for inference and monitoring (openssl rand -hex 32). Hash the exact printable secret strings with SHA-256, without a trailing newline. Supply only those digests in KeyHash and MonitorHash; keep plaintext secrets out of the repository. For example, a client policy has this shape:

```json
{
  "Disabled": true,
  "Clients": [{
    "ID": "t3-agent-staging",
    "KeyHash": "REPLACE_WITH_INFERENCE_SHA256",
    "MonitorHash": "REPLACE_WITH_MONITOR_SHA256",
    "Models": ["REPLACE_WITH_ALLOWED_API_MODEL"],
    "Expires": "REPLACE_WITH_RFC3339_UTC_EXPIRY",
    "RequestsPerDay": 100,
    "RequestsPerMinute": 5,
    "Concurrent": 1,
    "MaxBodyBytes": 1048576,
    "MaxDailyInputBytes": 10485760,
    "MaxOutputTokens": 8192,
    "MaxDailyRequestedOutputTokens": 200000,
    "MaxDailyReportedTokens": 300000,
    "RequireReportedUsage": true
  }]
}
```

These numbers are illustrative; select appropriate budgets before enabling. Production backend modes require positive input and output admission budgets and a minimum output cap of 16. Strict reported-usage mode requires concurrency 1. It denies the remainder of the UTC day when an admission is unresolved or usage is unknown. It is intentionally conservative. A reported output-cap violation also blocks new inference for that client on that UTC day. Change policy by atomic file replacement with preserved root ownership and 0640 permissions. Never reuse a client ID for a different security principal. Disabled=true denies new traffic and cancels active contexts on the next policy check (approximately 250 ms under normal conditions). Removing a client revokes its credential; key rotation also cancels in-flight contexts. The monitor key is separate, read-only and only sees that client's counters at GET /usage. T3 does not get that key or any CPA management key.

## Provider isolation

Set T3_GATEWAY_BACKEND_MODE explicitly.

* openai-api: directly uses the official HTTPS Responses API and an API project key, not a subscription login. This is useful for initial staging.
* isolated-cpa: sends only to localhost:8317. It requires the dedicated CPA process launched with CPA_T3_ISOLATED=1, not a shared multi-provider server. Install the provided t3-cpa.service, use its isolated configuration example, and create root-owned read-only empty auth storage /etc/t3-cpa/empty-auth accessible to the t3-cpa account. Use a distinct CPA ingress key and API project key. Do not copy existing OAuth files or enable management/plugins, alternate storage, model aliases, retries or fallback. Run this as a separate instance; the ordinary CPA management UI remains separate.

The isolated process validates its configuration at startup and ingress, inspects the live credential inventory, and rejects other HTTP paths. The gateway makes an authenticated readiness probe and requires the isolated backend marker. The Codex executor checks the actual selected API key, official endpoint, allowed model, and final translated output limit before sending requests. A dropped or increased cap fails closed. These controls are not an attestation of a hostile proxy host; trust the host, binary and root-owned configuration.

## T3 environments

Run each T3 environment under a dedicated OS account or separate VM without access to the user's ordinary Codex or OS credential store. Do this on the desktop too if using the native T3 app; a custom CODEX_HOME alone does not protect credentials from a compromised process running as the same user. Prefer accessing the remote server from a browser on your trusted desktop rather than giving a local native app access to your ordinary account. Do not forward an SSH agent, mount the Docker socket, grant sudo, or expose other privileged local services.

Use the provided t3-agent-isolation.conf.example as an opt-in systemd drop-in for an existing T3 server service; review all required network and workspace paths first. The exact gateway and operator IPs must be supplied. Verify the host supports systemd IP filtering; otherwise enforce equivalent isolation with a firewall/VM. If coding tasks require additional network access, allow specific destinations explicitly and never place trusted account credentials inside the T3 environment. Use a private hostname mapped to the gateway IP and a valid TLS certificate. Configure each remote independently.

Copy codex.config.example.toml to the fresh /var/lib/t3-agent/codex/config.toml, replacing the gateway URL and model. Do not run codex login or copy auth.json. In T3 Settings > Providers, select the intended environment, add a Codex instance, choose Configure manually, specify the pinned Codex binary and the dedicated CODEX_HOME, leave shadow home unset, and set T3_GATEWAY_CLIENT_KEY as its sensitive environment variable (or inject it via the root-owned service environment file). Disable managed ChatGPT and any other native-login provider instances. Add the exact allowed model as a custom model if it is not listed. Use a new thread in that instance. The custom provider requests the Responses API using only the gateway secret and disables WebSocket and automatic retries. Never give T3 a management key to enable native CPA quota monitoring.

Supported gateway paths are POST /v1/responses, GET /v1/models (local allowlist only), and GET /usage (monitoring key only). The request policy forbids hosted tools, background jobs, stored conversation IDs, prompt-template references, and externally fetched media; local function/custom tools are allowed. Streaming HTTP is supported in the gateway. WebSocket, compact, alpha search, images, and other routes are deliberately blocked, not emulated. Test long Codex threads and compaction behavior before relying on this provider; some T3/Codex features may not work within this restricted profile. Real T3 compatibility is not established by the mock tests.

## Staging verification

Use a dedicated ordinary API project key, not a subscription. Review the policy and enable the staging client. Start the dedicated CPA service first if needed, then the gateway. Run deploy/t3-gateway/smoke.py with --base set to the private gateway origin, --model set to the allowed model, and the client and monitor secrets in T3_GATEWAY_CLIENT_KEY and T3_GATEWAY_MONITOR_KEY in a trusted operator shell. Without --live the script tests local discovery, monitoring permissions and rejection paths without inference. With --live it sends one bounded, billable API request and checks reported output usage against its requested cap (set the staging cap to at least 128). Never run live tests without the operator's approval. Then test T3 streaming, multiple turns, cancellation, revocation, and attempted bypasses from the isolated host. Do not enable services at boot or production traffic until all acceptance checks pass.

## Accounting limitations

Daily admitted input bytes and requested output tokens are not actual subscription quota. OpenAI documents max_output_tokens as a bound on generated tokens including reasoning, but actual upstream behavior through CPA requires live verification. Reported usage is observed only from complete successful upstream JSON or SSE responses with valid totals. Unknown or interrupted responses retain admission reservations. Reported totals are attributed to admission day UTC. The observed token threshold stops later requests, not already in-flight usage; it is not a hard actual-token limit. A crash can leave admissions without completions; treat them as unresolved. Strict mode blocks new admission on the same UTC day. Completion-write failure suspends admissions in the process; inspect unresolved admissions before restarting. Audit records exclude prompt text and credentials but are not tamper-proof against host administrators. Monitor disk capacity and arrange offline retention/export. There is no web administration integration for gateway policies; use trusted root-owned configuration and the scoped monitoring endpoint.

## Subscription authorization

The isolated CPA mode is API-key-only. It does not load or proxy ChatGPT subscription OAuth. OpenAI Sign in with ChatGPT terms effective November 4, 2026 require app-specific authorization and prohibit providing general-purpose API access to other tools using that grant. An authorization issued for another application must not be assumed transferable. See https://openai.com/policies/sign-in-with-chatgpt-terms/. Keep subscription-backed traffic disabled unless a supported, specifically authorized integration is established. This does not modify the existing fork's ordinary provider behavior outside isolated mode.

## Release gates

Successful CI, actual CPA outbound-wire verification with a staging API key, live Codex/T3 compatibility and host isolation verification remain release gates. Subscription integration needs separate authorization and is not implemented. No production configuration or credentials are installed by these files.
