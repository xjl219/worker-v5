# Worker TCP Proxy — pluggable outbound v1

VLESS over WebSocket ingress with three selectable outbound modes:

- `direct` (default): Cloudflare Worker opens a TCP socket directly to the requested destination using `cloudflare:sockets`.
- `relay`: Worker opens TCP to an explicitly configured SNI relay endpoint and forwards the client's original TLS stream unchanged. This mode is for TLS/SNI traffic to destination port 443 only.
- `socks5`: Worker establishes SOCKS5 CONNECT to an explicitly configured upstream.

`OUTBOUND_MODE` selects exactly one mode. There is no automatic cross-mode fallback: a failed route fails closed. This avoids silently changing the network egress or destination path.

## Flow

```
VLESS client -> Cloudflare Worker -> selected outbound adapter
                                  |-> direct TCP -> destination
                                  |-> SNI relay TCP -> TLS/SNI destination (443)
                                  |-> SOCKS5 CONNECT -> destination
```

## Configuration

| Name | Type | Required | Purpose |
|---|---|---:|---|
| `UUID` | Secret | Yes | VLESS client UUID; the secure deploy command creates it on first deployment and reuses the Cloudflare secret on later deployments |
| `OUTBOUND_MODE` | Variable | No | `direct` (default), `relay`, or `socks5` |
| `PROXY_ENABLED` | Dashboard variable | Yes | Set in Cloudflare Worker Settings → Variables; keep `false` until acceptance is complete; only literal `true` enables proxying |
| `ALLOWED_HOSTS` | Dashboard variable | Yes | Comma-separated exact destination hostnames. Every destination must match one entry exactly; subdomains are not inherited. No wildcard, URL, path, or port entries. |
| `ALLOWED_PORTS` | Variable | No | Comma-separated destination ports |
| `RELAY_ENDPOINTS` | Variable | Relay only | Comma-separated `host:port` relay endpoints |
| `SOCKS5_HOST` | Variable | SOCKS5 only | Authorized SOCKS5 server hostname/IP |
| `SOCKS5_PORT` | Variable | No | SOCKS5 port; defaults to 1080 |
| `SOCKS5_USERNAME` | Secret | No | Set together with password |
| `SOCKS5_PASSWORD` | Secret | No | Set together with username |

### Automatic UUID provisioning

Use the normal deploy command:

```bash
npm run deploy
```

The deploy script performs these steps before deployment:

1. If the deployment environment contains `PROXY_UUID` (preferred) or `UUID`, validate it and inject it as the Cloudflare `UUID` secret for this deployment.
2. Otherwise, query Cloudflare with `wrangler secret list --format json`. If a `UUID` secret already exists, keep it unchanged so redeployments do not invalidate existing client profiles.
3. On the first deployment, when the Worker does not exist yet, generate a cryptographically random UUID v4. If a previous generated local copy exists, reuse it.
4. Include a new or supplied UUID in the same Worker deployment through Wrangler's `--secrets-file` option. The temporary secrets file is created outside the repository with restrictive permissions and removed after deployment.
5. Save an automatically generated UUID to `.wrangler/proxy-uuid.txt` (ignored by Git) so the operator can retrieve the client credential. Do not share or commit this file.

The UUID is never printed in deployment logs, placed in command-line arguments, or written into tracked source files. The script only reports whether it generated, reused, or accepted a supplied secret. If Cloudflare cannot return a valid secret listing for a reason other than a missing Worker, deployment stops rather than risking an accidental credential rotation. Existing Cloudflare secrets are retained by normal deployments when no replacement is supplied.

To intentionally rotate the credential, supply a new UUID for one deployment:

```bash
# PowerShell
$env:PROXY_UUID = [guid]::NewGuid().ToString()
npm run deploy
Remove-Item Env:PROXY_UUID

# Bash
PROXY_UUID="$(node -e 'console.log(require("node:crypto").randomUUID())')" npm run deploy
```

The value is stored as the Cloudflare `UUID` secret. For generated credentials, retrieve the client UUID from `.wrangler/proxy-uuid.txt` and keep it in your password manager. Cloudflare secret listings expose names, not secret values. If you do not provide an override on later deployments, the existing remote secret is reused.

Only when using an authenticated SOCKS5 upstream, set `SOCKS5_USERNAME` and `SOCKS5_PASSWORD` as Cloudflare secrets separately. Never put any credentials in `wrangler.toml`, source control, URLs, or logs.

`PROXY_ENABLED` is intentionally not declared in `wrangler.toml`: set it in Cloudflare Dashboard → Workers & Pages → this Worker → Settings → Variables and Secrets. Set it to `false` for initial deployment and only change it to `true` after controlled acceptance. The deploy script uses Wrangler `--keep-vars` so dashboard-managed variables are retained on subsequent deployments. Do not add this switch back to the repository configuration.


Example safe initial configuration:

- `OUTBOUND_MODE=direct`
- In Cloudflare Dashboard, set `PROXY_ENABLED=false` until configuration and controlled tests are complete
- Set `ALLOWED_HOSTS` to the exact destination hostnames required by the client; the proxy remains disabled if the list is missing or invalid
- Do not create or enable a Cloudflare Access application for the initial workers.dev deployment
- Do not configure WAF rules for this initial workers.dev deployment; workers.dev is Cloudflare-managed and does not provide owner-managed zone WAF custom rules

For relay mode, configure only relay endpoints that you own or are explicitly authorized to use. Each entry uses `host:port`; the current v1 parser expects a hostname or IPv4-style host and does not support bracketed IPv6 endpoints. The same destination hostname determines the preferred configured relay within an isolate. If that relay fails, the Worker tries the other explicitly configured relay endpoints. Each endpoint has an isolate-local circuit breaker: three consecutive connection failures open the circuit for 30 seconds; after the timeout, one request may perform a half-open probe. A successful probe closes the circuit. This state is not shared across Worker isolates and is not a global health/quota coordinator. There is no automatic public feed ingestion.

Relay mode forwards the original client TLS bytes; it does not create a new TLS session to the relay. The relay must implement compatible SNI-based forwarding. It is restricted to destination port 443, but this does not itself prove the client stream contains a valid TLS ClientHello or that the relay reaches the intended destination. Verify using a relay you control and a destination you are authorized to test.

## Security behavior

- Proxying is disabled unless `PROXY_ENABLED=true`.
- VLESS UUID validation is required before any outbound socket is opened.
- UUID authentication, `ALLOWED_PORTS`, and a non-empty `ALLOWED_HOSTS` exact-match allowlist are mandatory for all modes. A missing or invalid allowlist fails closed; a configured hostname does not authorize its subdomains.
- Private/local IP literals are rejected by the VLESS parser.
- No fallback between direct, relay, and SOCKS5 modes.
- Root, unknown paths, non-GET probes, and non-WebSocket requests to `/ws` return the same generic 404. `/health` is disabled by default (`HEALTH_ENABLED=false`); if explicitly enabled, it returns only `{ "ok": true }`. A disabled or incompletely configured proxy also returns a generic 404.
- WebSocket policy failures use a generic close reason; detailed auth, destination, and upstream errors are not returned to clients.
- HTTP endpoints retain method/path checks and security response headers.
- WebSocket messages and buffered output remain bounded.

### Entry protection and deployment: current workers.dev mode

The current deployment uses a Cloudflare-managed `workers.dev` hostname. This is not equivalent to a custom domain in a Cloudflare zone you control:

- You cannot create your own zone-level WAF custom rules or zone rate-limiting rules for the managed `workers.dev` hostname.
- Cloudflare applies Browser Integrity Check (BIC) to `workers.dev` requests before they reach the Worker. BIC cannot be disabled for this hostname. Some automated clients with generic library User-Agent signatures can receive HTTP 1010 before Worker code runs; those requests will not appear in Worker logs.
- Do not use Worker-level Cloudflare Access for this WebSocket service: Cloudflare documents that Worker-level Access policies currently reject WebSocket Upgrade requests with HTTP 403.
- Hostname-based Access can protect a specific `workers.dev` hostname and is the only Access mode worth evaluating for this WebSocket endpoint. It requires a Zero Trust Access application and a Service Auth policy. The client must be able to add both `CF-Access-Client-Id` and `CF-Access-Client-Secret` headers to its WebSocket handshake. Verify this capability in the exact VLESS client before enabling Access. If the client cannot set custom WebSocket headers, do not enable this policy: it will block legitimate connections. Treat the Service Token as a client-side secret that can be extracted from a device profile; use one token per device and rotate/revoke it if exposed. UUID authentication remains enabled as a second application-layer check.

Official references:
- [workers.dev behavior, BIC, and disabling the route](https://developers.cloudflare.com/workers/configuration/routing/workers-dev/)
- [Cloudflare Access for Workers and WebSocket limitation](https://developers.cloudflare.com/workers/configuration/cloudflare-access/)
- [Access Service Token request headers](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/)

#### Required settings while using workers.dev

1. Keep `workers_dev` enabled. Do not set `workers_dev = false` while this is the only public ingress; doing so removes the current production hostname. Do not disable it until a replacement Custom Domain or Route has been deployed and tested.
2. Keep `HEALTH_ENABLED=false`. The health endpoint is not required for proxy operation and only adds a public path.
3. In Cloudflare Dashboard → Workers & Pages → this Worker → Settings → Variables and Secrets, create `PROXY_ENABLED` as a plaintext variable with value `false`. This switch is deliberately not stored in `wrangler.toml`. Confirm the UUID secret is provisioned, the selected outbound mode is configured, and any upstream credentials are stored as Worker Secrets rather than in source files.
4. Configure a non-empty, narrow `ALLOWED_HOSTS` list containing every exact destination hostname required by the client. The Worker rejects requests when the list is missing, malformed, or does not contain the exact requested hostname. Do not use a general-purpose unrestricted destination policy.
5. Keep `ALLOWED_PORTS` as narrow as the actual application requires. Do not expand it simply to make a failed connection work.
6. Do not treat a descriptive `User-Agent` as authentication. If BIC blocks a legitimate client, configure a truthful, descriptive application User-Agent in that client if it supports the header. Do not impersonate a browser or add a fake browser signature. If the client cannot control User-Agent and receives 1010, the reliable fix is to move to a Custom Domain/Route in a zone you control, not to weaken UUID validation.
7. After settings are reviewed, change the dashboard variable `PROXY_ENABLED` to `true` for the controlled handshake and data-transfer tests below. If any test fails, change it back to `false` while diagnosing.

#### Access and WAF baseline

For this deployment, Cloudflare Access is not configured and remains off. Do not create an Access application or Service Auth policy. WAF rules are also not configured; the managed `workers.dev` hostname does not provide owner-managed zone-level WAF custom rules. These are platform/dashboard decisions, not Worker source-code settings. Revisit edge protections only if the service moves to a Custom Domain in a zone you control.

The following Access hardening is intentionally not part of the default deployment and must not be enabled for the initial rollout:

Only perform this later evaluation if the exact client supports custom WebSocket handshake headers:

1. In Zero Trust, create a Service Token dedicated to this proxy client. Do not reuse a token shared with unrelated applications.
2. In Zero Trust > Access > Applications, create a Self-hosted application for the exact hostname `<worker-name>.<account-subdomain>.workers.dev`. Do not select the Worker-level "Protect this Worker" control.
3. Add a policy with action **Service Auth** and authorize only the newly created Service Token.
4. Configure the VLESS client's WebSocket headers with `CF-Access-Client-Id` and `CF-Access-Client-Secret`. Keep the existing VLESS UUID unchanged.
5. Test from the actual client. Confirm the handshake reaches the Worker and the proxy works in both directions. A browser login page or HTTP 302 is not a successful proxy handshake.
6. If the client cannot send these headers, remove/disable the Access application before retrying. Do not try to work around this by disabling UUID authentication.

Access adds a pre-Worker identity gate, but it is not a substitute for application UUID validation, destination controls, or shared quotas. Service Token headers are credentials and must not be written to logs or committed to client profile repositories.

#### Deployment sequence for the current workers.dev endpoint

1. Run `npm ci`, `npm run check`, and `npx wrangler deploy --dry-run` locally or in CI.
2. Verify the Cloudflare account and Worker name selected by Wrangler. This repository's config names the Worker `worker-v5-pluggable-v1`; do not deploy over a different production Worker by accident.
3. Run `npm run deploy`. The script provisions/reuses the UUID secret without printing it. Preserve `.wrangler/proxy-uuid.txt` securely if this is the first generated UUID; never commit or share it.
4. In Cloudflare Dashboard, set `PROXY_ENABLED=false`; verify `HEALTH_ENABLED=false`, the intended `OUTBOUND_MODE`, and the relevant upstream variables/secrets. Confirm no Access application/policy has been created for this hostname and no WAF rules have been configured.
5. Test the public hostname's BIC behavior with the actual VLESS client. An HTTP 1010 response is an edge rejection before Worker execution; it is not a VLESS UUID or Worker routing error.
6. Test a deliberately invalid UUID and verify that no outbound connection is opened. Then test a valid UUID against an explicitly authorized destination and verify bidirectional traffic, reconnect behavior, and sustained transfer.
7. Verify the observed egress IP and country independently. A successful WebSocket connection does not prove a US exit location.
8. Only after the controlled tests pass, change the dashboard variable `PROXY_ENABLED` to `true`. Keep a rollback path: set it back to `false` if the service behaves unexpectedly.

#### What workers.dev does not provide for this service

- No owner-managed zone WAF custom rule that blocks every path except `/ws`.
- No owner-managed zone rate-limiting rule scoped to `/ws`.
- No reliable global concurrent-connection or byte quota from Worker isolate-local state.
- No guarantee that BIC accepts every non-browser WebSocket client.

The application still returns a generic 404 for root, unknown paths, non-GET requests, and non-WebSocket requests to `/ws`; `/health` remains disabled by default. This reduces the HTTP surface but does not stop a scanner from discovering the WebSocket endpoint. The VLESS UUID is the actual application credential.

If traffic volume or abuse risk grows, the production-grade path is to attach a Custom Domain in a zone you control, test it, add a WAF custom rule to allow only `/ws`, add a rate-limit rule for the handshake, and then disable `workers.dev`. Do not disable `workers.dev` before the replacement endpoint is confirmed. Cloudflare WAF evaluates the initial HTTP WebSocket Upgrade; it does not inspect frames after the connection is established.

The Worker code cannot provide a reliable account-wide rate or concurrent-connection quota across independent isolates. A reliable global concurrency/byte quota requires a shared coordinator such as a Durable Object or an equivalent external control plane; that remains a separate implementation gate and is not claimed by the current PR.

### Relay circuit breaker behavior

- Applies only to relay endpoints explicitly listed in `RELAY_ENDPOINTS`; it never switches between `direct`, `relay`, and `socks5` modes.
- Opens an endpoint circuit after 3 consecutive connection-establishment failures.
- Keeps the circuit open for 30 seconds, then permits one half-open probe at a time within the current Worker isolate.
- A successful probe closes the circuit; a failed probe reopens it.
- State is isolate-local and may be lost on isolate replacement. It is not a global circuit breaker and does not coordinate health across all Worker instances.
- Failover attempts other configured relay endpoints in deterministic order. If all are open or fail, the connection fails closed.

### DNS and destination boundary

The allowlist prevents a client from choosing arbitrary hostnames, but hostname allowlisting alone cannot prove which IP address a hostname resolves to at connection time. The current outbound paths do not yet enforce a common, application-controlled DNS resolution-and-pinning policy at the actual egress resolver. In particular, SOCKS5 and relay upstreams may resolve destination names remotely. Therefore:
- use only narrow, trusted destination hostnames controlled by reputable service operators;
- do not add user-controlled or arbitrary third-party hostnames;
- treat DNS rebinding resistance as a known limitation until a supported resolution/pinning design is implemented and tested;
- never claim that exact hostname matching alone eliminates SSRF or DNS-rebinding risk.

### Pre-deployment security acceptance gate

Do not enable the proxy or merge this as production-ready until all checks below have evidence:

| Test | Required result | Current verification scope |
|---|---|---|
| Proxy disabled | Generic 404; no outbound socket is opened | Worker unit/integration test |
| Missing UUID / wrong UUID | Connection rejected before outbound socket creation | VLESS parser + integration test |
| Host not on allowlist | Connection rejected before outbound socket creation | Host allowlist unit/integration test |
| Missing or malformed allowlist | Proxy remains unavailable; no outbound socket is opened | Configuration + handler test |
| Exact hostname matching | `google.com` authorizes only `google.com`, not `sub.google.com`, `evilgoogle.com`, or `google.com.evil.net` | Host allowlist unit test |
| Wildcard or malformed allowlist | Configuration rejected closed | Host allowlist unit test |
| Port not allowed | Connection rejected before outbound socket creation | Integration test |
| Unapproved relay/SOCKS upstream | Not selectable unless explicitly configured by operator | Configuration review + integration test |
| Sensitive/admin paths | Generic 404; no config or secret disclosure | HTTP handler test |
| Excess request rate | Not enforceable with owner-managed zone rules on the current managed `workers.dev` hostname; configure a rate-limit rule only after moving to a zone you control | Not available on current `workers.dev` deployment |
| Excess concurrent connections / bytes | Shared quota blocks excess usage | Not implemented; Durable Object/control-plane gate |
| DNS rebinding | Must not be represented as solved by hostname allowlisting | Design limitation; resolution/pinning work required |
| Secret leakage | UUID and SOCKS credentials absent from logs, URLs, health output, and committed config | Code review + log inspection |

A passing TypeScript build or unit-test suite is not a substitute for the zone-level WAF/rate-limit test, real outbound tests, or the remaining shared-quota and DNS-pinning work.

## Staged verification

1. Deploy under the separate Worker name in `wrangler.toml`; do not overwrite an existing service.
2. Set `OUTBOUND_MODE=direct`, configure `UUID` and a narrow `ALLOWED_HOSTS`, and confirm the dashboard variable `PROXY_ENABLED=false`.
3. Confirm `/health` returns only `{ "ok": true }`. It intentionally does not report the selected mode or configuration and does not test outbound connectivity.
4. Enable only for a controlled test and verify a permitted destination.
5. Record the observed egress IP and independently check its geolocation; a successful request does not prove a US exit.
6. Test sustained bidirectional traffic, reconnects, and error handling before any broader use.
7. Test relay or SOCKS5 only after direct mode has been measured and an authorized upstream is available.

## Known limitations

- TCP only; no UDP ASSOCIATE.
- Relay mode is TLS/SNI pass-through on port 443, not a general-purpose relay for arbitrary protocols.
- Relay selection is deterministic per destination within an isolate, with failover only among explicitly configured relay endpoints and isolate-local circuit breaking. Circuit state is not global across Worker isolates.
- SOCKS5 supports CONNECT only; no UDP ASSOCIATE.
- No built-in public relay list. Public feed entries have unknown ownership, authorization, location, and stability and are not trusted by default.
- Typecheck and automated tests must pass before this implementation is considered build-verified. Live deployment and end-to-end traffic tests are separate later gates; do not infer them from CI success.
