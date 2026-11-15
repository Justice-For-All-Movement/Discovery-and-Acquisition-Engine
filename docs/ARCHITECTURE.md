# Acquisition boundary

This library captures one explicitly approved HTTPS source at a time. Source policies bind tenant, project, exact hostname allowlist, expiry, access basis, byte/redirect budgets and an identifying user agent. DNS resolution is checked for public IPv4 addresses and the chosen address is pinned into the HTTPS connection. Each redirect repeats URL, host and DNS checks. Credentials, fragments, custom ports, private/reserved addresses, compressed transport and partial responses are rejected. TLS continues to verify the original hostname.

Captured exact bytes carry request/final URLs, retrieval time, redirects, response metadata and SHA256. A capture is not a factual conclusion or permission to publish. Captured files must enter evidence quarantine before processing. Tests inject DNS and transport; no live capture is required.

Current limits: IPv4 HTTPS only, six explicit media families including bounded WARC/ZIP capture, no bulk crawler, provider-specific archive API adapters, robots-policy evaluator or deployed worker daemon yet. The opt-in JSON archive catalog adapter, connector SDK and durable traversal checkpoint are described in CONNECTORS.md. Policy is trusted deployment configuration and must be enforced by an authenticated action gateway. A bounded total deadline covers DNS resolution, redirects and transport awaits. Cancellation reaches the transport; a timed-out resolver can never later start a transport call. Native DNS may continue its underlying OS query after the awaiting capture has failed; deployment concurrency limits remain required. Future work is retained in registry/prs.json.

## Collection acquisition contract

`createCollection`, `dueItems`, `startAcquisition`, `finishAcquisition` and `collectionCoverage` implement bounded collection/refresh planning with exact normalized allowlisted URLs, immutable attempt receipts, refresh cooldown and explicit capture/failure outcomes. Completion requires the durable evidence receipt supplied by the storage adapter. Coverage distinguishes expected items, successfully captured items, unseen/failed work, acquisition attempts and unique byte editions; repeated refreshes do not become new incidents or independent sources.

State must be persisted with atomic revision comparison before leasing an acquisition and after its evidence receipt is committed. The optional durable scheduler described below retains started attempts until completion or explicit recovery. A capture digest and collection count are provenance/coverage signals, not proof of factual claims.

## Asynchronous admission and output ownership

Capture snapshots authenticated context, source policy and configured resolver/transport functions before awaiting dependencies. Caller mutation cannot change scope, approved hosts, byte limits or provenance mid-flight. DNS answers are copied before validation and the checked address is passed as an immutable pin; transports receive a separate URL object. Returned byte arrays are independent copies, so later adapter buffer reuse cannot invalidate their digest. Provider errors are redacted, including adapter domain errors. The optional trusted `timeoutMs` is 10-30000 milliseconds (default 30000), and `signal` enables cancellation. A pre-aborted signal performs no DNS or transport work. One deadline spans all redirects; individual operations do not reset it.

A custom adapter is trusted deployment code and must honor the signal and constrain its own resources. The wrapper bounds awaiting it but cannot terminate arbitrary noncooperating code or an OS DNS request. Tests use fictional URLs and injected dependencies only; no external live capture or deployment acceptance is claimed by these injected tests. Scope/expiry admission is a captured capability decision for this bounded attempt; a future gateway must coordinate mid-flight revocation if required.

Native transport qualification also uses a local ephemeral TLS server and a child-specific test CA, without disabling hostname verification. It checks the actual pinned lookup, Host authority, wrong-host certificate rejection, oversized response, compressed response and cancellation. This intentionally invokes the transport directly with a loopback pin for the test; the public capture URL/address layer continues to reject loopback. No external endpoint or global trust-store change is used. The test requires the Node 24 runtime and `/usr/bin/openssl`, both available in CI.

## Durable scheduler adapter

The opt-in `./scheduler` adapter persists approved collection scheduling, actor-bound leases, one-shot work consumption, verified outcomes and uncertainty recovery in its own operational database. See SCHEDULER.md for trusted-host contracts, database roles, worker obligations and qualification limits. A deployed worker daemon and external receipt-service integration remain separate.

Receipt completion verification uses monotonic admission/result fences in addition to its timer, closes owned signals on every exit and sanitizes callback errors. A reproduced blocked-event-loop late result cannot commit captured/no-capture completion. This does not preempt callbacks or bound begun SQL and does not add an upstream proof service, fresh clock after SQL waits or distributed permission fence. See SCHEDULER.md for source-bound tests and limits.

The explicit consumeCurrent operation now samples a required trusted live clock after locked stored-state admission. Legacy consume and other scheduler operations retain caller-time semantics. This does not add current external Identity policy or a deployed receipt/worker service. See SCHEDULER.md.

leaseNextCurrent adds explicit post-lock live-clock lease creation, complementing consumeCurrent. Legacy leaseNext remains caller-time compatible and cached lease replay stays historical; no renewed execution authority is returned. Other scheduler clocks and deployed services remain pending. See SCHEDULER.md.

recoverCurrent adds explicit post-lock current expiry recovery while retaining consumed uncertainty/capacity until verified resolution. Legacy recovery stays caller-time based and cached results stay historical; no retries, quiescence proof or deployed services are introduced. See SCHEDULER.md.

## Durable catalog traversal metadata

The opt-in `./catalog-checkpoint` adapter stores traversal metadata in the engine's dedicated operational database with exact scope, purpose, connector-configuration and aggregate-limit binding. Creation and page append use the Evidence database SDK's revision comparison, project transaction lock, audit trail and minimal outbox notification. A restart can load the last committed revision and continue only from its explicit normalized `nextUrl`; stale or differently bound callers fail closed.

This is not archival storage or network authority. Exact catalog bytes and verified evidence receipts stay outside this checkpoint, and hosts must make a fresh authenticated/current-policy decision before each capture. The adapter issues no requests and provides no automatic retry or continuation. Migration-backed tests exercise filesystem reopen, optimistic contention and rejection rollback; independent PostgreSQL sessions, provider APIs, deployed workers and live acceptance remain separate.


## Archive format boundary

The opt-in `./archive-formats` parser inventories already captured WARC envelopes and ZIP central directories under explicit per-entry, aggregate-expansion, header and count limits. It performs no decompression or extraction and rejects unsafe paths, encryption, ZIP64, multi-disk layouts, unsupported compression and inconsistent local/central metadata. WARC payload digests and ZIP CRC/size fields preserve source-bound inventory metadata only; they do not authenticate archive statements or authorize downstream processing. See CONNECTORS.md for exact limits and qualification boundaries.

POSTGRES_TESTS.md defines six independent PostgreSQL17 scheduler-session scenarios, separate from embedded timing-hook tests and production qualification. Canonical migration, restricted authenticated LOGIN, directly observed lock waits, explicit disposable empty loopback target and no-reset rules apply. Current-head CI execution remains required.

## Monotonic capture deadline fences

The total HTTPS-capture deadline uses Node's monotonic clock as well as its abort timer. Checks run before each dependency invocation, after either dependency settlement, and after bytes/provenance assembly before publication. Synchronous DNS/transport work or delayed event-loop timer delivery therefore cannot authorize a later request or publish a late successful capture. A late provider rejection is classified as timeout without exposing provider diagnostics. Explicit cancellation still propagates its generic cancellation code.

This bounds acceptance, not synchronous CPU preemption: a trusted adapter can block JavaScript until it returns, and native DNS may outlive the wrapper. Hosts still need process/concurrency/resource isolation. No external network acceptance, acquisition permission, upstream scheduler clock change or worker deployment is implied.
