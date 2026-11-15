# E04 Discovery and Acquisition — engine API

Service layer following the engine service convention (v1). Schema `e04_discovery`, capability prefix `discovery`.
Kit: `src/service-kit.ts` version 1.0.1, sha256 `95475a907267ba1fdd54b557aabe5645c37add9788a5b2d0854d9accfd5d8ea5`
(byte-identical copy from the Identity engine; `src/contracts.ts` is identical too).

Status words used below: **tested** = covered by `tests/engine*.test.ts` against real PostgreSQL 16 and a controlled HTTP
server on 127.0.0.1; **implemented, not verified** = code exists but has not run against a real third-party provider.
Nothing here has been verified against a live external website, search provider or object store, deployed in a hosted
environment, or independently security reviewed.

## Entry points

```ts
import { createEngine, migrate, routes, manifest, migrations, SCHEMA } from '@accountability/discovery-acquisition/engine';
createEngine({ sql, objects?, ports?: { evidence?, authorization?, useDecision? }, config?: DiscoveryConfig })
```

| `config` key | Default | Meaning |
|---|---|---|
| `userAgent` | `AccountabilityDiscoveryBot/<version>` | Sent on every request; set an honest, contactable identity. `serve` requires `DISCOVERY_USER_AGENT`. |
| `allowedPrivateHosts` | `[]` | Exact `host:port` entries allowed to resolve to non-public addresses (tests, deliberate intranet sources). Anything else private is refused. |
| `allowedPorts` | `[80, 443]` | Ports permitted for hosts not on the private allowlist. |
| `maxRedirects` / `maxBytes` / `maxDecompressedBytes` / `timeoutMs` | 5 / 50 MiB / 100 MiB / 30 s | Per-request ceilings; the stream is aborted when exceeded. |
| `resolver` | system `getaddrinfo` | Injectable DNS resolver (tests). |
| `credentialKey` | none | Base64 of 32 bytes (AES-256-GCM). Without it, storing a source credential answers `unavailable`. |
| `defaultMinIntervalMs` / `maxCrawlDelayMs` / `robotsTtlMs` | 1000 / 30 000 / 24 h | Politeness defaults. |
| `maxPageAttempts` / `pageRetryBaseMs` | 3 / 2000 | In-run retries of a transiently failing index page. |
| `maxItemAttempts` / `retryBaseMs` | 4 / 60 000 | Item retry ceiling and exponential backoff base. |
| `mirrorThreshold` | 0.5 | Shingle similarity at or above which two texts are one source family. |
| `importRoot` | none | Only directory under which `format: 'directory'` imports may read. |
| `maxPages` / `maxItems` | 1000 / 50 000 | Ceilings for per-run options. |
| `leaseMs` / `workerId` | 60 000 / random | Job lease length and worker name. |

Ports: `evidence` (kit `EvidencePort`) receives original bytes; when absent, bytes go to `objects` under
`<tenant>/<project>/discovery/originals/<sha256>` and every receipt says so; when both are absent a bytes-level run is
refused with `unavailable`. `authorization` (kit `AuthorizationPort`) is re-checked inside the worker before a run does
anything; a denial or error ends the run as `blocked`. `useDecision` (kit `UseDecisionPort`), when supplied, is asked
`preserve` for the source and its `permissionRefs` before a metadata/bytes run; anything but `allow` blocks the run.

Server: `npm run serve` (`src/engine/serve.ts`). Env: `DATABASE_URL`, `PORT` (8104), `HOST`, `IDENTITY_PUBLIC_KEYS` (JSON
kid→PEM) or `IDENTITY_JWKS_FILE`, `IDENTITY_ISSUER`, `OBJECT_STORE`=`fs`|`s3`|`none` with `OBJECT_STORE_PATH` / `S3_*`,
`DISCOVERY_USER_AGENT` (required), `DISCOVERY_ALLOWED_PRIVATE_HOSTS` (comma list of `host:port`), `DISCOVERY_ALLOWED_PORTS`,
`DISCOVERY_MAX_BYTES`, `DISCOVERY_TIMEOUT_MS`, `DISCOVERY_CREDENTIAL_KEY`, `DISCOVERY_IMPORT_ROOT`, `DISCOVERY_WORKERS`
(worker loops, default 2, `0` disables), `DISCOVERY_SCHEDULER_MS` (default 60 000), `PG_POOL_MAX`. The standalone server has
no EvidencePort: it stores originals in its own object store. The server start path is not covered by an automated test; it was started once by hand against a disposable database (healthz and an authenticated list call answered).

## Capabilities

`discovery:read`, `discovery:configure` (sources, expected items, gap resolution), `discovery:acquire` (runs, refresh,
single acquisitions, retries, control, imports), `discovery:search`, `discovery:read_bytes`, `discovery:read_leads`,
`discovery:write_leads`, `discovery:admin` (credentials, robots decision, unblocking — sensitive, never granted by
`discovery:*`), `discovery:events` (event feed and `applyUpstreamChange` — sensitive). Every method checks its capability
before any read or write; a foreign tenant, project or compartment is `not_found`.

## Data model (all rows carry `tenant_id`, `project_id`; `compartment` is inherited from the source)

| Object (uref kind) | What it is |
|---|---|
| `source` | Catalog entry: `kind` (`html_index`, `sitemap`, `feed` [RSS/Atom], `json_api`, `file_list`, `archive_import`, `search_json`, `search_opensearch`), `baseUrl`, `config`, `accessTerms`, `reuse` (`unknown`, `citation_only`, `licensed`, `public_domain`, `permission_granted`, `restricted`), `rateLimit {minIntervalMs,maxConcurrent}`, `refreshPolicy {mode: manual\|interval, intervalSeconds}`, `robotsPolicy` (`honour`\|`ignore`), `permissionRefs`, optional encrypted credential. Revisions are kept. |
| `run` | A collection run (`collect`, `refresh`, `search`, `single`, `retry`, `import`) with a durable checkpoint; executed by kit job `discovery.run`. States: `queued`, `running`, `paused`, `cancelled`, `completed`, `blocked`. |
| `item` | A discovered link (unique per source by canonical URL). `state`: `discovered` (link only), `metadata_acquired`, `bytes_acquired`, `failed`, `skipped_policy`, `access_restricted`, `not_found`. |
| `acquisition` | One acquired revision of an item: `level` `metadata` or `bytes`, sha256, size, sniffed media type, `storage` (`evidence_port`, `object_store`, `none`), `evidenceRef`/`objectKey`, `reuse`, `accessTerms`, `origin` JSON, `changed`, `supersedes`. |
| `receipt` | Immutable (database trigger rejects UPDATE/DELETE) record of one request or import: request URL, final URL, redirect chain, resolved IP, status, selected response headers (never cookies), sha256, size, sniffed and declared media type, outcome, robots decision, conditional headers sent, storage statement, reuse, tool version, timestamps, content hash. |
| `failure` (listed, not inspectable) | Per item: reason, attempts, `nextRetryAt`, state `open`/`resolved`/`exhausted`. |
| `gap` | Expected-but-unresolved or blocked thing: kinds `expected_unresolved`, `access_restricted`, `not_found`, `robots_disallowed`, `blocked_target`, `outside_source_scope`, `too_large`, `redirect_loop`, `too_many_redirects`, `unsupported_encoding`, `unexpected_status`, `retries_exhausted`, `page_unavailable`, `unparseable_page`, `page_limit_reached`, `item_limit_reached`, `byte_ceiling`, `provenance_missing`, `integrity_mismatch`. |
| `family` | Content family: one sha256, many locations. Each family belongs to a `source_family`; mirrors share it. |
| `search_attempt` | One query against a search adapter, including zero-result and failed attempts. |
| `lead` / `lead_route` | Contact lead and its routes with provenance. |

`config` keys by kind — `html_index`: `itemPattern` (regular expression over absolute URLs; operator-supplied and trusted),
`linkScope: 'any'`; `json_api`/`search_json`: `itemsPath`, `urlField`, `idField`, `titleField`, `itemUrlTemplate` (`{id}`),
`metadataFields`, `totalPath`, `pagination` (`cursor {cursorPath,cursorParam}`, `page {pageParam,startPage,totalPagesPath}`,
`offset {offsetParam,limitParam,limit}`, `next_url {nextPath}`, `link_header`), `queryParam`, `params`, `listingIsMetadata`;
`search_opensearch`: `template` (or `baseUrl`) containing `{searchTerms}`, `count`; `file_list`: `urls` (inline list) or a
text file of URLs at `baseUrl`; all: `allowedHosts` (extra `host[:port]` values in scope), `accessRestrictionMarkers`
(strings that mark a paywall page), `contactTerms` (heading terms for contact sections, default `["contact"]`).

## Service methods (`ctx: ServiceContext` first; `Rec` = camel-cased row plus `ref`)

```ts
createSource(ctx, input: SourceInput): Promise<Rec>                       // discovery:configure, idempotencyKey
updateSource(ctx, id, patch: Partial<SourceInput>): Promise<Rec>
getSource(ctx, id): Promise<Rec>;  listSources(ctx, { kind?, limit? }?): Promise<Rec[]>
setSourceCredential(ctx, id, { header?, value: string | null, authorizationNote }): Promise<Rec>   // discovery:admin
setRobotsPolicy(ctx, id, { policy: 'honour' | 'ignore', decisionNote }): Promise<Rec>              // discovery:admin; 'ignore' only by a human actor
unblockSource(ctx, id, { decisionNote, permissionRef? }): Promise<Rec>                             // discovery:admin
startCollection(ctx, { sourceId, level?: 'links'|'metadata'|'bytes', maxPages?, maxItems?, maxTotalBytes?, questionRef?, extractLeads?: boolean | { why? }, idempotencyKey? }): Promise<Rec /* run */>
refreshSource(ctx, sourceId, options?: RunOptions): Promise<Rec /* run */>
acquire(ctx, { sourceId, url? | itemId?, level?: 'metadata'|'bytes', questionRef?, extractLeads?, idempotencyKey? }): Promise<Rec /* run + item ref */>
retryFailures(ctx, { sourceId, force?, idempotencyKey? }): Promise<Rec | null>
getRun(ctx, id): Promise<Rec>;  listRuns(ctx, { sourceId?, state?, limit? }?): Promise<Rec[]>
controlRun(ctx, id, action: 'pause' | 'resume' | 'cancel'): Promise<Rec>
coverage(ctx, { runId } | { sourceId }): Promise<Coverage>
listItems(ctx, { sourceId?, runId?, state?, limit?, after? }?): Promise<Rec[]>   // with runId, `state` filters the run outcome
getItem(ctx, id): Promise<Rec /* item + acquisitions[] */>
getAcquisition(ctx, id): Promise<Rec>
getAcquisitionBytes(ctx, id): Promise<{ bytes, mediaType, sha256 }>              // discovery:read_bytes; audited
getReceipt(ctx, id): Promise<Rec>;  listReceipts(ctx, { runId?, itemId?, limit? }?): Promise<Rec[]>
listFailures(ctx, { sourceId?, state?, limit? }?): Promise<Rec[]>
listGaps(ctx, { sourceId?, runId?, kind?, state?, limit? }?): Promise<Rec[]>
declareExpected(ctx, { sourceId, expected: { url, note? }[], idempotencyKey? }): Promise<{ recorded: number }>
resolveGap(ctx, id, { resolution }): Promise<Rec>
getFamily(ctx, id): Promise<Rec>;  corroboration(ctx, { items: string[] /* E04:item urefs */ }): Promise<Rec>
searchSource(ctx, { sourceId, query, questionRef?, maxPages?, maxItems?, params?, idempotencyKey? }): Promise<Rec /* attempt */>   // discovery:search
getSearchAttempt(ctx, id): Promise<Rec>;  listSearchAttempts(ctx, { sourceId?, questionRef?, limit? }?): Promise<Rec[]>
importArchive(ctx, { sourceId, format: 'zip'|'warc'|'directory', bytes?, path?, manifest?, idempotencyKey? }): Promise<Rec>
createLead(ctx, input: LeadInput): Promise<Rec>;  getLead(ctx, id): Promise<Rec>
listLeads(ctx, { questionRef?, sourceItemRef?, limit? }?): Promise<Rec[]>
setRouteVerification(ctx, leadId, routeId, { state: 'unverified'|'channel_verified'|'undeliverable'|'invalid', note }): Promise<Rec>
setLeadIdentity(ctx, leadId, { identityState: 'unconfirmed'|'confirmed_by_operator'|'disputed', note }): Promise<Rec>
extractLeadsFromAcquisition(ctx, acquisitionId, { questionRef?, why? }?): Promise<Rec[]>
runWorkerOnce(options?: { limit?: number }): Promise<number>     // one job-leasing pass; returns jobs processed (no ctx: jobs carry theirs)
runDueWork(now?: Date): Promise<string[]>                         // enqueues due interval refreshes and due retries; returns run ids
inspect, search, audit, events, applyUpstreamChange, health       // StandardEngine
```

`DiscoveryPort` (exported type) is the subset `startCollection | searchSource | coverage | listItems | listLeads | getRun |
listSources` intended for E08.

### Runs and checkpoints (tested)

A run is one kit job (`discovery.run`, dedupe key = run id). Phase `pages` walks the listing: each fetched page is committed
in one transaction (receipt, page row, item upserts, run-item rows, events, checkpoint advance with a sequence fence), so a
crash loses at most the page in flight. Phase `items` processes pending run items one at a time, each settled in its own
transaction. After a crash the lease expires and another worker continues from the checkpoint: checkpointed pages and
settled items are not requested again (the request in flight at the crash is repeated). The crash test kills a real child
process with SIGKILL twice. Pause and cancel revoke the job lease; the worker checks the lease before each request and inside
each settling transaction. A request already in flight when a pause lands completes on the wire but is not recorded, and is
repeated after resume. Run limits (`maxPages`, `maxItems`, `maxTotalBytes`) end the walk with a gap, never silently.

### Retrieval worker (tested with a local source; no live third-party site)

Only `http`/`https`; URLs with credentials are refused; port allowlist; the host name is resolved once per hop, **every**
returned address must be public (loopback, RFC 1918, link-local and metadata, CGNAT, multicast, reserved, documentation,
IPv4-mapped/compatible IPv6, NAT64, 6to4, Teredo, unique/site-local are refused) and the connection is pinned to the vetted
address (checked against the socket's remote address); every redirect hop is vetted again; redirect limit and loop
detection; overall deadline; raw and decoded byte ceilings with streaming abort; gzip/deflate/br decoding with an expansion
ceiling; media type sniffed from the bytes (declared type kept separately); no cookies sent or stored; a stored credential is
decrypted only in the worker and sent only to its bound origin. Per-host spacing and concurrency are reserved in PostgreSQL
(`host_rate`, `host_leases` — host names and timestamps only, deliberately shared across tenants and workers). robots.txt is
fetched per origin, cached per project, evaluated per RFC 9309 (exact product-token group, longest match, `*`/`$`), its
crawl-delay raises the interval, an unreachable robots.txt is treated as disallow, and the decision is written into every
receipt. Setting `robotsPolicy: 'ignore'` needs `discovery:admin`, a human actor and a decision note recorded in audit.

Access controls are never bypassed: 401/402/403/407/451, challenge pages and operator-configured paywall markers become
`access_restricted` gaps with one receipt and no retry. 404/410 become `not_found`. 408/425/429/5xx, timeouts and network
errors become failures with attempts and `nextRetryAt` (Retry-After honoured), retried only by `runDueWork`/`retryFailures`
until `maxItemAttempts`, then a `retries_exhausted` gap.

### Dedupe and independence (tested)

Canonical URLs (scheme/host case, default port, fragment, tracking parameters, sorted query) identify items. Identical bytes
from different URLs are one content family with several locations. For text, a bottom-k sketch of 5-word shingles over the
main text (navigation chrome removed) is compared with existing families; similarity ≥ `mirrorThreshold`, or a
`rel=canonical` link to another acquired item, puts the new family in the existing **source family** with a
`same_source_family` hint. `corroboration` and coverage count source families, so a copy or detected mirror is never counted
as independent. Limits: only text formats are compared (PDFs and images are matched by exact bytes only); the candidate search
needs at least one shared sketch value; undetected syndication remains possible and the result says so.

### Refresh (tested)

`refreshSource` re-walks the listing, then revisits every item that has an acquisition with `If-None-Match` /
`If-Modified-Since`. 304 or an equal digest → `unchanged`; a different digest → a new acquisition revision (`changed`,
`supersedes`), handed to the evidence port again with `previousEvidenceRef`, an `acquisition.completed` event with
`changed: true`, and one `collection.changed` event with `{added, changed, missing}`. Items no longer listed get
`missingSince` (only when the listing was walked completely). Interval refresh is enqueued by `runDueWork`.

### Contact leads (tested)

Deterministic extractors over an acquired HTML page: schema.org JSON-LD (`Person`, organizations, `ContactPoint`), staff
cards (class names such as `staff`, `team-member`, `vcard`, `h-card`), contact sections (`<address>`, elements or headings
matching `contactTerms`: e-mail, web form, postal) and remaining `mailto:` links. Each lead stores person/role/organization,
`why` with `questionRef` and `sourceItemRef`, a confidence note, and routes whose `provenanceRef` is the acquisition uref and
`provenanceUrl` the page. Manual leads need a reason and provenance for every route. `verificationState` belongs to the
route; `identityState` and `knowledgeState` belong to the lead and are never changed by channel verification
(`knowledgeState` has no setter at all in this engine). This engine never contacts anyone. Extraction runs only when a run
asks for it (`extractLeads`, needs `discovery:write_leads`) or on demand. Obfuscated addresses, phone numbers outside
JSON-LD and non-HTML documents are not extracted.

### Search adapters (tested locally; implemented, not verified against any live search provider)

`searchSource` builds the request for a `search_json` source (generic JSON API: `queryParam`, static `params`, the same item
mapping and pagination as `json_api`) or a `search_opensearch` source (URL template, RSS/Atom response,
`opensearch:totalResults`), records a `search_attempt` immediately and runs it as a job. Results become link-level items
carrying `questionRef`. The attempt ends `completed` with `resultCount` (0 is a recorded result) or `failed` with the error.
The OpenSearch description document itself is not fetched or parsed; the template is configuration.

### Private archive import (tested)

`importArchive` into an `archive_import` source, synchronously: ZIP (stored/deflate; CRC and size verified; a
`manifest.json` member is used when no manifest is passed), WARC 1.0/1.1 (optionally gzip; `response` and `resource`
records; several captures of one URL become successive revisions in capture order) or a directory under `importRoot`
(symlinks and special files skipped and counted). Manifest: `{ collection?, collectedBy?, description?, entries: [{ path,
originalUrl?, retrievedAt?, title?, mediaType?, sha256?, note?, history?: Json[] }] }`. Each entry's `history` is preserved
verbatim in the acquisition origin and handed to the evidence port. Items lacking `originalUrl`, `retrievedAt` or a manifest
entry get a `provenance_missing` gap; a digest differing from the manifest gets `integrity_mismatch`; manifest entries with
no file get `expected_unresolved`. Limits: 25 MiB per archive, 5000 entries; no ZIP64, encrypted or multi-disk ZIPs; ZIPs
containing directory entries are refused (create with `zip -D`); WARC HTTP bodies with chunked or content encoding are
skipped and counted; WARC `revisit`/`continuation` records are not resolved.

## Events (outbox; subject → payload)

| Type | Subject |
|---|---|
| `source.registered`, `source.changed`, `source.blocked`, `source.unblocked`, `source.stale` | `E04:source:<id>[@rev]` |
| `source.discovered` | `E04:item:<id>` (first time an item is seen) |
| `collection.started`, `collection.completed`, `collection.paused`, `collection.resumed`, `collection.cancelled` | `E04:run:<id>` |
| `collection.changed` | `E04:source:<id>` `{ run, added, changed, missing }` |
| `acquisition.completed` | `E04:acquisition:<id>@<rev>` `{ item, level, sha256, changed, supersedes, evidenceRef, duplicateOfExistingContent, reuse }` |
| `acquisition.blocked` | item, acquisition or run `{ reason, … }` (access restricted, robots, blocked target, upstream block) |
| `acquisition.failed` | `E04:item:<id>` `{ attempts, exhausted }` |
| `search.attempted` | `E04:search_attempt:<id>` `{ results, succeeded, question }` |
| `lead.recorded`, `lead.stale`, `lead.blocked` | `E04:lead:<id>` |
| `gap.recorded` | `E04:gap:<id>` |

`applyUpstreamChange(ctx, change)` (capability `discovery:events`, idempotent by `eventId`): for `permission_withdrawn`,
`permission_changed` and `rights_changed`, sources whose own uref or `permissionRefs` match are **blocked** (their active
runs are cancelled and marked `blocked`; `startCollection`, `refreshSource`, `acquire`, `searchSource`, `importArchive`,
`getAcquisitionBytes` and lead extraction answer `consent_denied`; the scheduler skips them), as are directly referenced
items, acquisitions (by own uref or `evidenceRef`) and leads. Any other kind marks matching sources, items (by own uref or
`questionRef`) and leads (by `questionRef` / `sourceItemRef`) **stale**. Nothing is deleted. Reasons are visible in
`inspect`; only `unblockSource` (audited operator decision) clears a source. Items, acquisitions and leads have no unblock
method. `permission_changed` is treated conservatively as a block.

## HTTP routes

Standard: `GET /healthz`, `GET /v1/manifest`, `GET /v1/inspect?ref=`, `GET /v1/search?q=`, `GET /v1/audit`, `GET /v1/events`,
`POST /v1/upstream-changes`. `Idempotency-Key` header maps to `idempotencyKey`. `unavailable` is returned as HTTP 503 with
its code.

`POST|GET /v1/sources`, `GET|PATCH /v1/sources/:id`, `POST /v1/sources/:id/credential`, `…/robots-policy`, `…/unblock`,
`…/expected`, `…/retry-failures`, `GET /v1/sources/:id/coverage`, `POST /v1/connectors/:id/refresh`,
`POST|GET /v1/collections`, `GET /v1/collections/:id`, `GET /v1/collections/:id/coverage`, `POST /v1/collections/:id/control`
`{action}`, `POST /v1/acquisitions`, `GET /v1/acquisitions/:id`, `GET /v1/acquisitions/:id/bytes`,
`POST /v1/acquisitions/:id/extract-leads`, `GET /v1/receipts`, `GET /v1/receipts/:id`, `GET /v1/items`, `GET /v1/items/:id`,
`GET /v1/failures`, `GET /v1/gaps`, `POST /v1/gaps/:id/resolve`, `GET /v1/families/:id`, `POST /v1/corroboration`,
`POST|GET /v1/discovery/searches`, `GET /v1/discovery/searches/:id`, `POST /v1/imports` (`{sourceId, format, bytesBase64 |
path, manifest}`), `POST|GET /v1/leads`, `GET /v1/leads/:id`, `POST /v1/leads/:id/identity`,
`POST /v1/leads/:id/routes/:routeId/verification`. Only a sample of routes is exercised over HTTP in tests; all delegate to
the tested service methods.

## Not implemented, not verified, known limits

- No verification against any live website, API, search provider, S3 store or hosted deployment. No independent security review.
- Parsers run in-process with size, node-count, depth and candidate caps (tested against hostile inputs); there is no
  separate parser sandbox process. `itemPattern` is an operator-supplied regular expression and is trusted configuration.
- No JavaScript rendering, form submission, login flows or cookie sessions: listings that need them appear as gaps.
- HTML `<meta name="robots">` and `X-Robots-Tag` are recorded (header) but not enforced; only robots.txt is.
- Mirror detection covers text formats only; see "Dedupe and independence".
- A paused/cancelled or crashed worker may repeat the single request that was in flight.
- Only one run job executes a given run at a time and items within a run are fetched sequentially; parallelism comes from
  several runs/workers.
- Host politeness state is global per host (not per tenant) by design; robots cache is per project.
- `listItems` paginates by id (`after`); other list methods take `limit` only.
- Source credentials support a single request header bound to the base URL's origin; OAuth flows are not implemented.
- The legacy foundation modules (`src/index.ts`, `scheduler.ts`, `catalog-*.ts`, `connectors.ts`, `collection.ts`) are kept
  with their tests; the service layer reuses `archive-formats.ts` (WARC/ZIP inventory) and does not use the legacy scheduler.
