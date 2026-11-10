// E04 Discovery and Acquisition — service layer.
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';
import { DomainError, canonical, digest, invariant, nonempty } from '../contracts.ts';
import type { Json } from '../contracts.ts';
import * as kit from '../service-kit.ts';
import type { AuditRecord, EngineEvent, EngineManifestV1, Inspection, Job, ObjectStore, Route, SearchHit, ServiceContext, Sql, StandardEngine, UpstreamChange } from '../service-kit.ts';
import { SCHEMA, migrations } from './schema.ts';
import { parseRobots, robotsDecide, safeFetch, sniffMediaType, vetUrl, FetchBlock } from './net.ts';
import type { FetchOutcome, FetchPolicy, Resolver } from './net.ts';
import { accessMarker, canonicalUrl, decodeText, extractLeads, feedListing, htmlListing, jsonListing, linkHeaderNext, mainText, pageMetadata, parseHtml, shingleSketch, sitemapListing, sketchSimilarity } from './parse.ts';
import type { ExtractedLead, Listing } from './parse.ts';
import { readArchive } from './archive.ts';
import type { ArchiveManifest } from './archive.ts';

export { SCHEMA, migrations };
export const TOOL_VERSION = '1.0.0';
const S = SCHEMA;
// deno-lint-ignore no-explicit-any
type Rec = Record<string, any>;

export const manifest: EngineManifestV1 = {
  id: 'E04', name: 'Discovery and acquisition engine', version: TOOL_VERSION, kit: kit.SERVICE_KIT_VERSION,
  capabilities: ['discovery:read', 'discovery:configure', 'discovery:acquire', 'discovery:search', 'discovery:read_bytes', 'discovery:read_leads', 'discovery:write_leads', 'discovery:admin', 'discovery:events'],
  emits: ['source.registered', 'source.changed', 'source.blocked', 'source.unblocked', 'source.stale', 'source.discovered', 'collection.started', 'collection.completed', 'collection.changed', 'collection.paused', 'collection.resumed', 'collection.cancelled',
    'acquisition.completed', 'acquisition.blocked', 'acquisition.failed', 'search.attempted', 'lead.recorded', 'lead.stale', 'lead.blocked', 'gap.recorded'],
  consumes: ['permission.withdrawn', 'permission.changed', 'rights.changed', 'question.changed'],
};
export function migrate(sql: Sql): Promise<string[]> { return kit.runMigrations(sql, SCHEMA, migrations); }

export const SOURCE_KINDS = ['html_index', 'sitemap', 'feed', 'json_api', 'file_list', 'archive_import', 'search_json', 'search_opensearch'] as const;
export const REUSE = ['unknown', 'citation_only', 'licensed', 'public_domain', 'permission_granted', 'restricted'] as const;
export type SourceKind = (typeof SOURCE_KINDS)[number];
export type Reuse = (typeof REUSE)[number];
export type Level = 'links' | 'metadata' | 'bytes';

export type DiscoveryConfig = Readonly<{
  /** Honest identification sent with every request, e.g. `ExampleResearchBot/1.0 (+https://example.org/bot)`. */
  userAgent?: string;
  /** Exact `host:port` entries permitted to resolve to non-public addresses. Default empty. */
  allowedPrivateHosts?: readonly string[];
  allowedPorts?: readonly number[];
  maxRedirects?: number; maxBytes?: number; maxDecompressedBytes?: number; timeoutMs?: number;
  resolver?: Resolver;
  /** Base64 of 32 random bytes; required before a source credential can be stored. */
  credentialKey?: string;
  robotsTtlMs?: number; defaultMinIntervalMs?: number; maxCrawlDelayMs?: number;
  maxPageAttempts?: number; pageRetryBaseMs?: number; maxItemAttempts?: number; retryBaseMs?: number;
  mirrorThreshold?: number; importRoot?: string; maxPages?: number; maxItems?: number; leaseMs?: number; workerId?: string;
}>;
export type DiscoveryPorts = Readonly<{ evidence?: kit.EvidencePort; authorization?: kit.AuthorizationPort; useDecision?: kit.UseDecisionPort }>;
export type DiscoveryDeps = Readonly<{ sql: Sql; objects?: ObjectStore; ports?: DiscoveryPorts; config?: DiscoveryConfig }>;

export type SourceInput = {
  name: string; kind: SourceKind; baseUrl: string; config?: Rec; accessTerms: string; reuse?: Reuse;
  rateLimit?: { minIntervalMs?: number; maxConcurrent?: number }; refreshPolicy?: { mode: 'manual' | 'interval'; intervalSeconds?: number };
  permissionRefs?: string[]; compartment?: string; idempotencyKey?: string;
};
export type RunOptions = { level?: Level; maxPages?: number; maxItems?: number; maxTotalBytes?: number; questionRef?: string; extractLeads?: boolean | { why?: string }; idempotencyKey?: string };
export type Coverage = {
  scope: 'run' | 'source'; ref: string; state: string;
  discovered: number; linkOnly: number; acquiredMetadata: number; acquiredBytes: number; unchanged: number; failed: number;
  skippedByPolicy: number; accessRestricted: number; notFound: number; pending: number; newItems: number; duplicateContent: number;
  gaps: { open: number; byKind: Record<string, number> }; pages: { fetched: number; unavailable: number };
  independentSourceFamilies: number; bytesAcquired: number; lastCheckpoint: Json; note: string;
};
export type LeadInput = {
  personName?: string; role?: string; organization?: string; why: string; questionRef?: string; sourceItemRef?: string; confidenceNote?: string; compartment?: string;
  routes: { kind: 'email' | 'postal' | 'web_form' | 'phone' | 'other'; value: string; provenanceRef?: string; provenanceUrl?: string; provenanceNote?: string }[]; idempotencyKey?: string;
};

const NUMERIC = new Set(['size']);
function camel(row: Rec | undefined): Rec {
  const out: Rec = {};
  for (const [k, v] of Object.entries(row ?? {})) {
    const key = k.replace(/_([a-z0-9])/g, (_m, c: string) => c.toUpperCase());
    out[key] = v instanceof Date ? v.toISOString() : NUMERIC.has(k) && v !== null ? Number(v) : v;
  }
  return out;
}
const ref = (kind: string, id: unknown, revision?: unknown): string => kit.uref('E04', kind, String(id), revision === undefined || revision === null ? undefined : Number(revision));
const SC = 'tenant_id=$1 and project_id=$2 and (compartment is null or compartment = any($3::text[]))';
const sc = (a: string): string => `${a}.tenant_id=$1 and ${a}.project_id=$2 and (${a}.compartment is null or ${a}.compartment = any($3::text[]))`;
const P = (ctx: ServiceContext): unknown[] => [ctx.tenantId, ctx.projectId, [...ctx.compartments]];
const notFound = (): never => { throw new DomainError('not_found', 'Not found'); };
const isUuid = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
const int = (v: unknown, label: string, min: number, max: number, dflt: number): number => {
  if (v === undefined || v === null) return dflt;
  invariant(Number.isSafeInteger(v) && (v as number) >= min && (v as number) <= max, 'invalid_input', `${label} must be an integer between ${min} and ${max}`);
  return v as number;
};
const like = (q: string): string => `%${q.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
const TRANSIENT_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);
const RESTRICTED_STATUS = new Set([401, 402, 403, 407, 451]);

export type DiscoveryEngine = ReturnType<typeof createEngine>;
/** The narrow surface another engine (E08) needs: start a run, search, read coverage, items and leads. */
export type DiscoveryPort = Pick<DiscoveryEngine, 'startCollection' | 'searchSource' | 'coverage' | 'listItems' | 'listLeads' | 'getRun' | 'listSources'>;

export function createEngine(deps: DiscoveryDeps) {
  const { sql, objects } = deps;
  const ports = deps.ports ?? {};
  const cfg = deps.config ?? {};
  const fetchPolicy: FetchPolicy = {
    userAgent: cfg.userAgent ?? `AccountabilityDiscoveryBot/${TOOL_VERSION}`,
    allowedPrivateHosts: (cfg.allowedPrivateHosts ?? []).map((h) => h.toLowerCase()), allowedPorts: cfg.allowedPorts ?? [80, 443],
    maxRedirects: cfg.maxRedirects ?? 5, maxBytes: cfg.maxBytes ?? 50 * 1024 * 1024, maxDecompressedBytes: cfg.maxDecompressedBytes ?? 100 * 1024 * 1024,
    timeoutMs: cfg.timeoutMs ?? 30_000, ...(cfg.resolver === undefined ? {} : { resolver: cfg.resolver }),
  };
  invariant(/^[\x20-\x7e]{3,200}$/.test(fetchPolicy.userAgent), 'invalid_config', 'userAgent must be printable ASCII');
  const leaseMs = cfg.leaseMs ?? 60_000;
  const workerId = cfg.workerId ?? `e04-${randomUUID()}`;
  const tool = { name: 'e04-discovery', version: TOOL_VERSION, kit: kit.SERVICE_KIT_VERSION, userAgent: fetchPolicy.userAgent };
  const credKey = cfg.credentialKey === undefined ? null : Buffer.from(cfg.credentialKey, 'base64');
  invariant(credKey === null || credKey.byteLength === 32, 'invalid_config', 'credentialKey must be 32 bytes, base64 encoded');

  // ───────────── small persistence helpers ─────────────
  const one = async (q: Sql, text: string, params: readonly unknown[]): Promise<Rec | undefined> => (await q.query(text, params))[0];
  const audit = (tx: Sql, ctx: ServiceContext, action: string, subject: string, detail: Json = {}): Promise<void> => kit.appendAudit(tx, S, ctx, action, subject, detail);
  const emit = (tx: Sql, ctx: ServiceContext, type: string, subject: string, payload: Json = {}): Promise<EngineEvent> => kit.emitEvent(tx, S, ctx, type, subject, payload);
  const sourcePublic = (r: Rec): Rec => { const { credential, ...rest } = camel(r); return { ...rest, ref: ref('source', r.id, r.revision), hasCredential: credential !== null && credential !== undefined }; };
  const loadSource = async (q: Sql, ctx: ServiceContext, id: string, lock = false): Promise<Rec> => {
    if (!isUuid(id)) return notFound();
    return (await one(q, `select * from ${S}.sources where ${SC} and id=$4${lock ? ' for update' : ''}`, [...P(ctx), id])) ?? notFound();
  };
  const sourceHosts = (source: Rec): string[] => {
    const hosts: string[] = [];
    try { hosts.push(new URL(source.base_url).host.toLowerCase()); } catch { /* archive sources have no base URL */ }
    for (const h of (source.config?.allowedHosts ?? []) as unknown[]) if (typeof h === 'string') hosts.push(h.toLowerCase());
    return hosts;
  };
  const inScope = (source: Rec, url: string): boolean => { try { return sourceHosts(source).includes(new URL(url).host.toLowerCase()); } catch { return false; } };
  const assertUsable = (source: Rec): void => {
    if (source.blocked === true) throw new DomainError('consent_denied', 'Source is blocked by a permission or rights change; an operator decision is required before further retrieval');
  };

  function encryptCredential(header: string, origin: string, value: string): Rec {
    if (credKey === null) throw new DomainError('unavailable', 'No credential encryption key is configured (DISCOVERY_CREDENTIAL_KEY)');
    const iv = randomBytes(12); const c = createCipheriv('aes-256-gcm', credKey, iv);
    const data = Buffer.concat([c.update(value, 'utf8'), c.final()]);
    return { header, origin, iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), data: data.toString('base64'), keyId: createHash('sha256').update(credKey).digest('hex').slice(0, 8) };
  }
  function decryptCredential(stored: Rec | null): { origin: string; header: string; value: string } | undefined {
    if (stored === null || stored === undefined) return undefined;
    if (credKey === null) throw new DomainError('unavailable', 'Source has a stored credential but no credential key is configured');
    const d = createDecipheriv('aes-256-gcm', credKey, Buffer.from(stored.iv, 'base64')); d.setAuthTag(Buffer.from(stored.tag, 'base64'));
    return { origin: stored.origin, header: stored.header, value: Buffer.concat([d.update(Buffer.from(stored.data, 'base64')), d.final()]).toString('utf8') };
  }

  // ───────────── host politeness (shared by all workers through PostgreSQL) ─────────────
  async function acquireSlot(host: string, minIntervalMs: number, maxConcurrent: number, beat: () => Promise<void>): Promise<string> {
    for (;;) {
      const got = await sql.tx(async (tx) => {
        await tx.query(`insert into ${S}.host_rate (host, next_at) values ($1, clock_timestamp()) on conflict do nothing`, [host]);
        const row = await one(tx, `select next_at, clock_timestamp() as now from ${S}.host_rate where host=$1 for update`, [host]) as Rec;
        await tx.query(`delete from ${S}.host_leases where host=$1 and expires_at < clock_timestamp()`, [host]);
        const active = Number((await one(tx, `select count(*)::int as n from ${S}.host_leases where host=$1`, [host]) as Rec).n);
        if (active >= maxConcurrent) return null;
        const now = new Date(row.now).getTime(); const start = Math.max(now, new Date(row.next_at).getTime());
        const id = randomUUID();
        await tx.query(`update ${S}.host_rate set next_at=$2 where host=$1`, [host, new Date(start + minIntervalMs).toISOString()]);
        await tx.query(`insert into ${S}.host_leases (id, host, expires_at) values ($1,$2,$3)`, [id, host, new Date(start + fetchPolicy.timeoutMs + 5000).toISOString()]);
        return { id, wait: start - now };
      });
      if (got === null) { await sleep(25); await beat(); continue; }
      let left = got.wait;
      while (left > 0) { const part = Math.min(left, Math.max(50, Math.floor(leaseMs / 3))); await sleep(part); left -= part; if (left > 0) await beat(); }
      return got.id;
    }
  }
  const releaseSlot = (id: string): Promise<unknown> => sql.query(`delete from ${S}.host_leases where id=$1`, [id]);

  type Polite = { outcome: FetchOutcome | null; robots: Rec; skipped: 'robots_disallowed' | null };
  async function limited(source: Rec, url: string, crawlDelayMs: number, request: Parameters<typeof safeFetch>[0], beat: () => Promise<void>): Promise<FetchOutcome> {
    let host: string;
    try { host = vetUrl(url, fetchPolicy).hostPort; } catch { return safeFetch(request, fetchPolicy); }
    const interval = Math.max(int(source.rate_limit?.minIntervalMs, 'minIntervalMs', 0, 3_600_000, cfg.defaultMinIntervalMs ?? 1000), Math.min(crawlDelayMs, cfg.maxCrawlDelayMs ?? 30_000));
    const slot = await acquireSlot(host, interval, int(source.rate_limit?.maxConcurrent, 'maxConcurrent', 1, 16, 1), beat);
    try { return await safeFetch(request, fetchPolicy); } finally { await releaseSlot(slot); }
  }
  async function politeFetch(ctx: ServiceContext, source: Rec, url: string, opts: { headers?: Record<string, string>; maxBytes?: number }, beat: () => Promise<void>): Promise<Polite> {
    let origin: string | null = null; let path = '/';
    try { const v = vetUrl(url, fetchPolicy); origin = v.url.origin; path = `${v.url.pathname}${v.url.search}`; } catch { /* safeFetch reports the refusal */ }
    let robots: Rec = { policy: source.robots_policy, honoured: source.robots_policy === 'honour', allowed: true, rule: null, group: null, crawlDelaySeconds: null, robotsStatus: null, basis: 'not_evaluated' };
    if (origin !== null && source.robots_policy === 'honour') {
      let cached = await one(sql, `select * from ${S}.robots_cache where tenant_id=$1 and project_id=$2 and origin=$3 and expires_at > now()`, [ctx.tenantId, ctx.projectId, origin]);
      if (cached === undefined) {
        const r = await limited(source, `${origin}/robots.txt`, 0, { url: `${origin}/robots.txt`, maxBytes: 512 * 1024 }, beat);
        const outcome = r.ok && r.status !== null && r.status < 300 ? 'rules' : r.status !== null && r.status >= 400 && r.status < 500 ? 'absent' : r.code.startsWith('blocked_') ? 'blocked' : 'unreachable';
        cached = { status: r.status, outcome, body: outcome === 'rules' && r.bytes !== null ? decodeText(r.bytes, r.headers['content-type']).slice(0, 500_000) : '' };
        await sql.query(`insert into ${S}.robots_cache (tenant_id, project_id, origin, fetched_at, expires_at, status, outcome, body) values ($1,$2,$3,now(),now() + ($4::int * interval '1 millisecond'),$5,$6,$7)
          on conflict (tenant_id, project_id, origin) do update set fetched_at=excluded.fetched_at, expires_at=excluded.expires_at, status=excluded.status, outcome=excluded.outcome, body=excluded.body`,
          [ctx.tenantId, ctx.projectId, origin, outcome === 'unreachable' ? 300_000 : cfg.robotsTtlMs ?? 86_400_000, cached.status, outcome, cached.body]);
      }
      if (cached.outcome === 'rules') { const d = robotsDecide(parseRobots(cached.body), fetchPolicy.userAgent, path); robots = { ...robots, ...d, robotsStatus: cached.status, basis: 'robots.txt rules' }; }
      else if (cached.outcome === 'unreachable') robots = { ...robots, allowed: false, robotsStatus: cached.status, basis: 'robots.txt unreachable; treated as disallow (RFC 9309)' };
      else robots = { ...robots, robotsStatus: cached.status, basis: cached.outcome === 'absent' ? 'no robots.txt' : 'robots.txt target refused by address policy' };
      if (robots.allowed === false) return { outcome: null, robots, skipped: 'robots_disallowed' };
    } else if (source.robots_policy === 'ignore') robots.basis = 'robots.txt not consulted by recorded operator decision';
    const credential = decryptCredential(source.credential);
    const outcome = await limited(source, url, Number(robots.crawlDelaySeconds ?? 0) * 1000, { url, ...(opts.headers === undefined ? {} : { headers: opts.headers }), ...(credential === undefined ? {} : { credential }), ...(opts.maxBytes === undefined ? {} : { maxBytes: opts.maxBytes }) }, beat);
    return { outcome, robots, skipped: null };
  }

  // ───────────── receipts ─────────────
  function buildReceipt(ctx: ServiceContext, source: Rec, o: FetchOutcome | null, x: { id?: string; kind?: string; purpose: string; runId?: string | null; itemId?: string | null; robots?: Rec; conditional?: Rec | null; storage?: Rec; outcome?: string; message?: string; requestUrl?: string; sha256?: string; size?: number; mediaType?: string }): Rec {
    const now = new Date().toISOString();
    const r: Rec = {
      tenant_id: ctx.tenantId, project_id: ctx.projectId, id: x.id ?? randomUUID(), kind: x.kind ?? 'http', purpose: x.purpose, source_id: source.id, run_id: x.runId ?? null, item_id: x.itemId ?? null,
      request_url: o?.requestUrl ?? x.requestUrl ?? null, final_url: o?.finalUrl ?? x.requestUrl ?? null, redirect_chain: o?.redirects ?? [], resolved_ip: o?.resolvedIp ?? null, status: o?.status ?? null,
      headers: o?.headers ?? {}, sha256: o?.sha256 ?? x.sha256 ?? null, size: o?.size ?? x.size ?? null, media_type: o?.mediaType ?? x.mediaType ?? null, declared_media_type: o?.declaredMediaType ?? null,
      outcome: x.outcome ?? o?.code ?? 'not_requested', message: (x.message ?? o?.message ?? '').slice(0, 500), robots: x.robots ?? { policy: source.robots_policy, basis: 'not_evaluated' }, conditional: x.conditional ?? null,
      storage: x.storage ?? { kind: 'none', note: 'No bytes were retained for this request' }, reuse: source.reuse, credential_used: o?.credentialSent ?? false, tool,
      started_at: o?.startedAt ?? now, finished_at: o?.finishedAt ?? now, compartment: source.compartment ?? null,
    };
    r.receipt_hash = digest(JSON.parse(JSON.stringify(r)));
    return r;
  }
  async function insertReceipt(tx: Sql, r: Rec): Promise<string> {
    const cols = Object.keys(r); const jsonb = new Set(['redirect_chain', 'headers', 'robots', 'conditional', 'storage', 'tool']);
    await tx.query(`insert into ${S}.receipts (${cols.join(',')}) values (${cols.map((c, i) => `$${i + 1}${jsonb.has(c) ? '::jsonb' : ''}`).join(',')})`, cols.map((c) => (jsonb.has(c) ? JSON.stringify(r[c]) : r[c])));
    return r.id as string;
  }
  async function recordGap(tx: Sql, ctx: ServiceContext, source: Rec, g: { kind: string; expected: string; detail: string; runId?: string | null; itemId?: string | null; receiptId?: string | null }): Promise<void> {
    const id = randomUUID();
    const rows = await tx.query(`insert into ${S}.gaps (tenant_id, project_id, id, source_id, run_id, item_id, kind, expected, detail, receipt_id, compartment, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      on conflict (tenant_id, project_id, source_id, kind, md5(expected)) where state = 'open' do nothing returning id`,
      [ctx.tenantId, ctx.projectId, id, source.id, g.runId ?? null, g.itemId ?? null, g.kind, g.expected.slice(0, 4000), g.detail.slice(0, 1000), g.receiptId ?? null, source.compartment ?? null, ctx.now]);
    if (rows.length > 0) await emit(tx, ctx, 'gap.recorded', ref('gap', id), { kind: g.kind, source: ref('source', source.id) });
  }

  // ───────────── sources ─────────────
  function validateSource(input: SourceInput): Rec {
    nonempty(input.name, 'name', 200); nonempty(input.accessTerms, 'accessTerms', 4000);
    invariant(SOURCE_KINDS.includes(input.kind), 'invalid_input', 'Unknown source kind');
    const reuse = input.reuse ?? 'unknown'; invariant(REUSE.includes(reuse), 'invalid_input', 'Unknown reuse status');
    let baseUrl = '';
    if (input.kind !== 'archive_import' || (input.baseUrl ?? '') !== '') {
      nonempty(input.baseUrl, 'baseUrl', 4000);
      try { baseUrl = vetUrl(input.baseUrl.replace(/\{[A-Za-z?]+\}/g, 'x'), { allowedPrivateHosts: fetchPolicy.allowedPrivateHosts, allowedPorts: fetchPolicy.allowedPorts }) && input.baseUrl; }
      catch (e) { throw new DomainError('invalid_input', e instanceof FetchBlock ? e.message : 'Invalid baseUrl'); }
    }
    const config = input.config ?? {};
    invariant(config !== null && typeof config === 'object' && !Array.isArray(config) && JSON.stringify(config).length <= 100_000, 'invalid_input', 'config must be a JSON object');
    if (config.itemPattern !== undefined) { invariant(typeof config.itemPattern === 'string' && config.itemPattern.length <= 300, 'invalid_input', 'itemPattern must be a short regular expression'); try { new RegExp(config.itemPattern); } catch { throw new DomainError('invalid_input', 'itemPattern is not a valid regular expression'); } }
    const rate = { minIntervalMs: int(input.rateLimit?.minIntervalMs, 'rateLimit.minIntervalMs', 0, 3_600_000, cfg.defaultMinIntervalMs ?? 1000), maxConcurrent: int(input.rateLimit?.maxConcurrent, 'rateLimit.maxConcurrent', 1, 16, 1) };
    const mode = input.refreshPolicy?.mode ?? 'manual'; invariant(mode === 'manual' || mode === 'interval', 'invalid_input', 'Unknown refresh mode');
    const refresh = mode === 'interval' ? { mode, intervalSeconds: int(input.refreshPolicy?.intervalSeconds, 'refreshPolicy.intervalSeconds', 60, 31_536_000, 86_400) } : { mode };
    const permissionRefs = input.permissionRefs ?? []; invariant(Array.isArray(permissionRefs) && permissionRefs.length <= 50, 'invalid_input', 'permissionRefs must be a list'); for (const r of permissionRefs) kit.parseUref(r);
    if (input.compartment !== undefined) nonempty(input.compartment, 'compartment', 128);
    return { name: input.name.trim(), kind: input.kind, base_url: baseUrl, config, access_terms: input.accessTerms, reuse, rate_limit: rate, refresh_policy: refresh, permission_refs: permissionRefs, compartment: input.compartment ?? null };
  }
  const snapshot = (r: Rec): Json => { const { credential: _c, ...rest } = camel(r); return JSON.parse(JSON.stringify({ ...rest, hasCredential: r.credential !== null && r.credential !== undefined })) as Json; };

  async function createSource(ctx: ServiceContext, input: SourceInput): Promise<Rec> {
    kit.requireCapability(ctx, 'discovery:configure');
    const v = validateSource(input); kit.requireCompartment(ctx, v.compartment);
    return sql.tx((tx) => kit.idempotent(tx, S, ctx, input.idempotencyKey, { op: 'createSource', v }, async () => {
      const id = randomUUID();
      const dup = await one(tx, `select 1 from ${S}.sources where tenant_id=$1 and project_id=$2 and name=$3`, [ctx.tenantId, ctx.projectId, v.name]);
      invariant(dup === undefined, 'conflict', 'A source with this name already exists');
      const row = await one(tx, `insert into ${S}.sources (tenant_id, project_id, id, name, kind, base_url, config, access_terms, reuse, rate_limit, refresh_policy, permission_refs, compartment, created_by, created_at, updated_at, next_refresh_at)
        values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14,$15,$15,$16) returning *`,
        [ctx.tenantId, ctx.projectId, id, v.name, v.kind, v.base_url, JSON.stringify(v.config), v.access_terms, v.reuse, JSON.stringify(v.rate_limit), JSON.stringify(v.refresh_policy), v.permission_refs, v.compartment, ctx.actor.id, ctx.now, null]) as Rec;
      await tx.query(`insert into ${S}.source_revisions (tenant_id, project_id, source_id, revision, snapshot, summary, actor_id, at) values ($1,$2,$3,1,$4::jsonb,'registered',$5,$6)`, [ctx.tenantId, ctx.projectId, id, JSON.stringify(snapshot(row)), ctx.actor.id, ctx.now]);
      await audit(tx, ctx, 'source.registered', ref('source', id), { kind: v.kind, reuse: v.reuse });
      await emit(tx, ctx, 'source.registered', ref('source', id, 1), { kind: v.kind });
      return sourcePublic(row) as Json;
    })) as Promise<Rec>;
  }
  async function reviseSource(tx: Sql, ctx: ServiceContext, id: string, set: Rec, summary: string, action: string, detail: Json): Promise<Rec> {
    const cur = await loadSource(tx, ctx, id, true);
    const keys = Object.keys(set); const jsonb = new Set(['config', 'rate_limit', 'refresh_policy', 'credential', 'reasons']);
    const row = await one(tx, `update ${S}.sources set ${keys.map((k, i) => `${k}=$${i + 2}${jsonb.has(k) ? '::jsonb' : ''}`).join(', ')}, revision=revision+1, updated_at=$${keys.length + 2} where id=$1 returning *`,
      [cur.id, ...keys.map((k) => (jsonb.has(k) && set[k] !== null ? JSON.stringify(set[k]) : set[k])), ctx.now]) as Rec;
    await tx.query(`insert into ${S}.source_revisions (tenant_id, project_id, source_id, revision, snapshot, summary, actor_id, at) values ($1,$2,$3,$4,$5::jsonb,$6,$7,$8)`, [ctx.tenantId, ctx.projectId, id, row.revision, JSON.stringify(snapshot(row)), summary, ctx.actor.id, ctx.now]);
    await audit(tx, ctx, action, ref('source', id), detail);
    await emit(tx, ctx, action === 'source.unblocked' ? 'source.unblocked' : 'source.changed', ref('source', id, row.revision), { summary });
    return row;
  }
  async function updateSource(ctx: ServiceContext, id: string, patch: Partial<SourceInput> & { idempotencyKey?: string }): Promise<Rec> {
    kit.requireCapability(ctx, 'discovery:configure');
    return sql.tx((tx) => kit.idempotent(tx, S, ctx, patch.idempotencyKey, { op: 'updateSource', id, patch }, async () => {
      const cur = await loadSource(tx, ctx, id, true);
      const v = validateSource({ name: patch.name ?? cur.name, kind: cur.kind, baseUrl: patch.baseUrl ?? cur.base_url, config: patch.config ?? cur.config, accessTerms: patch.accessTerms ?? cur.access_terms, reuse: patch.reuse ?? cur.reuse,
        rateLimit: patch.rateLimit ?? cur.rate_limit, refreshPolicy: patch.refreshPolicy ?? cur.refresh_policy, permissionRefs: patch.permissionRefs ?? cur.permission_refs, ...(cur.compartment === null ? {} : { compartment: cur.compartment }) });
      invariant(patch.kind === undefined || patch.kind === cur.kind, 'invalid_input', 'Source kind cannot change; register a new source');
      if (cur.credential !== null && v.base_url !== cur.base_url) invariant(new URL(v.base_url).origin === cur.credential.origin, 'invalid_input', 'baseUrl origin cannot change while a credential is stored; remove the credential first');
      const next = v.refresh_policy.mode === 'interval' ? new Date(new Date(cur.last_refresh_at ?? ctx.now).getTime() + v.refresh_policy.intervalSeconds * 1000).toISOString() : null;
      const row = await reviseSource(tx, ctx, id, { name: v.name, base_url: v.base_url, config: v.config, access_terms: v.access_terms, reuse: v.reuse, rate_limit: v.rate_limit, refresh_policy: v.refresh_policy, permission_refs: v.permission_refs, next_refresh_at: next }, 'updated', 'source.updated', { fields: Object.keys(patch).filter((k) => k !== 'idempotencyKey') });
      return sourcePublic(row) as Json;
    })) as Promise<Rec>;
  }
  async function setSourceCredential(ctx: ServiceContext, id: string, input: { header?: string; value: string | null; authorizationNote: string }): Promise<Rec> {
    kit.requireCapability(ctx, 'discovery:admin');
    nonempty(input.authorizationNote, 'authorizationNote', 2000);
    const header = (input.header ?? 'authorization').toLowerCase();
    invariant(/^[a-z][a-z0-9-]{0,39}$/.test(header) && !['host', 'content-length', 'transfer-encoding', 'connection', 'user-agent'].includes(header), 'invalid_input', 'Invalid credential header name');
    if (input.value !== null) invariant(typeof input.value === 'string' && input.value.length > 0 && input.value.length <= 4000 && !/[\r\n]/.test(input.value), 'invalid_input', 'Invalid credential value');
    return sql.tx(async (tx) => {
      const cur = await loadSource(tx, ctx, id, true);
      invariant(cur.base_url !== '', 'invalid_state', 'Source has no base URL to bind a credential to');
      const stored = input.value === null ? null : encryptCredential(header, new URL(cur.base_url.replace(/\{[A-Za-z?]+\}/g, 'x')).origin, input.value);
      const row = await reviseSource(tx, ctx, id, { credential: stored }, input.value === null ? 'credential removed' : 'authorized credential stored', 'source.credential_changed', { present: input.value !== null, header, note: input.authorizationNote });
      return sourcePublic(row);
    });
  }
  async function setRobotsPolicy(ctx: ServiceContext, id: string, input: { policy: 'honour' | 'ignore'; decisionNote: string }): Promise<Rec> {
    kit.requireCapability(ctx, 'discovery:admin');
    invariant(input.policy === 'honour' || input.policy === 'ignore', 'invalid_input', 'policy must be honour or ignore');
    nonempty(input.decisionNote, 'decisionNote', 2000);
    invariant(input.policy === 'honour' || ctx.actor.kind === 'human', 'forbidden', 'Only a human operator may decide that robots.txt is not honoured');
    return sql.tx(async (tx) => sourcePublic(await reviseSource(tx, ctx, id, { robots_policy: input.policy }, `robots policy: ${input.policy}`, 'source.robots_policy_changed', { policy: input.policy, decision: input.decisionNote, decidedBy: ctx.actor.id })));
  }
  async function unblockSource(ctx: ServiceContext, id: string, input: { decisionNote: string; permissionRef?: string }): Promise<Rec> {
    kit.requireCapability(ctx, 'discovery:admin');
    nonempty(input.decisionNote, 'decisionNote', 2000); if (input.permissionRef !== undefined) kit.parseUref(input.permissionRef);
    return sql.tx(async (tx) => {
      const cur = await loadSource(tx, ctx, id, true);
      invariant(cur.blocked === true || cur.stale === true, 'invalid_state', 'Source is not blocked or stale');
      const reasons = [...cur.reasons, { at: ctx.now, cleared: true, by: ctx.actor.id, note: input.decisionNote, ...(input.permissionRef === undefined ? {} : { permissionRef: input.permissionRef }) }];
      return sourcePublic(await reviseSource(tx, ctx, id, { blocked: false, stale: false, reasons }, 'unblocked by operator decision', 'source.unblocked', { decision: input.decisionNote, permissionRef: input.permissionRef ?? null }));
    });
  }
  async function getSource(ctx: ServiceContext, id: string): Promise<Rec> { kit.requireCapability(ctx, 'discovery:read'); return sourcePublic(await loadSource(sql, ctx, id)); }
  async function listSources(ctx: ServiceContext, options: { kind?: string; limit?: number } = {}): Promise<Rec[]> {
    kit.requireCapability(ctx, 'discovery:read');
    return (await sql.query(`select * from ${S}.sources where ${SC} and ($4::text is null or kind=$4) order by created_at, id limit ${int(options.limit, 'limit', 1, 500, 200)}`, [...P(ctx), options.kind ?? null])).map(sourcePublic);
  }

  // ───────────── runs ─────────────
  const runPublic = (r: Rec): Rec => ({ ...camel(r), ref: ref('run', r.id), source: ref('source', r.source_id) });
  const loadRun = async (q: Sql, ctx: ServiceContext, id: string, lock = false): Promise<Rec> => {
    if (!isUuid(id)) return notFound();
    return (await one(q, `select * from ${S}.runs where ${SC} and id=$4${lock ? ' for update' : ''}`, [...P(ctx), id])) ?? notFound();
  };
  function runLimits(o: RunOptions): Rec {
    const level = o.level ?? 'bytes'; invariant(['links', 'metadata', 'bytes'].includes(level), 'invalid_input', 'level must be links, metadata or bytes');
    if (o.questionRef !== undefined) kit.parseUref(o.questionRef);
    return { level, maxPages: int(o.maxPages, 'maxPages', 1, cfg.maxPages ?? 1000, Math.min(100, cfg.maxPages ?? 1000)), maxItems: int(o.maxItems, 'maxItems', 1, cfg.maxItems ?? 50_000, Math.min(5000, cfg.maxItems ?? 50_000)),
      maxTotalBytes: int(o.maxTotalBytes, 'maxTotalBytes', 1, Number.MAX_SAFE_INTEGER, 2 * 1024 * 1024 * 1024), extractLeads: o.extractLeads === undefined || o.extractLeads === false ? null : { why: typeof o.extractLeads === 'object' && typeof o.extractLeads.why === 'string' ? o.extractLeads.why.slice(0, 1000) : null } };
  }
  function requireStorage(level: string): void {
    if (level === 'bytes' && ports.evidence === undefined && objects === undefined) throw new DomainError('unavailable', 'Acquiring original bytes needs an EvidencePort or an ObjectStore; neither is configured');
  }
  async function createRun(tx: Sql, ctx: ServiceContext, source: Rec, kind: string, limits: Rec, queue: string[], extra: { questionRef?: string | undefined; itemIds?: string[] } = {}): Promise<Rec> {
    const id = randomUUID();
    const checkpoint = { phase: extra.itemIds === undefined ? 'pages' : 'items', queue, visited: [] as string[], seq: 0, pagesDone: 0, pageAttempts: 0, pageGaps: 0, bytes: 0, listed: 0, truncated: false, totalReported: null };
    const job = await kit.enqueueJob(tx, S, ctx, { kind: 'discovery.run', payload: { runId: id }, dedupeKey: id, maxAttempts: 25 });
    const row = await one(tx, `insert into ${S}.runs (tenant_id, project_id, id, source_id, kind, state, level, options, checkpoint, job_id, question_ref, compartment, created_by, created_at, updated_at)
      values ($1,$2,$3,$4,$5,'queued',$6,$7::jsonb,$8::jsonb,$9,$10,$11,$12,$13,$13) returning *`,
      [ctx.tenantId, ctx.projectId, id, source.id, kind, limits.level, JSON.stringify({ ...limits, sourceRevision: source.revision }), JSON.stringify(checkpoint), job.id, extra.questionRef ?? null, source.compartment, ctx.actor.id, ctx.now]) as Rec;
    for (const itemId of extra.itemIds ?? []) await tx.query(`insert into ${S}.run_items (tenant_id, project_id, run_id, item_id, seen) values ($1,$2,$3,$4,false) on conflict do nothing`, [ctx.tenantId, ctx.projectId, id, itemId]);
    await audit(tx, ctx, `collection.${kind}_started`, ref('run', id), { source: ref('source', source.id), level: limits.level });
    await emit(tx, ctx, 'collection.started', ref('run', id), { kind, source: ref('source', source.id) });
    return row;
  }
  function rootQueue(source: Rec): string[] {
    if (source.kind === 'file_list' && Array.isArray(source.config.urls)) return [];
    invariant(!['archive_import', 'search_json', 'search_opensearch'].includes(source.kind), 'invalid_state', `A ${source.kind} source is not walked as a collection`);
    return [source.base_url];
  }
  async function startCollection(ctx: ServiceContext, input: { sourceId: string } & RunOptions): Promise<Rec> {
    kit.requireCapability(ctx, 'discovery:acquire');
    const limits = runLimits(input); requireStorage(limits.level);
    if (limits.extractLeads !== null) kit.requireCapability(ctx, 'discovery:write_leads');
    return sql.tx((tx) => kit.idempotent(tx, S, ctx, input.idempotencyKey, { op: 'startCollection', sourceId: input.sourceId, limits, q: input.questionRef ?? null }, async () => {
      const source = await loadSource(tx, ctx, input.sourceId); assertUsable(source);
      return runPublic(await createRun(tx, ctx, source, 'collect', limits, rootQueue(source), { questionRef: input.questionRef })) as Json;
    })) as Promise<Rec>;
  }
  async function refreshSource(ctx: ServiceContext, sourceId: string, input: RunOptions = {}): Promise<Rec> {
    kit.requireCapability(ctx, 'discovery:acquire');
    const limits = runLimits(input); requireStorage(limits.level);
    return sql.tx((tx) => kit.idempotent(tx, S, ctx, input.idempotencyKey, { op: 'refreshSource', sourceId, limits }, async () => {
      const source = await loadSource(tx, ctx, sourceId); assertUsable(source);
      return runPublic(await createRun(tx, ctx, source, 'refresh', limits, rootQueue(source), { questionRef: input.questionRef })) as Json;
    })) as Promise<Rec>;
  }
  async function upsertItem(tx: Sql, ctx: ServiceContext, source: Rec, runId: string, it: { url: string; title: string | null; metadata: Rec }, questionRef: string | null): Promise<{ id: string; inserted: boolean; row: Rec }> {
    const row = await one(tx, `insert into ${S}.items (tenant_id, project_id, id, source_id, url, canonical_url, title, listing, first_run_id, discovered_at, last_seen_at, last_seen_run, question_ref, compartment)
      values ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$10,$9,$11,$12)
      on conflict (tenant_id, project_id, source_id, canonical_url) do update set last_seen_at=excluded.last_seen_at, last_seen_run=excluded.last_seen_run, missing_since=null, title=coalesce(${S}.items.title, excluded.title)
      returning *, (xmax = 0) as inserted`,
      [ctx.tenantId, ctx.projectId, randomUUID(), source.id, it.url.slice(0, 4000), canonicalUrl(it.url).slice(0, 4000), it.title, JSON.stringify(it.metadata), runId, ctx.now, questionRef, source.compartment]) as Rec;
    if (row.inserted === true) await emit(tx, ctx, 'source.discovered', ref('item', row.id), { source: ref('source', source.id), run: ref('run', runId) });
    return { id: row.id, inserted: row.inserted === true, row };
  }
  async function acquire(ctx: ServiceContext, input: { sourceId: string; url?: string; itemId?: string; level?: Level; questionRef?: string; extractLeads?: RunOptions['extractLeads']; idempotencyKey?: string }): Promise<Rec> {
    kit.requireCapability(ctx, 'discovery:acquire');
    const limits = runLimits({ level: input.level ?? 'bytes', ...(input.questionRef === undefined ? {} : { questionRef: input.questionRef }), ...(input.extractLeads === undefined ? {} : { extractLeads: input.extractLeads }) }); requireStorage(limits.level);
    invariant(limits.level !== 'links', 'invalid_input', 'An acquisition is metadata or bytes');
    if (limits.extractLeads !== null) kit.requireCapability(ctx, 'discovery:write_leads');
    invariant((input.url === undefined) !== (input.itemId === undefined), 'invalid_input', 'Give exactly one of url or itemId');
    return sql.tx((tx) => kit.idempotent(tx, S, ctx, input.idempotencyKey, { op: 'acquire', s: input.sourceId, u: input.url ?? null, i: input.itemId ?? null, limits }, async () => {
      const source = await loadSource(tx, ctx, input.sourceId); assertUsable(source);
      let itemId: string;
      if (input.itemId !== undefined) { invariant(isUuid(input.itemId), 'not_found', 'Not found'); const item = await one(tx, `select id from ${S}.items where ${SC} and id=$4 and source_id=$5`, [...P(ctx), input.itemId, source.id]); itemId = (item ?? notFound()).id; }
      else {
        nonempty(input.url, 'url', 4000);
        try { vetUrl(input.url as string, fetchPolicy); } catch (e) { throw new DomainError('invalid_input', e instanceof FetchBlock ? e.message : 'Invalid url'); }
        invariant(inScope(source, input.url as string), 'invalid_input', 'URL host is outside the hosts registered for this source');
        const run0 = randomUUID();
        itemId = (await upsertItem(tx, ctx, source, run0, { url: input.url as string, title: null, metadata: {} }, input.questionRef ?? null)).id;
      }
      const run = await createRun(tx, ctx, source, 'single', limits, [], { questionRef: input.questionRef, itemIds: [itemId] });
      return { ...runPublic(run), item: ref('item', itemId) } as Json;
    })) as Promise<Rec>;
  }
  async function retryFailures(ctx: ServiceContext, input: { sourceId: string; force?: boolean; idempotencyKey?: string }): Promise<Rec | null> {
    kit.requireCapability(ctx, 'discovery:acquire');
    return sql.tx((tx) => kit.idempotent(tx, S, ctx, input.idempotencyKey, { op: 'retryFailures', input }, async () => {
      const source = await loadSource(tx, ctx, input.sourceId); assertUsable(source);
      const due = await tx.query(`select item_id, level from ${S}.failures where tenant_id=$1 and project_id=$2 and source_id=$3 and (state='open' and ($4::boolean or next_retry_at <= $5) or ($4::boolean and state='exhausted')) order by first_at limit 5000`, [ctx.tenantId, ctx.projectId, source.id, input.force === true, ctx.now]);
      if (due.length === 0) return null;
      const level = due.some((d) => d.level === 'bytes') ? 'bytes' : 'metadata'; requireStorage(level);
      if (input.force === true) await tx.query(`update ${S}.failures set state='open', attempts=0 where tenant_id=$1 and project_id=$2 and source_id=$3 and state='exhausted'`, [ctx.tenantId, ctx.projectId, source.id]);
      return runPublic(await createRun(tx, ctx, source, 'retry', runLimits({ level }), [], { itemIds: due.map((d) => d.item_id as string) })) as Json;
    })) as Promise<Rec | null>;
  }
  async function getRun(ctx: ServiceContext, id: string): Promise<Rec> { kit.requireCapability(ctx, 'discovery:read'); return runPublic(await loadRun(sql, ctx, id)); }
  async function listRuns(ctx: ServiceContext, options: { sourceId?: string; state?: string; limit?: number } = {}): Promise<Rec[]> {
    kit.requireCapability(ctx, 'discovery:read');
    return (await sql.query(`select * from ${S}.runs where ${SC} and ($4::uuid is null or source_id=$4) and ($5::text is null or state=$5) order by created_at desc, id limit ${int(options.limit, 'limit', 1, 500, 100)}`, [...P(ctx), isUuid(options.sourceId) ? options.sourceId : options.sourceId === undefined ? null : randomUUID(), options.state ?? null])).map(runPublic);
  }
  async function controlRun(ctx: ServiceContext, id: string, action: 'pause' | 'resume' | 'cancel'): Promise<Rec> {
    kit.requireCapability(ctx, 'discovery:acquire');
    invariant(['pause', 'resume', 'cancel'].includes(action), 'invalid_input', 'action must be pause, resume or cancel');
    return sql.tx(async (tx) => {
      const run = await loadRun(tx, ctx, id, true);
      invariant(!['completed', 'cancelled', 'failed', 'blocked'].includes(run.state), 'invalid_state', `Run is ${run.state}`);
      await kit.controlJob(tx, S, ctx, run.job_id, action);
      const state = action === 'pause' ? 'paused' : action === 'resume' ? 'queued' : 'cancelled';
      const row = await one(tx, `update ${S}.runs set state=$2, updated_at=$3, finished_at=case when $2='cancelled' then $3::timestamptz else finished_at end where id=$1 returning *`, [run.id, state, ctx.now]) as Rec;
      await audit(tx, ctx, `collection.${action}`, ref('run', id), {});
      await emit(tx, ctx, action === 'pause' ? 'collection.paused' : action === 'resume' ? 'collection.resumed' : 'collection.cancelled', ref('run', id), {});
      return runPublic(row);
    });
  }

  // ───────────── dedupe: content families and same-source-family hints ─────────────
  async function assignFamily(tx: Sql, ctx: ServiceContext, a: { sha256: string; size: number; mediaType: string; sketch: number[] | null; canonicalTarget: string | null; itemId: string }): Promise<{ id: string; duplicate: boolean }> {
    await tx.query('select pg_advisory_xact_lock(hashtext($1))', [`e04-family:${ctx.tenantId}:${ctx.projectId}`]);
    const existing = await one(tx, `select id from ${S}.families where tenant_id=$1 and project_id=$2 and sha256=$3`, [ctx.tenantId, ctx.projectId, a.sha256]);
    if (existing !== undefined) {
      const other = await one(tx, `select 1 from ${S}.acquisitions where tenant_id=$1 and project_id=$2 and family_id=$3 and item_id<>$4 limit 1`, [ctx.tenantId, ctx.projectId, existing.id, a.itemId]);
      return { id: existing.id, duplicate: other !== undefined };
    }
    const id = randomUUID(); let sourceFamily = id;
    const hints: Rec[] = [];
    if (a.sketch !== null) {
      const candidates = await tx.query(`select id, source_family, sketch from ${S}.families where tenant_id=$1 and project_id=$2 and sketch && $3::integer[] order by created_at limit 500`, [ctx.tenantId, ctx.projectId, a.sketch]);
      let best: { row: Rec; sim: number } | null = null;
      for (const c of candidates) { const sim = sketchSimilarity(a.sketch, c.sketch as number[]); if (sim >= (cfg.mirrorThreshold ?? 0.5) && (best === null || sim > best.sim)) best = { row: c, sim }; }
      if (best !== null) { sourceFamily = best.row.source_family; hints.push({ other: best.row.id, method: 'text_shingle_similarity', similarity: best.sim }); }
    }
    if (a.canonicalTarget !== null) {
      const target = await one(tx, `select f.id, f.source_family from ${S}.items i join ${S}.families f on f.id = i.family_id where i.tenant_id=$1 and i.project_id=$2 and i.canonical_url=$3 and i.id<>$4 limit 1`, [ctx.tenantId, ctx.projectId, a.canonicalTarget, a.itemId]);
      if (target !== undefined) { if (sourceFamily === id) sourceFamily = target.source_family; hints.push({ other: target.id, method: 'rel_canonical_link', similarity: null }); }
    }
    await tx.query(`insert into ${S}.families (tenant_id, project_id, id, sha256, size, media_type, source_family, sketch, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8::integer[],$9)`, [ctx.tenantId, ctx.projectId, id, a.sha256, a.size, a.mediaType, sourceFamily, a.sketch, ctx.now]);
    for (const h of hints) await tx.query(`insert into ${S}.mirror_hints (tenant_id, project_id, id, family_id, other_family_id, relation, method, similarity, at) values ($1,$2,$3,$4,$5,'same_source_family',$6,$7,$8)`, [ctx.tenantId, ctx.projectId, randomUUID(), id, h.other, h.method, h.similarity, ctx.now]);
    return { id, duplicate: false };
  }

  // ───────────── leads ─────────────
  const leadKey = (l: { personName: string | null; organization: string | null; routes: { kind: string; value: string }[] }): string => digest({ n: (l.personName ?? '').toLowerCase(), o: l.personName === null ? (l.organization ?? '').toLowerCase() : '', r: l.personName === null ? `${l.routes[0]?.kind}:${l.routes[0]?.value.toLowerCase()}` : (l.routes.find((r) => r.kind === 'email')?.value.toLowerCase() ?? `${l.routes[0]?.kind}:${l.routes[0]?.value.toLowerCase()}`) });
  async function storeLead(tx: Sql, ctx: ServiceContext, l: { personName: string | null; role: string | null; organization: string | null; why: string; questionRef: string | null; sourceItemRef: string | null; origin: string; extractor: string | null; confidenceNote: string; compartment: string | null;
    routes: { kind: string; value: string; provenanceRef: string | null; provenanceUrl: string | null; provenanceNote: string | null }[] }): Promise<string> {
    const key = leadKey(l);
    let lead = await one(tx, `select id from ${S}.leads where tenant_id=$1 and project_id=$2 and dedupe_key=$3 for update`, [ctx.tenantId, ctx.projectId, key]);
    const created = lead === undefined;
    if (lead === undefined) {
      lead = await one(tx, `insert into ${S}.leads (tenant_id, project_id, id, dedupe_key, person_name, role, organization, why, question_ref, source_item_ref, origin, extractor, confidence_note, compartment, created_by, created_at, updated_at)
        values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$16) returning id`,
        [ctx.tenantId, ctx.projectId, randomUUID(), key, l.personName, l.role, l.organization, l.why, l.questionRef, l.sourceItemRef, l.origin, l.extractor, l.confidenceNote, l.compartment, ctx.actor.id, ctx.now]) as Rec;
    } else await tx.query(`update ${S}.leads set role=coalesce(role,$2), organization=coalesce(organization,$3), updated_at=$4 where id=$1`, [lead.id, l.role, l.organization, ctx.now]);
    let added = 0;
    for (const r of l.routes) {
      added += (await tx.query(`insert into ${S}.lead_routes (tenant_id, project_id, id, lead_id, kind, value, provenance_ref, provenance_url, provenance_note, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) on conflict (lead_id, kind, value) do nothing returning id`,
        [ctx.tenantId, ctx.projectId, randomUUID(), lead.id, r.kind, r.value.slice(0, 2000), r.provenanceRef, r.provenanceUrl, r.provenanceNote, ctx.now])).length;
    }
    if (created || added > 0) {
      await audit(tx, ctx, created ? 'lead.recorded' : 'lead.route_added', ref('lead', lead.id), { origin: l.origin, extractor: l.extractor, routes: added, provenance: l.sourceItemRef });
      await emit(tx, ctx, 'lead.recorded', ref('lead', lead.id), { created, routesAdded: added, question: l.questionRef });
    }
    return lead.id as string;
  }
  async function storeExtracted(tx: Sql, ctx: ServiceContext, found: ExtractedLead[], x: { acquisitionRef: string; itemRef: string; pageUrl: string; questionRef: string | null; why: string | null; compartment: string | null }): Promise<string[]> {
    const ids: string[] = [];
    for (const f of found) {
      ids.push(await storeLead(tx, ctx, {
        personName: f.personName, role: f.role, organization: f.organization, questionRef: x.questionRef, sourceItemRef: x.itemRef, origin: 'extracted', extractor: f.extractor, compartment: x.compartment,
        why: x.why ?? `Published as a contact on ${x.pageUrl}${f.role === null ? '' : ` (${f.role})`}; relevance to the question has not been assessed`,
        confidenceNote: `Deterministic ${f.extractor} extraction from the cited page; context: "${f.context.slice(0, 200)}". The route is as published and has not been tested; publication of a route proves neither who answers it nor that they know anything.`,
        routes: f.routes.map((r) => ({ kind: r.kind, value: r.value, provenanceRef: x.acquisitionRef, provenanceUrl: x.pageUrl, provenanceNote: `extractor ${f.extractor}` })),
      }));
    }
    return [...new Set(ids)];
  }
  const leadPublic = async (q: Sql, r: Rec): Promise<Rec> => ({
    ...camel(r), ref: ref('lead', r.id),
    routes: (await q.query(`select * from ${S}.lead_routes where tenant_id=$1 and project_id=$2 and lead_id=$3 order by created_at, id`, [r.tenant_id, r.project_id, r.id])).map((x) => ({ ...camel(x), ref: ref('lead_route', x.id) })),
    note: 'Route verification state describes the channel only. identityState and knowledgeState are separate and are never changed by channel verification.',
  });
  async function createLead(ctx: ServiceContext, input: LeadInput): Promise<Rec> {
    kit.requireCapability(ctx, 'discovery:write_leads');
    nonempty(input.why, 'why', 2000);
    invariant(Array.isArray(input.routes) && input.routes.length >= 1 && input.routes.length <= 20, 'invalid_input', 'At least one contact route is required');
    for (const r of input.routes) {
      invariant(['email', 'postal', 'web_form', 'phone', 'other'].includes(r.kind), 'invalid_input', 'Unknown route kind'); nonempty(r.value, 'route value', 2000);
      invariant(r.provenanceRef !== undefined || r.provenanceUrl !== undefined || (r.provenanceNote ?? '').trim() !== '', 'invalid_input', 'Every route needs provenance: where the route was published or who supplied it');
      if (r.provenanceRef !== undefined) kit.parseUref(r.provenanceRef);
    }
    invariant((input.personName ?? input.organization ?? input.role ?? '') !== '', 'invalid_input', 'A lead names a person, role or organization');
    if (input.questionRef !== undefined) kit.parseUref(input.questionRef); if (input.sourceItemRef !== undefined) kit.parseUref(input.sourceItemRef);
    kit.requireCompartment(ctx, input.compartment);
    return sql.tx((tx) => kit.idempotent(tx, S, ctx, input.idempotencyKey, { op: 'createLead', input }, async () => {
      const id = await storeLead(tx, ctx, { personName: input.personName ?? null, role: input.role ?? null, organization: input.organization ?? null, why: input.why, questionRef: input.questionRef ?? null, sourceItemRef: input.sourceItemRef ?? null, origin: 'manual', extractor: null,
        confidenceNote: input.confidenceNote ?? 'Entered manually; not assessed', compartment: input.compartment ?? null,
        routes: input.routes.map((r) => ({ kind: r.kind, value: r.value.trim(), provenanceRef: r.provenanceRef ?? null, provenanceUrl: r.provenanceUrl ?? null, provenanceNote: r.provenanceNote ?? null })) });
      return (await leadPublic(tx, await one(tx, `select * from ${S}.leads where id=$1`, [id]) as Rec)) as Json;
    })) as Promise<Rec>;
  }
  const loadLead = async (q: Sql, ctx: ServiceContext, id: string, lock = false): Promise<Rec> => (isUuid(id) ? await one(q, `select * from ${S}.leads where ${SC} and id=$4${lock ? ' for update' : ''}`, [...P(ctx), id]) : undefined) ?? notFound();
  async function getLead(ctx: ServiceContext, id: string): Promise<Rec> { kit.requireCapability(ctx, 'discovery:read_leads'); return leadPublic(sql, await loadLead(sql, ctx, id)); }
  async function listLeads(ctx: ServiceContext, options: { questionRef?: string; sourceItemRef?: string; limit?: number } = {}): Promise<Rec[]> {
    kit.requireCapability(ctx, 'discovery:read_leads');
    const rows = await sql.query(`select * from ${S}.leads where ${SC} and ($4::text is null or question_ref=$4) and ($5::text is null or source_item_ref=$5) order by created_at, id limit ${int(options.limit, 'limit', 1, 500, 200)}`, [...P(ctx), options.questionRef ?? null, options.sourceItemRef ?? null]);
    return Promise.all(rows.map((r) => leadPublic(sql, r)));
  }
  async function setRouteVerification(ctx: ServiceContext, leadId: string, routeId: string, input: { state: 'unverified' | 'channel_verified' | 'undeliverable' | 'invalid'; note: string }): Promise<Rec> {
    kit.requireCapability(ctx, 'discovery:write_leads');
    invariant(['unverified', 'channel_verified', 'undeliverable', 'invalid'].includes(input.state), 'invalid_input', 'Unknown verification state'); nonempty(input.note, 'note', 2000);
    return sql.tx(async (tx) => {
      const lead = await loadLead(tx, ctx, leadId, true);
      const rows = isUuid(routeId) ? await tx.query(`update ${S}.lead_routes set verification_state=$3, verification_note=$4, verified_at=$5, verified_by=$6 where lead_id=$1 and id=$2 returning id`, [lead.id, routeId, input.state, input.note, ctx.now, ctx.actor.id]) : [];
      if (rows.length === 0) notFound();
      await audit(tx, ctx, 'lead.route_verification_changed', ref('lead', lead.id), { route: ref('lead_route', routeId), state: input.state });
      return leadPublic(tx, lead);
    });
  }
  async function setLeadIdentity(ctx: ServiceContext, leadId: string, input: { identityState: 'unconfirmed' | 'confirmed_by_operator' | 'disputed'; note: string }): Promise<Rec> {
    kit.requireCapability(ctx, 'discovery:write_leads');
    invariant(['unconfirmed', 'confirmed_by_operator', 'disputed'].includes(input.identityState), 'invalid_input', 'Unknown identity state'); nonempty(input.note, 'note', 2000);
    return sql.tx(async (tx) => {
      const lead = await loadLead(tx, ctx, leadId, true);
      const row = await one(tx, `update ${S}.leads set identity_state=$2, identity_note=$3, updated_at=$4 where id=$1 returning *`, [lead.id, input.identityState, input.note, ctx.now]) as Rec;
      await audit(tx, ctx, 'lead.identity_state_changed', ref('lead', lead.id), { state: input.identityState });
      return leadPublic(tx, row);
    });
  }

  // ───────────── storage of originals ─────────────
  function filenameFor(url: string, o: { headers: Readonly<Record<string, string>>; mediaType: string | null }): string {
    const disp = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(o.headers['content-disposition'] ?? '')?.[1];
    let name = disp ?? '';
    if (name === '') { try { name = decodeURIComponent(new URL(url).pathname.split('/').filter((p) => p !== '').pop() ?? ''); } catch { name = ''; } }
    name = name.replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^[._]+/, '').slice(-120);
    return name === '' ? `original.${(o.mediaType ?? 'bin').split('/').pop()?.replace(/[^a-z0-9]/g, '') ?? 'bin'}` : name;
  }
  async function storeOriginal(ctx: ServiceContext, source: Rec, bytes: Uint8Array, x: { sha256: string; mediaType: string; filename: string; origin: Rec; key: string }): Promise<Rec> {
    if (ports.evidence !== undefined) {
      const info = await ports.evidence.accept(ctx, { bytes, mediaType: x.mediaType, filename: x.filename, origin: JSON.parse(JSON.stringify(x.origin)) as Json, ...(source.compartment === null ? {} : { compartment: source.compartment }), idempotencyKey: x.key });
      invariant(info.sha256 === x.sha256, 'conflict', 'Evidence store returned a different digest for the handed-over bytes');
      return { kind: 'evidence_port', evidenceRef: info.ref, note: 'Original bytes were handed to the evidence engine through EvidencePort.accept; this engine keeps no copy' };
    }
    if (objects === undefined) throw new DomainError('unavailable', 'No EvidencePort or ObjectStore is configured for original bytes');
    const key = `${ctx.tenantId}/${ctx.projectId}/discovery/originals/${x.sha256}`;
    if ((await objects.head(key)) === null) await objects.put(key, bytes);
    return { kind: 'object_store', objectKey: key, note: 'No EvidencePort was supplied: original bytes are held in this engine\'s own object store prefix and have NOT been preserved by the evidence engine' };
  }

  // ───────────── worker: one item ─────────────
  type StepEnv = { ctx: () => ServiceContext; job: Job | null; run: Rec; source: Rec; beat: () => Promise<void> };
  async function assertLease(tx: Sql, job: Job | null): Promise<void> {
    if (job === null) return;
    const held = await one(tx, `select 1 from ${S}._jobs where id=$1 and state='leased' and lease_owner=$2 and generation=$3 for share`, [job.id, job.leaseOwner, job.generation]);
    if (held === undefined) throw new DomainError('lease_lost', 'Job lease is no longer held');
  }
  function retryAfterMs(o: FetchOutcome | null): number | null {
    const v = o?.headers['retry-after']; if (v === undefined) return null;
    const ms = /^\d+$/.test(v.trim()) ? Number(v.trim()) * 1000 : Date.parse(v) - Date.now();
    return Number.isFinite(ms) && ms > 0 ? Math.min(ms, 86_400_000) : null;
  }
  function classify(o: FetchOutcome, markers: readonly string[]): { cls: 'ok' | 'unchanged' | 'restricted' | 'not_found' | 'policy' | 'transient'; gap?: string; detail: string } {
    if (o.code === 'not_modified') return { cls: 'unchanged', detail: 'HTTP 304' };
    if (o.code === 'ok') {
      if (o.bytes !== null && o.mediaType !== null && /html/.test(o.mediaType)) { const m = accessMarker(decodeText(o.bytes, o.headers['content-type'], 400_000), markers); if (m !== null) return { cls: 'restricted', gap: 'access_restricted', detail: `Response is an access challenge or restricted page (${m}); not retried and not treated as the document` }; }
      return { cls: 'ok', detail: 'retrieved' };
    }
    if (o.code === 'http_error' && o.status !== null) {
      if (RESTRICTED_STATUS.has(o.status) || o.headers['cf-mitigated'] !== undefined) return { cls: 'restricted', gap: 'access_restricted', detail: `HTTP ${o.status}: access is restricted; no bypass is attempted` };
      if (o.status === 404 || o.status === 410) return { cls: 'not_found', gap: 'not_found', detail: `HTTP ${o.status}` };
      if (TRANSIENT_STATUS.has(o.status) || o.status >= 500) return { cls: 'transient', detail: `HTTP ${o.status}` };
      return { cls: 'not_found', gap: 'unexpected_status', detail: `HTTP ${o.status}` };
    }
    if (o.code === 'blocked_url' || o.code === 'blocked_address') return { cls: 'policy', gap: 'blocked_target', detail: o.message };
    if (o.code === 'too_large' || o.code === 'decompression_limit') return { cls: 'policy', gap: 'too_large', detail: o.message };
    if (o.code === 'too_many_redirects' || o.code === 'redirect_loop' || o.code === 'unsupported_encoding') return { cls: 'policy', gap: o.code, detail: o.message };
    return { cls: 'transient', detail: `${o.code}: ${o.message}` };
  }
  async function settleItem(tx: Sql, env: StepEnv, ctx: ServiceContext, item: Rec, outcome: string, detail: string, x: { receipt?: Rec; acquisitionId?: string | null; duplicate?: boolean; bytes?: number; state?: string | null }): Promise<void> {
    const receiptId = x.receipt === undefined ? null : await insertReceipt(tx, x.receipt);
    await tx.query(`update ${S}.run_items set outcome=$3, detail=$4, acquisition_id=$5, receipt_id=$6, duplicate=$7, at=$8 where run_id=$1 and item_id=$2`, [env.run.id, item.id, outcome, detail.slice(0, 500), x.acquisitionId ?? null, receiptId, x.duplicate === true, ctx.now]);
    await tx.query(`update ${S}.items set last_outcome=$2, state=case when current_acquisition is null and $3::text is not null then $3 else state end where id=$1`, [item.id, outcome, x.state ?? null]);
    if ((x.bytes ?? 0) > 0) await tx.query(`update ${S}.runs set checkpoint=jsonb_set(checkpoint,'{bytes}',to_jsonb((checkpoint->>'bytes')::bigint + $2::bigint)), updated_at=$3 where id=$1`, [env.run.id, x.bytes, ctx.now]);
    else await tx.query(`update ${S}.runs set updated_at=$2 where id=$1`, [env.run.id, ctx.now]);
  }
  async function attemptItem(env: StepEnv, item: Rec): Promise<void> {
    const { source, run } = env;
    const level: 'metadata' | 'bytes' = run.level === 'metadata' ? 'metadata' : 'bytes';
    const itemRef = ref('item', item.id);
    const simple = (outcome: string, detail: string, gap: string | null, state: string | null, receipt?: Rec, event?: string): Promise<void> => sql.tx(async (tx) => {
      await assertLease(tx, env.job); const ctx = env.ctx();
      await settleItem(tx, env, ctx, item, outcome, detail, { ...(receipt === undefined ? {} : { receipt }), state });
      if (gap !== null) await recordGap(tx, ctx, source, { kind: gap, expected: item.canonical_url, detail, runId: run.id, itemId: item.id, receiptId: receipt?.id ?? null });
      await audit(tx, ctx, `item.${outcome}`, itemRef, { detail: detail.slice(0, 300), gap });
      if (event !== undefined) await emit(tx, ctx, event, itemRef, { reason: gap ?? outcome, run: ref('run', run.id) });
    });
    if (item.blocked === true) return simple('skipped_policy', 'Item is blocked by a permission or rights change', null, null, undefined, 'acquisition.blocked');
    if (!inScope(source, item.url)) return simple('skipped_policy', 'URL host is outside the hosts registered for this source; recorded as a discovered link only', 'outside_source_scope', 'skipped_policy');
    const cp = (await one(sql, `select checkpoint from ${S}.runs where id=$1`, [run.id]) as Rec).checkpoint;
    if (Number(cp.bytes) >= Number(run.options.maxTotalBytes)) return simple('skipped_policy', 'Run byte ceiling reached before this item', 'byte_ceiling', null);
    const prior = item.current_acquisition === null ? undefined : await one(sql, `select * from ${S}.acquisitions where id=$1`, [item.current_acquisition]);
    const conditional: Record<string, string> = {};
    if (prior !== undefined && (prior.level === 'bytes' || level === 'metadata') && prior.receipt_id !== null && run.kind !== 'single') { if (item.etag) conditional['if-none-match'] = item.etag; if (item.last_modified) conditional['if-modified-since'] = item.last_modified; }
    const condRecord = Object.keys(conditional).length === 0 ? null : conditional;
    const pf = await politeFetch(env.ctx(), source, item.url, { headers: conditional }, env.beat);
    const receiptId = randomUUID();
    const base = { id: receiptId, purpose: run.kind === 'refresh' ? 'refresh' : 'item', runId: run.id, itemId: item.id, robots: pf.robots, conditional: condRecord };
    if (pf.skipped !== null || pf.outcome === null) return simple('skipped_policy', `robots.txt disallows this path (${pf.robots.rule ?? pf.robots.basis})`, 'robots_disallowed', 'skipped_policy', buildReceipt(env.ctx(), source, null, { ...base, outcome: 'robots_disallowed', requestUrl: item.url, message: String(pf.robots.basis) }), 'acquisition.blocked');
    const o = pf.outcome;
    const c = classify(o, Array.isArray(source.config.accessRestrictionMarkers) ? source.config.accessRestrictionMarkers : []);
    if (c.cls === 'unchanged') return simple('unchanged', 'Not modified since the last acquisition', null, null, buildReceipt(env.ctx(), source, o, base));
    if (c.cls === 'restricted') return simple('access_restricted', c.detail, 'access_restricted', 'access_restricted', buildReceipt(env.ctx(), source, o, { ...base, outcome: 'access_restricted' }), 'acquisition.blocked');
    if (c.cls === 'not_found') return simple('not_found', c.detail, c.gap ?? 'not_found', 'not_found', buildReceipt(env.ctx(), source, o, base));
    if (c.cls === 'policy') return simple('skipped_policy', c.detail, c.gap ?? 'blocked_target', 'skipped_policy', buildReceipt(env.ctx(), source, o, base), c.gap === 'blocked_target' ? 'acquisition.blocked' : undefined);
    if (c.cls === 'transient') {
      return sql.tx(async (tx) => {
        await assertLease(tx, env.job); const ctx = env.ctx();
        const f = await one(tx, `select * from ${S}.failures where item_id=$1 for update`, [item.id]);
        const attempts = f === undefined || f.state === 'resolved' ? 1 : Number(f.attempts) + 1;
        const exhausted = attempts >= (cfg.maxItemAttempts ?? 4);
        const next = exhausted ? null : new Date(Date.now() + Math.max(retryAfterMs(o) ?? 0, (cfg.retryBaseMs ?? 60_000) * 2 ** (attempts - 1))).toISOString();
        const receipt = buildReceipt(ctx, source, o, base);
        await settleItem(tx, env, ctx, item, 'failed', c.detail, { receipt, state: 'failed' });
        await tx.query(`insert into ${S}.failures (tenant_id, project_id, id, item_id, source_id, run_id, reason, detail, attempts, next_retry_at, last_receipt_id, state, level, first_at, last_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14)
          on conflict (item_id) do update set run_id=excluded.run_id, reason=excluded.reason, detail=excluded.detail, attempts=excluded.attempts, next_retry_at=excluded.next_retry_at, last_receipt_id=excluded.last_receipt_id, state=excluded.state, level=excluded.level, last_at=excluded.last_at`,
          [ctx.tenantId, ctx.projectId, randomUUID(), item.id, source.id, run.id, o.code === 'http_error' ? `http_${o.status}` : o.code, c.detail.slice(0, 500), attempts, next, receipt.id, exhausted ? 'exhausted' : 'open', level, ctx.now]);
        if (exhausted) await recordGap(tx, ctx, source, { kind: 'retries_exhausted', expected: item.canonical_url, detail: `${attempts} attempts; last: ${c.detail}`, runId: run.id, itemId: item.id, receiptId: receipt.id });
        await audit(tx, ctx, 'item.failed', itemRef, { reason: c.detail.slice(0, 300), attempts, nextRetryAt: next });
        await emit(tx, ctx, 'acquisition.failed', itemRef, { attempts, exhausted, run: ref('run', run.id) });
      });
    }
    // Successful retrieval.
    const bytes = o.bytes as Uint8Array; const sha256 = o.sha256 as string; const mediaType = o.mediaType as string;
    const sameContent = prior !== undefined && prior.sha256 === sha256 && (prior.level === 'bytes' || level === 'metadata');
    const isText = /html|^text\/|xml/.test(mediaType);
    const text = isText ? decodeText(bytes, o.headers['content-type']) : null;
    const root = text !== null && /html/.test(mediaType) ? parseHtml(text) : null;
    const meta: Rec = root !== null ? pageMetadata(root, o.finalUrl) : {};
    if (o.declaredMediaType !== null && o.declaredMediaType !== mediaType) { meta.declaredMediaType = o.declaredMediaType; meta.mediaTypeMismatch = true; }
    const acquisitionId = randomUUID(); const revision = prior === undefined ? 1 : Number(prior.revision) + 1;
    const origin: Rec = { kind: 'discovery', receipt: ref('receipt', receiptId), url: o.finalUrl, requestUrl: o.requestUrl, retrievedAt: o.finishedAt, sha256, source: ref('source', source.id, source.revision), item: itemRef, acquisition: ref('acquisition', acquisitionId, revision), reuse: source.reuse, accessTerms: source.access_terms,
      ...(prior?.evidence_ref ? { previousEvidenceRef: prior.evidence_ref, changedContent: true } : {}) };
    let storage: Rec = { kind: 'none', note: level === 'metadata' ? 'Metadata-level acquisition: the response was read to describe the document; its bytes were not retained' : 'Content unchanged; bytes already held' };
    if (!sameContent && level === 'bytes') {
      try { storage = await storeOriginal(env.ctx(), source, bytes, { sha256, mediaType, filename: filenameFor(o.finalUrl, o), origin, key: `e04-${item.id}-${sha256}` }); }
      catch (error) {
        if (error instanceof DomainError && error.code === 'lease_lost') throw error;
        const detail = `Storing the original failed: ${error instanceof DomainError ? error.code : 'storage_error'}`;
        return sql.tx(async (tx) => {
          await assertLease(tx, env.job); const ctx = env.ctx();
          const receipt = buildReceipt(ctx, source, o, { ...base, outcome: 'storage_failed', message: detail });
          const f = await one(tx, `select * from ${S}.failures where item_id=$1 for update`, [item.id]);
          const attempts = f === undefined || f.state === 'resolved' ? 1 : Number(f.attempts) + 1; const exhausted = attempts >= (cfg.maxItemAttempts ?? 4);
          await settleItem(tx, env, ctx, item, 'failed', detail, { receipt, state: 'failed' });
          await tx.query(`insert into ${S}.failures (tenant_id, project_id, id, item_id, source_id, run_id, reason, detail, attempts, next_retry_at, last_receipt_id, state, level, first_at, last_at) values ($1,$2,$3,$4,$5,$6,'storage_failed',$7,$8,$9,$10,$11,'bytes',$12,$12)
            on conflict (item_id) do update set run_id=excluded.run_id, reason=excluded.reason, detail=excluded.detail, attempts=excluded.attempts, next_retry_at=excluded.next_retry_at, last_receipt_id=excluded.last_receipt_id, state=excluded.state, last_at=excluded.last_at`,
            [ctx.tenantId, ctx.projectId, randomUUID(), item.id, source.id, run.id, detail, attempts, exhausted ? null : new Date(Date.now() + (cfg.retryBaseMs ?? 60_000) * 2 ** (attempts - 1)).toISOString(), receipt.id, exhausted ? 'exhausted' : 'open', ctx.now]);
          await audit(tx, ctx, 'item.failed', itemRef, { reason: detail, attempts });
          await emit(tx, ctx, 'acquisition.failed', itemRef, { attempts, exhausted, run: ref('run', run.id) });
        });
      }
    }
    const leads = run.options.extractLeads !== null && run.options.extractLeads !== undefined && root !== null && text !== null ? extractLeads(text, o.finalUrl, { ...(Array.isArray(source.config.contactTerms) ? { contactTerms: source.config.contactTerms } : {}) }) : [];
    const sketch = sameContent || text === null ? null : shingleSketch(root !== null ? mainText(root) : text);
    await sql.tx(async (tx) => {
      await assertLease(tx, env.job); const ctx = env.ctx();
      const resolve = async (): Promise<void> => {
        await tx.query(`update ${S}.failures set state='resolved', next_retry_at=null, last_at=$2 where item_id=$1 and state<>'resolved'`, [item.id, ctx.now]);
        await tx.query(`update ${S}.gaps set state='resolved', resolved_at=$4, resolution='acquired' where tenant_id=$1 and project_id=$2 and state='open' and (item_id=$3 or (source_id=$5 and kind='expected_unresolved' and expected=$6))`, [ctx.tenantId, ctx.projectId, item.id, ctx.now, source.id, item.canonical_url]);
      };
      if (sameContent) {
        await settleItem(tx, env, ctx, item, 'unchanged', 'Content digest equals the last acquisition', { receipt: buildReceipt(ctx, source, o, { ...base, storage }) });
        await tx.query(`update ${S}.items set etag=$2, last_modified=$3 where id=$1`, [item.id, o.headers.etag ?? null, o.headers['last-modified'] ?? null]);
        return resolve();
      }
      const family = await assignFamily(tx, ctx, { sha256, size: o.size as number, mediaType, sketch, canonicalTarget: typeof meta.canonicalLink === 'string' && canonicalUrl(meta.canonicalLink) !== item.canonical_url ? canonicalUrl(meta.canonicalLink) : null, itemId: item.id });
      const receipt = buildReceipt(ctx, source, o, { ...base, storage });
      await settleItem(tx, env, ctx, item, level, level === 'bytes' ? 'Original bytes acquired' : 'Metadata acquired; bytes not retained', { receipt, acquisitionId, duplicate: family.duplicate, bytes: level === 'bytes' ? o.size as number : 0 });
      await tx.query(`insert into ${S}.acquisitions (tenant_id, project_id, id, item_id, source_id, run_id, revision, level, sha256, size, media_type, storage, evidence_ref, object_key, family_id, reuse, access_terms, receipt_id, metadata, origin, changed, supersedes, compartment, acquired_at)
        values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19::jsonb,$20::jsonb,$21,$22,$23,$24)`,
        [ctx.tenantId, ctx.projectId, acquisitionId, item.id, source.id, run.id, revision, level, sha256, o.size, mediaType, storage.kind, storage.evidenceRef ?? null, storage.objectKey ?? null, family.id, source.reuse, source.access_terms, receipt.id, JSON.stringify(meta), JSON.stringify(origin), prior !== undefined && prior.sha256 !== sha256, prior?.id ?? null, source.compartment, ctx.now]);
      await tx.query(`update ${S}.items set current_acquisition=$2, family_id=$3, etag=$4, last_modified=$5, state=$6, title=coalesce($7, title), stale=false where id=$1`, [item.id, acquisitionId, family.id, o.headers.etag ?? null, o.headers['last-modified'] ?? null, level === 'bytes' ? 'bytes_acquired' : 'metadata_acquired', typeof meta.title === 'string' ? meta.title : null]);
      await resolve();
      const acqRef = ref('acquisition', acquisitionId, revision);
      if (leads.length > 0) await storeExtracted(tx, ctx, leads, { acquisitionRef: acqRef, itemRef, pageUrl: o.finalUrl, questionRef: run.question_ref ?? item.question_ref ?? null, why: run.options.extractLeads?.why ?? null, compartment: source.compartment });
      await audit(tx, ctx, 'acquisition.recorded', acqRef, { item: itemRef, level, sha256, size: o.size, storage: storage.kind, reuse: source.reuse, receipt: ref('receipt', receipt.id) });
      await emit(tx, ctx, 'acquisition.completed', acqRef, { item: itemRef, level, sha256, changed: prior !== undefined && prior.sha256 !== sha256, supersedes: prior === undefined ? null : ref('acquisition', prior.id, prior.revision), evidenceRef: storage.evidenceRef ?? null, duplicateOfExistingContent: family.duplicate, reuse: source.reuse });
    });
  }

  // ───────────── worker: one index page ─────────────
  function parseListing(source: Rec, o: FetchOutcome): Listing {
    const text = decodeText(o.bytes as Uint8Array, o.headers['content-type']);
    const c = source.config as Rec;
    switch (source.kind as SourceKind) {
      case 'html_index': { const l = htmlListing(text, o.finalUrl, { ...(typeof c.itemPattern === 'string' ? { itemPattern: c.itemPattern } : {}), ...(c.linkScope === 'any' ? { linkScope: 'any' as const } : {}) }); const h = linkHeaderNext(o.headers.link, o.finalUrl); if (h !== null && !l.next.includes(h)) l.next.push(h); return l; }
      case 'sitemap': return sitemapListing(text, o.finalUrl);
      case 'feed': case 'search_opensearch': return feedListing(text, o.finalUrl);
      case 'json_api': case 'search_json': return jsonListing(text, o.finalUrl, c, o.headers.link);
      case 'file_list': return { items: text.split(/\r?\n/).map((l) => l.trim()).filter((l) => /^https?:\/\//i.test(l)).slice(0, 50_000).map((url) => ({ url, title: null, metadata: {} })), next: [] };
      default: return { items: [], next: [] };
    }
  }
  async function stepPage(env: StepEnv, cp: Rec): Promise<void> {
    const { source, run } = env; const url = cp.queue[0] as string;
    const purpose = run.kind === 'search' ? 'search' : 'index_page';
    const advance = async (tx: Sql, ctx: ServiceContext, next: Rec): Promise<void> => {
      const ok = await tx.query(`update ${S}.runs set checkpoint=$2::jsonb, updated_at=$4 where id=$1 and (checkpoint->>'seq')::int=$3 returning id`, [run.id, JSON.stringify(next), cp.seq, ctx.now]);
      if (ok.length === 0) throw new DomainError('lease_lost', 'Checkpoint was advanced by another worker');
    };
    const drop = (outcome: string, gap: string, detail: string, receipt?: Rec): Promise<void> => sql.tx(async (tx) => {
      await assertLease(tx, env.job); const ctx = env.ctx();
      const receiptId = receipt === undefined ? null : await insertReceipt(tx, receipt);
      await tx.query(`insert into ${S}.run_pages (tenant_id, project_id, run_id, seq, url, receipt_id, outcome, at) values ($1,$2,$3,$4,$5,$6,$7,$8)`, [ctx.tenantId, ctx.projectId, run.id, cp.seq, url, receiptId, outcome, ctx.now]);
      await recordGap(tx, ctx, source, { kind: gap, expected: url, detail: `Index page: ${detail}`, runId: run.id, receiptId });
      await audit(tx, ctx, 'collection.page_gap', ref('run', run.id), { gap, detail: detail.slice(0, 300) });
      await advance(tx, ctx, { ...cp, queue: cp.queue.slice(1), seq: cp.seq + 1, pageAttempts: 0, pageGaps: cp.pageGaps + 1, lastError: detail.slice(0, 300) });
    });
    if (!inScope(source, url)) return drop('skipped_policy', 'outside_source_scope', 'page host is outside the hosts registered for this source');
    const pf = await politeFetch(env.ctx(), source, url, { maxBytes: Math.min(fetchPolicy.maxBytes, 16 * 1024 * 1024) }, env.beat);
    const base = { purpose, runId: run.id, robots: pf.robots };
    if (pf.outcome === null) return drop('skipped_policy', 'robots_disallowed', `robots.txt disallows this path (${pf.robots.rule ?? pf.robots.basis})`, buildReceipt(env.ctx(), source, null, { ...base, outcome: 'robots_disallowed', requestUrl: url }));
    const o = pf.outcome; const c = classify(o, Array.isArray(source.config.accessRestrictionMarkers) ? source.config.accessRestrictionMarkers : []);
    if (c.cls === 'transient') {
      const attempts = Number(cp.pageAttempts) + 1;
      if (attempts >= (cfg.maxPageAttempts ?? 3)) return drop('unavailable', 'page_unavailable', `${c.detail} after ${attempts} attempts`, buildReceipt(env.ctx(), source, o, base));
      await sql.tx(async (tx) => { await assertLease(tx, env.job); const ctx = env.ctx(); await insertReceipt(tx, buildReceipt(ctx, source, o, base)); await tx.query(`update ${S}.runs set checkpoint=jsonb_set(checkpoint,'{pageAttempts}',$2::jsonb), updated_at=$3 where id=$1 and (checkpoint->>'seq')::int=$4`, [run.id, String(attempts), ctx.now, cp.seq]); });
      let wait = Math.min(Math.max(retryAfterMs(o) ?? 0, (cfg.pageRetryBaseMs ?? 2000) * 2 ** (attempts - 1)), 60_000);
      while (wait > 0) { const part = Math.min(wait, Math.max(50, Math.floor(leaseMs / 3))); await sleep(part); wait -= part; await env.beat(); }
      return;
    }
    if (c.cls !== 'ok') return drop(c.cls === 'restricted' ? 'access_restricted' : c.cls === 'not_found' ? 'not_found' : 'skipped_policy', c.gap ?? 'page_unavailable', c.detail, buildReceipt(env.ctx(), source, o, { ...base, ...(c.cls === 'restricted' ? { outcome: 'access_restricted' } : {}) }));
    let listing: Listing;
    try { listing = parseListing(source, o); } catch { return drop('unparseable', 'unparseable_page', `page could not be parsed as ${source.kind}`, buildReceipt(env.ctx(), source, o, base)); }
    await sql.tx(async (tx) => {
      await assertLease(tx, env.job); const ctx = env.ctx();
      const receipt = buildReceipt(ctx, source, o, base); await insertReceipt(tx, receipt);
      let listed = Number(cp.listed); let added = 0; let fresh = 0; let truncated = cp.truncated === true;
      const listingIsMetadata = (source.kind === 'json_api' || source.kind === 'search_json' || source.kind === 'feed' || source.kind === 'search_opensearch') && source.config.listingIsMetadata !== false;
      for (const it of listing.items) {
        if (listed >= Number(run.options.maxItems)) { truncated = true; break; }
        const up = await upsertItem(tx, ctx, source, run.id, it, run.question_ref ?? null);
        const hasMeta = listingIsMetadata && (it.title !== null || Object.keys(it.metadata).length > 0);
        let acqId: string | null = null;
        if (hasMeta && up.row.current_acquisition === null) {
          acqId = randomUUID(); const md = { title: it.title, ...it.metadata, fromListing: true };
          await tx.query(`insert into ${S}.acquisitions (tenant_id, project_id, id, item_id, source_id, run_id, revision, level, sha256, size, media_type, storage, reuse, access_terms, receipt_id, metadata, origin, compartment, acquired_at)
            values ($1,$2,$3,$4,$5,$6,1,'metadata',$7,$8,'application/json','none',$9,$10,$11,$12::jsonb,$13::jsonb,$14,$15)`,
            [ctx.tenantId, ctx.projectId, acqId, up.id, source.id, run.id, digest(JSON.parse(JSON.stringify(md))), Buffer.byteLength(canonical(JSON.parse(JSON.stringify(md)))), source.reuse, source.access_terms, receipt.id, JSON.stringify(md), JSON.stringify({ kind: 'discovery', receipt: ref('receipt', receipt.id), url: o.finalUrl, retrievedAt: o.finishedAt, listingRecord: true }), source.compartment, ctx.now]);
          await tx.query(`update ${S}.items set current_acquisition=$2, state='metadata_acquired' where id=$1`, [up.id, acqId]);
        }
        const initial = run.level === 'links' ? (hasMeta ? 'metadata' : 'link_only') : run.level === 'metadata' && hasMeta && run.kind !== 'refresh' ? 'metadata' : 'pending';
        const ins = await tx.query(`insert into ${S}.run_items (tenant_id, project_id, run_id, item_id, page_seq, is_new, outcome, acquisition_id, receipt_id, detail, at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) on conflict (run_id, item_id) do nothing returning item_id`,
          [ctx.tenantId, ctx.projectId, run.id, up.id, cp.seq, up.inserted, initial, acqId, initial === 'pending' ? null : receipt.id, initial === 'metadata' ? 'Record metadata taken from the listing; the document itself was not retrieved' : initial === 'link_only' ? 'Discovered link only' : null, initial === 'pending' ? null : ctx.now]);
        if (ins.length > 0) { listed++; added++; if (up.inserted) fresh++; }
      }
      const visited = new Set<string>(cp.visited as string[]); visited.add(digest(canonicalUrl(url)).slice(0, 16));
      const queue = (cp.queue as string[]).slice(1);
      for (const n of listing.next) { const k = digest(canonicalUrl(n)).slice(0, 16); if (!visited.has(k) && !queue.includes(n) && queue.length < 10_000) queue.push(n); }
      await tx.query(`insert into ${S}.run_pages (tenant_id, project_id, run_id, seq, url, receipt_id, outcome, item_count, new_item_count, at) values ($1,$2,$3,$4,$5,$6,'ok',$7,$8,$9)`, [ctx.tenantId, ctx.projectId, run.id, cp.seq, url, receipt.id, added, fresh, ctx.now]);
      await advance(tx, ctx, { ...cp, queue: truncated ? [] : queue, visited: [...visited].slice(-20_000), seq: cp.seq + 1, pagesDone: cp.pagesDone + 1, pageAttempts: 0, listed, truncated, unvisited: truncated ? queue.length : 0, totalReported: listing.total ?? cp.totalReported ?? null });
      if (truncated) await recordGap(tx, ctx, source, { kind: 'item_limit_reached', expected: url, detail: `Run stopped listing at maxItems=${run.options.maxItems}; later entries were not enumerated`, runId: run.id });
    });
  }

  // ───────────── worker: run loop ─────────────
  async function runCoverageRow(q: Sql, run: Rec): Promise<Coverage> {
    const counts: Rec = {}; let total = 0;
    for (const r of await q.query(`select outcome, count(*)::int as n from ${S}.run_items where run_id=$1 group by outcome`, [run.id])) { counts[r.outcome as string] = r.n; total += r.n as number; }
    const extra = await one(q, `select count(*) filter (where is_new)::int as fresh, count(*) filter (where duplicate)::int as dup from ${S}.run_items where run_id=$1`, [run.id]) as Rec;
    const byKind: Record<string, number> = {}; let open = 0;
    for (const g of await q.query(`select kind, count(*)::int as n from ${S}.gaps where tenant_id=$1 and project_id=$2 and state='open' and (run_id=$3 or (source_id=$4 and kind='expected_unresolved')) group by kind`, [run.tenant_id, run.project_id, run.id, run.source_id])) { byKind[g.kind as string] = g.n as number; open += g.n as number; }
    const pages = await one(q, `select count(*) filter (where outcome='ok')::int as ok, count(*) filter (where outcome<>'ok')::int as bad from ${S}.run_pages where run_id=$1`, [run.id]) as Rec;
    const fam = await one(q, `select count(distinct f.source_family)::int as n from ${S}.run_items ri join ${S}.acquisitions a on a.id=ri.acquisition_id join ${S}.families f on f.id=a.family_id where ri.run_id=$1`, [run.id]) as Rec;
    const cp = run.checkpoint as Rec;
    return {
      scope: 'run', ref: ref('run', run.id), state: run.state, discovered: total, linkOnly: counts.link_only ?? 0, acquiredMetadata: counts.metadata ?? 0, acquiredBytes: counts.bytes ?? 0, unchanged: counts.unchanged ?? 0, failed: counts.failed ?? 0,
      skippedByPolicy: counts.skipped_policy ?? 0, accessRestricted: counts.access_restricted ?? 0, notFound: counts.not_found ?? 0, pending: counts.pending ?? 0, newItems: extra.fresh, duplicateContent: extra.dup,
      gaps: { open, byKind }, pages: { fetched: pages.ok, unavailable: pages.bad }, independentSourceFamilies: fam.n, bytesAcquired: Number(cp.bytes ?? 0),
      lastCheckpoint: { phase: cp.phase, pagesDone: cp.pagesDone, seq: cp.seq, queued: (cp.queue ?? []).length, truncated: cp.truncated === true, updatedAt: new Date(run.updated_at).toISOString() },
      note: 'discovered = linkOnly + acquiredMetadata + acquiredBytes + unchanged + failed + skippedByPolicy + accessRestricted + notFound + pending. Only acquiredBytes are held originals; identical or mirrored content counts once in independentSourceFamilies.',
    };
  }
  async function finishRun(env: StepEnv, state: string, error: string | null): Promise<Rec> {
    return sql.tx(async (tx) => {
      await assertLease(tx, env.job); const ctx = env.ctx();
      const run = await one(tx, `select * from ${S}.runs where id=$1 for update`, [env.run.id]) as Rec; const source = env.source;
      let missing = 0;
      if (state === 'completed' && run.kind === 'refresh' && Number(run.checkpoint.pageGaps) === 0 && run.checkpoint.truncated !== true) {
        missing = (await tx.query(`update ${S}.items i set missing_since=$4 where i.tenant_id=$1 and i.project_id=$2 and i.source_id=$3 and i.missing_since is null and not exists (select 1 from ${S}.run_items ri where ri.run_id=$5 and ri.item_id=i.id and ri.seen) returning id`, [ctx.tenantId, ctx.projectId, source.id, ctx.now, run.id])).length;
      }
      const done = await one(tx, `update ${S}.runs set state=$2, error=$3, finished_at=$4, updated_at=$4, checkpoint=jsonb_set(checkpoint,'{phase}','"done"') where id=$1 returning *`, [run.id, state, error, ctx.now]) as Rec;
      const cov = await runCoverageRow(tx, done);
      const changed = Number((await one(tx, `select count(*)::int as n from ${S}.acquisitions where run_id=$1 and changed`, [run.id]) as Rec).n);
      const summary = { discovered: cov.discovered, newItems: cov.newItems, acquiredBytes: cov.acquiredBytes, acquiredMetadata: cov.acquiredMetadata, unchanged: cov.unchanged, changed, missing, failed: cov.failed, gaps: cov.gaps.open };
      await tx.query(`update ${S}.runs set summary=$2::jsonb where id=$1`, [run.id, JSON.stringify(summary)]);
      if (run.kind === 'search') {
        const failed = Number(run.checkpoint.pagesDone) === 0;
        await tx.query(`update ${S}.search_attempts set state=$2, result_count=$3, total_reported=$4, error=$5, finished_at=$6 where run_id=$1`, [run.id, state !== 'completed' || failed ? 'failed' : 'completed', failed ? null : cov.discovered, run.checkpoint.totalReported ?? null, state !== 'completed' ? error : failed ? String(run.checkpoint.lastError ?? 'search request did not succeed') : null, ctx.now]);
        const att = await one(tx, `select id, question_ref from ${S}.search_attempts where run_id=$1`, [run.id]);
        if (att !== undefined) await emit(tx, ctx, 'search.attempted', ref('search_attempt', att.id), { results: failed ? null : cov.discovered, succeeded: !failed && state === 'completed', question: att.question_ref });
      }
      if (state === 'completed' && (run.kind === 'refresh' || run.kind === 'collect')) {
        const next = source.refresh_policy.mode === 'interval' ? new Date(Date.now() + Number(source.refresh_policy.intervalSeconds) * 1000).toISOString() : null;
        await tx.query(`update ${S}.sources set last_refresh_at=$2, next_refresh_at=$3 where id=$1`, [source.id, ctx.now, next]);
      }
      await audit(tx, ctx, `collection.${state}`, ref('run', run.id), summary as Json);
      await emit(tx, ctx, state === 'blocked' ? 'acquisition.blocked' : 'collection.completed', ref('run', run.id), { state, ...summary, ...(error === null ? {} : { reason: error }) } as Json);
      if (state === 'completed' && (cov.newItems > 0 || changed > 0 || missing > 0) && run.kind !== 'search') await emit(tx, ctx, 'collection.changed', ref('source', source.id), { run: ref('run', run.id), added: cov.newItems, changed, missing });
      return { state, ...summary };
    });
  }
  async function processRun(job: Job): Promise<Json> {
    const base = job.ctx;
    kit.requireCapability(base, 'discovery:acquire');
    const ctx = (): ServiceContext => ({ ...base, now: new Date().toISOString() });
    const runId = (job.payload as Rec).runId as string;
    const run = await one(sql, `select * from ${S}.runs where tenant_id=$1 and project_id=$2 and id=$3`, [base.tenantId, base.projectId, runId]);
    if (run === undefined) throw new DomainError('not_found', 'Run not found');
    if (['completed', 'cancelled', 'failed', 'blocked'].includes(run.state)) return { state: run.state };
    const source = await one(sql, `select * from ${S}.sources where tenant_id=$1 and project_id=$2 and id=$3`, [base.tenantId, base.projectId, run.source_id]) as Rec;
    const beat = async (): Promise<void> => { await kit.heartbeatJob(sql, S, job, leaseMs); };
    const env: StepEnv = { ctx, job, run, source, beat };
    if (source.blocked === true) return finishRun(env, 'blocked', 'Source is blocked by a permission or rights change') as Promise<Json>;
    if (ports.authorization !== undefined) {
      let allowed = false; let reason = 'authorization unavailable';
      try { const d = await ports.authorization.authorize(ctx(), { capability: 'discovery:acquire', resource: ref('source', source.id) }); allowed = d.allowed === true; reason = d.reason; } catch { allowed = false; }
      if (!allowed) return finishRun(env, 'blocked', `Authorization re-check denied: ${String(reason).slice(0, 200)}`) as Promise<Json>;
    }
    if (ports.useDecision !== undefined && run.level !== 'links') {
      const d = await ports.useDecision.decide(ctx(), { subjects: [ref('source', source.id), ...(source.permission_refs as string[])], action: 'preserve', purpose: base.purpose });
      if (d.decision !== 'allow') return finishRun(env, 'blocked', `Use decision is ${d.decision}: ${d.reasons.join('; ').slice(0, 300)}`) as Promise<Json>;
    }
    await sql.tx(async (tx) => { await assertLease(tx, job); await tx.query(`update ${S}.runs set state='running', started_at=coalesce(started_at,$2), updated_at=$2 where id=$1`, [run.id, new Date().toISOString()]); });
    for (;;) {
      await beat();
      const cur = await one(sql, `select checkpoint from ${S}.runs where id=$1`, [run.id]) as Rec; const cp = cur.checkpoint as Rec;
      if (cp.phase === 'pages') {
        if (run.kind !== 'search' && source.kind === 'file_list' && Array.isArray(source.config.urls) && cp.seq === 0) {
          await sql.tx(async (tx) => {
            await assertLease(tx, job); const c = ctx(); let listed = 0;
            for (const u of (source.config.urls as unknown[]).filter((x): x is string => typeof x === 'string').slice(0, Number(run.options.maxItems))) {
              const up = await upsertItem(tx, c, source, run.id, { url: u, title: null, metadata: {} }, run.question_ref ?? null);
              listed += (await tx.query(`insert into ${S}.run_items (tenant_id, project_id, run_id, item_id, page_seq, is_new, outcome, detail, at) values ($1,$2,$3,$4,0,$5,$6,$7,$8) on conflict do nothing returning item_id`, [c.tenantId, c.projectId, run.id, up.id, up.inserted, run.level === 'links' ? 'link_only' : 'pending', run.level === 'links' ? 'Discovered link only' : null, run.level === 'links' ? c.now : null])).length;
            }
            await tx.query(`update ${S}.runs set checkpoint=$2::jsonb, updated_at=$3 where id=$1 and (checkpoint->>'seq')::int=0`, [run.id, JSON.stringify({ ...cp, seq: 1, listed }), c.now]);
          });
          continue;
        }
        if ((cp.queue as string[]).length > 0 && Number(cp.pagesDone) + Number(cp.pageGaps) >= Number(run.options.maxPages)) {
          await sql.tx(async (tx) => { await assertLease(tx, job); const c = ctx(); await recordGap(tx, c, source, { kind: 'page_limit_reached', expected: cp.queue[0], detail: `Run stopped at maxPages=${run.options.maxPages}; ${cp.queue.length} listed page(s) were not visited`, runId: run.id }); await tx.query(`update ${S}.runs set checkpoint=$2::jsonb where id=$1`, [run.id, JSON.stringify({ ...cp, unvisited: cp.queue.length, queue: [], truncated: true })]); });
          continue;
        }
        if ((cp.queue as string[]).length === 0) {
          await sql.tx(async (tx) => {
            await assertLease(tx, job); const c = ctx();
            if (run.kind === 'refresh') await tx.query(`insert into ${S}.run_items (tenant_id, project_id, run_id, item_id, seen) select $1,$2,$3,i.id,false from ${S}.items i where i.tenant_id=$1 and i.project_id=$2 and i.source_id=$4 and i.current_acquisition is not null on conflict do nothing`, [c.tenantId, c.projectId, run.id, source.id]);
            await tx.query(`update ${S}.runs set checkpoint=jsonb_set(checkpoint,'{phase}','"items"'), updated_at=$2 where id=$1`, [run.id, c.now]);
          });
          continue;
        }
        await stepPage(env, cp);
      } else if (cp.phase === 'items') {
        const next = await one(sql, `select i.* from ${S}.run_items ri join ${S}.items i on i.id=ri.item_id where ri.run_id=$1 and ri.outcome='pending' order by ri.seq limit 1`, [run.id]);
        if (next === undefined) return finishRun(env, 'completed', null) as Promise<Json>;
        await attemptItem(env, next);
      } else return { state: 'completed' };
    }
  }
  async function runWorkerOnce(options: { limit?: number } = {}): Promise<number> {
    return kit.runJobsOnce(sql, S, { 'discovery.run': processRun }, { worker: workerId, limit: options.limit ?? 1, leaseMs });
  }
  /** Enqueues refresh runs whose interval has elapsed and retry runs for failures that are due. Returns the runs created. */
  async function runDueWork(now: Date = new Date()): Promise<string[]> {
    const created: string[] = [];
    const svc = (r: Rec, purpose: string): ServiceContext => ({ tenantId: r.tenant_id, projectId: r.project_id, purpose, requestId: randomUUID(), now: new Date().toISOString(), actor: { id: 'discovery-scheduler', kind: 'service', roles: [] }, capabilities: ['discovery:acquire'], compartments: r.compartment === null ? [] : [r.compartment] });
    const active = `not exists (select 1 from ${S}.runs r where r.source_id=s.id and r.state in ('queued','running','paused'))`;
    for (const s of await sql.query(`select s.* from ${S}.sources s where not s.blocked and s.refresh_policy->>'mode'='interval' and s.next_refresh_at <= $1 and ${active} limit 50`, [now.toISOString()])) {
      const hasBytes = await one(sql, `select 1 from ${S}.acquisitions where source_id=$1 and level='bytes' limit 1`, [s.id]);
      const level: Level = hasBytes !== undefined && (ports.evidence !== undefined || objects !== undefined) ? 'bytes' : 'metadata';
      const ctx = svc(s, 'scheduled refresh');
      created.push((await sql.tx((tx) => createRun(tx, ctx, s, 'refresh', runLimits({ level }), rootQueue(s)))).id);
    }
    for (const s of await sql.query(`select s.* from ${S}.sources s where not s.blocked and exists (select 1 from ${S}.failures f where f.source_id=s.id and f.state='open' and f.next_retry_at <= $1) and ${active} limit 50`, [now.toISOString()])) {
      const ctx = svc(s, 'scheduled retry of failed retrievals');
      const due = await sql.query(`select item_id, level from ${S}.failures where source_id=$1 and state='open' and next_retry_at <= $2 limit 5000`, [s.id, now.toISOString()]);
      const level: Level = due.some((d) => d.level === 'bytes') && (ports.evidence !== undefined || objects !== undefined) ? 'bytes' : 'metadata';
      created.push((await sql.tx((tx) => createRun(tx, ctx, s, 'retry', runLimits({ level }), [], { itemIds: due.map((d) => d.item_id as string) }))).id);
    }
    return created;
  }

  // ───────────── search ─────────────
  async function searchSource(ctx: ServiceContext, input: { sourceId: string; query: string; questionRef?: string; maxPages?: number; maxItems?: number; params?: Record<string, string>; idempotencyKey?: string }): Promise<Rec> {
    kit.requireCapability(ctx, 'discovery:search');
    nonempty(input.query, 'query', 1000); if (input.questionRef !== undefined) kit.parseUref(input.questionRef);
    const params = input.params ?? {}; invariant(Object.entries(params).every(([k, v]) => /^[A-Za-z0-9_.-]{1,60}$/.test(k) && typeof v === 'string' && v.length <= 500), 'invalid_input', 'Invalid search parameters');
    const limits = runLimits({ level: 'links', maxPages: input.maxPages ?? 1, maxItems: input.maxItems ?? 200 });
    return sql.tx((tx) => kit.idempotent(tx, S, ctx, input.idempotencyKey, { op: 'search', s: input.sourceId, q: input.query, params, limits, qr: input.questionRef ?? null }, async () => {
      const source = await loadSource(tx, ctx, input.sourceId); assertUsable(source);
      invariant(source.kind === 'search_json' || source.kind === 'search_opensearch', 'invalid_state', 'Source is not a search adapter (search_json or search_opensearch)');
      let url: string;
      if (source.kind === 'search_opensearch') {
        const template = String(source.config.template ?? source.base_url); invariant(template.includes('{searchTerms}'), 'invalid_state', 'OpenSearch template has no {searchTerms}');
        const fill: Record<string, string> = { searchTerms: input.query, count: String(source.config.count ?? 20), startIndex: '1', startPage: '1', language: '*', inputEncoding: 'UTF-8', outputEncoding: 'UTF-8', ...params };
        url = template.replace(/\{([A-Za-z:]+)\??\}/g, (_m, k: string) => encodeURIComponent(fill[k] ?? ''));
      } else {
        const u = new URL(source.base_url);
        for (const [k, v] of Object.entries({ ...(source.config.params ?? {}), ...params })) u.searchParams.set(k, String(v));
        u.searchParams.set(typeof source.config.queryParam === 'string' ? source.config.queryParam : 'q', input.query); url = u.href;
      }
      const run = await createRun(tx, ctx, source, 'search', limits, [url], { questionRef: input.questionRef });
      const id = randomUUID();
      const row = await one(tx, `insert into ${S}.search_attempts (tenant_id, project_id, id, source_id, run_id, question_ref, query, params, request_url, state, compartment, created_by, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,'queued',$10,$11,$12) returning *`,
        [ctx.tenantId, ctx.projectId, id, source.id, run.id, input.questionRef ?? null, input.query, JSON.stringify(params), url, source.compartment, ctx.actor.id, ctx.now]) as Rec;
      await audit(tx, ctx, 'search.requested', ref('search_attempt', id), { source: ref('source', source.id), question: input.questionRef ?? null });
      return attemptPublic(row) as Json;
    })) as Promise<Rec>;
  }
  const attemptPublic = (r: Rec): Rec => ({ ...camel(r), ref: ref('search_attempt', r.id), run: ref('run', r.run_id), source: ref('source', r.source_id) });
  async function getSearchAttempt(ctx: ServiceContext, id: string): Promise<Rec> {
    kit.requireCapability(ctx, 'discovery:read');
    return attemptPublic((isUuid(id) ? await one(sql, `select * from ${S}.search_attempts where ${SC} and id=$4`, [...P(ctx), id]) : undefined) ?? notFound());
  }
  async function listSearchAttempts(ctx: ServiceContext, options: { sourceId?: string; questionRef?: string; limit?: number } = {}): Promise<Rec[]> {
    kit.requireCapability(ctx, 'discovery:read');
    return (await sql.query(`select * from ${S}.search_attempts where ${SC} and ($4::text is null or source_id::text=$4) and ($5::text is null or question_ref=$5) order by created_at, id limit ${int(options.limit, 'limit', 1, 500, 200)}`, [...P(ctx), options.sourceId ?? null, options.questionRef ?? null])).map(attemptPublic);
  }

  // ───────────── reads ─────────────
  const itemPublic = (r: Rec): Rec => ({ ...camel(r), ref: ref('item', r.id), source: ref('source', r.source_id) });
  const acqPublic = (r: Rec): Rec => ({ ...camel(r), ref: ref('acquisition', r.id, r.revision), item: ref('item', r.item_id), receipt: ref('receipt', r.receipt_id), reuseNote: 'Acquisition is not permission to republish; `reuse` records the status declared in the source catalog.' });
  async function listItems(ctx: ServiceContext, options: { sourceId?: string; runId?: string; state?: string; limit?: number; after?: string } = {}): Promise<Rec[]> {
    kit.requireCapability(ctx, 'discovery:read');
    const lim = int(options.limit, 'limit', 1, 1000, 200);
    if (options.runId !== undefined) {
      if (!isUuid(options.runId)) return [];
      return (await sql.query(`select i.*, ri.outcome as run_outcome, ri.detail as run_detail from ${S}.run_items ri join ${S}.items i on i.id=ri.item_id where ${sc('i')} and ri.run_id=$4 and ($5::text is null or ri.outcome=$5) and ($6::uuid is null or i.id > $6) order by i.id limit ${lim}`, [...P(ctx), options.runId, options.state ?? null, isUuid(options.after) ? options.after : null])).map(itemPublic);
    }
    return (await sql.query(`select * from ${S}.items where ${SC} and ($4::text is null or source_id::text=$4) and ($5::text is null or state=$5) and ($6::uuid is null or id > $6) order by id limit ${lim}`, [...P(ctx), options.sourceId ?? null, options.state ?? null, isUuid(options.after) ? options.after : null])).map(itemPublic);
  }
  const loadItem = async (ctx: ServiceContext, id: string): Promise<Rec> => (isUuid(id) ? await one(sql, `select * from ${S}.items where ${SC} and id=$4`, [...P(ctx), id]) : undefined) ?? notFound();
  async function getItem(ctx: ServiceContext, id: string): Promise<Rec> {
    kit.requireCapability(ctx, 'discovery:read');
    const item = await loadItem(ctx, id);
    return { ...itemPublic(item), acquisitions: (await sql.query(`select * from ${S}.acquisitions where ${SC} and item_id=$4 order by revision`, [...P(ctx), id])).map(acqPublic) };
  }
  const loadAcq = async (ctx: ServiceContext, id: string): Promise<Rec> => (isUuid(id) ? await one(sql, `select * from ${S}.acquisitions where ${SC} and id=$4`, [...P(ctx), id]) : undefined) ?? notFound();
  async function getAcquisition(ctx: ServiceContext, id: string): Promise<Rec> { kit.requireCapability(ctx, 'discovery:read'); return acqPublic(await loadAcq(ctx, id)); }
  async function getAcquisitionBytes(ctx: ServiceContext, id: string): Promise<{ bytes: Uint8Array; mediaType: string; sha256: string }> {
    kit.requireCapability(ctx, 'discovery:read_bytes');
    const a = await loadAcq(ctx, id);
    const source = await loadSource(sql, ctx, a.source_id);
    if (a.blocked === true || source.blocked === true) throw new DomainError('consent_denied', 'This acquisition is blocked by a permission or rights change');
    invariant(a.level === 'bytes', 'invalid_state', 'This acquisition is metadata only; no bytes were retained');
    let bytes: Uint8Array;
    if (a.storage === 'object_store') { if (objects === undefined) throw new DomainError('unavailable', 'Object store is not configured'); bytes = await objects.get(a.object_key); }
    else { if (ports.evidence === undefined) throw new DomainError('unavailable', 'Bytes are held by the evidence engine and no EvidencePort is configured'); bytes = await ports.evidence.getBytes(ctx, a.evidence_ref); }
    invariant(createHash('sha256').update(bytes).digest('hex') === a.sha256, 'conflict', 'Stored bytes do not match the recorded digest');
    await sql.tx((tx) => audit(tx, ctx, 'acquisition.bytes_read', ref('acquisition', a.id, a.revision), {}));
    return { bytes, mediaType: a.media_type, sha256: a.sha256 };
  }
  const receiptPublic = (r: Rec): Rec => ({ ...camel(r), ref: ref('receipt', r.id), immutable: true });
  async function getReceipt(ctx: ServiceContext, id: string): Promise<Rec> {
    kit.requireCapability(ctx, 'discovery:read');
    return receiptPublic((isUuid(id) ? await one(sql, `select * from ${S}.receipts where ${SC} and id=$4`, [...P(ctx), id]) : undefined) ?? notFound());
  }
  async function listReceipts(ctx: ServiceContext, options: { runId?: string; itemId?: string; limit?: number } = {}): Promise<Rec[]> {
    kit.requireCapability(ctx, 'discovery:read');
    return (await sql.query(`select * from ${S}.receipts where ${SC} and ($4::text is null or run_id::text=$4) and ($5::text is null or item_id::text=$5) order by started_at, id limit ${int(options.limit, 'limit', 1, 1000, 200)}`, [...P(ctx), options.runId ?? null, options.itemId ?? null])).map(receiptPublic);
  }
  async function listFailures(ctx: ServiceContext, options: { sourceId?: string; state?: string; limit?: number } = {}): Promise<Rec[]> {
    kit.requireCapability(ctx, 'discovery:read');
    return (await sql.query(`select f.*, i.url from ${S}.failures f join ${S}.items i on i.id=f.item_id where ${sc('i')} and ($4::text is null or f.source_id::text=$4) and ($5::text is null or f.state=$5) order by f.last_at, f.id limit ${int(options.limit, 'limit', 1, 1000, 200)}`, [...P(ctx), options.sourceId ?? null, options.state ?? null]))
      .map((r) => ({ ...camel(r), ref: ref('failure', r.id), item: ref('item', r.item_id) }));
  }
  const gapPublic = (r: Rec): Rec => ({ ...camel(r), ref: ref('gap', r.id) });
  async function listGaps(ctx: ServiceContext, options: { sourceId?: string; runId?: string; kind?: string; state?: string; limit?: number } = {}): Promise<Rec[]> {
    kit.requireCapability(ctx, 'discovery:read');
    return (await sql.query(`select * from ${S}.gaps where ${SC} and ($4::text is null or source_id::text=$4) and ($5::text is null or run_id::text=$5) and ($6::text is null or kind=$6) and ($7::text is null or state=$7) order by created_at, id limit ${int(options.limit, 'limit', 1, 1000, 200)}`, [...P(ctx), options.sourceId ?? null, options.runId ?? null, options.kind ?? null, options.state ?? null])).map(gapPublic);
  }
  /** Declares items a collection is expected to contain; each stays an open gap until an item with that URL is acquired. */
  async function declareExpected(ctx: ServiceContext, input: { sourceId: string; expected: { url: string; note?: string }[]; idempotencyKey?: string }): Promise<{ recorded: number }> {
    kit.requireCapability(ctx, 'discovery:configure');
    invariant(Array.isArray(input.expected) && input.expected.length >= 1 && input.expected.length <= 5000, 'invalid_input', 'expected must list 1-5000 entries');
    return sql.tx((tx) => kit.idempotent(tx, S, ctx, input.idempotencyKey, { op: 'declareExpected', input }, async () => {
      const source = await loadSource(tx, ctx, input.sourceId); let recorded = 0;
      for (const e of input.expected) {
        nonempty(e.url, 'expected url', 4000); const c = canonicalUrl(e.url);
        const have = await one(tx, `select 1 from ${S}.items where tenant_id=$1 and project_id=$2 and source_id=$3 and canonical_url=$4 and current_acquisition is not null`, [ctx.tenantId, ctx.projectId, source.id, c]);
        if (have === undefined) { await recordGap(tx, ctx, source, { kind: 'expected_unresolved', expected: c, detail: (e.note ?? 'Declared as expected in this collection; not yet acquired').slice(0, 1000) }); recorded++; }
      }
      await audit(tx, ctx, 'gap.expected_declared', ref('source', source.id), { count: input.expected.length, open: recorded });
      return { recorded };
    }));
  }
  async function resolveGap(ctx: ServiceContext, id: string, input: { resolution: string }): Promise<Rec> {
    kit.requireCapability(ctx, 'discovery:configure'); nonempty(input.resolution, 'resolution', 1000);
    return sql.tx(async (tx) => {
      const rows = isUuid(id) ? await tx.query(`update ${S}.gaps set state='resolved', resolved_at=$5, resolution=$6 where ${SC} and id=$4 and state='open' returning *`, [...P(ctx), id, ctx.now, input.resolution]) : [];
      if (rows[0] === undefined) { const cur = isUuid(id) ? await one(tx, `select state from ${S}.gaps where ${SC} and id=$4`, [...P(ctx), id]) : undefined; if (cur === undefined) notFound(); throw new DomainError('invalid_state', 'Gap is already resolved'); }
      await audit(tx, ctx, 'gap.resolved', ref('gap', id), { resolution: input.resolution.slice(0, 300) });
      return gapPublic(rows[0]);
    });
  }
  async function coverage(ctx: ServiceContext, target: { runId: string } | { sourceId: string }): Promise<Coverage> {
    kit.requireCapability(ctx, 'discovery:read');
    if ('runId' in target) return runCoverageRow(sql, await loadRun(sql, ctx, target.runId));
    const source = await loadSource(sql, ctx, target.sourceId);
    const counts: Rec = {}; let total = 0;
    for (const r of await sql.query(`select state, count(*)::int as n from ${S}.items where tenant_id=$1 and project_id=$2 and source_id=$3 group by state`, [ctx.tenantId, ctx.projectId, source.id])) { counts[r.state as string] = r.n; total += r.n as number; }
    const byKind: Record<string, number> = {}; let open = 0;
    for (const g of await sql.query(`select kind, count(*)::int as n from ${S}.gaps where tenant_id=$1 and project_id=$2 and source_id=$3 and state='open' group by kind`, [ctx.tenantId, ctx.projectId, source.id])) { byKind[g.kind as string] = g.n as number; open += g.n as number; }
    const x = await one(sql, `select (select count(distinct f.source_family)::int from ${S}.items i join ${S}.families f on f.id=i.family_id where i.source_id=$1) as fam,
      (select coalesce(sum(a.size),0)::float8 from ${S}.acquisitions a join ${S}.items i on i.current_acquisition=a.id where i.source_id=$1 and a.level='bytes') as bytes,
      (select count(*)::int from ${S}.failures where source_id=$1 and state<>'resolved') as failing,
      (select count(*)::int from ${S}.run_pages p join ${S}.runs r on r.id=p.run_id where r.source_id=$1 and p.outcome='ok') as pages_ok,
      (select count(*)::int from ${S}.run_pages p join ${S}.runs r on r.id=p.run_id where r.source_id=$1 and p.outcome<>'ok') as pages_bad,
      (select count(*)::int from ${S}.items i where i.source_id=$1 and exists (select 1 from ${S}.acquisitions a where a.family_id=i.family_id and a.item_id<>i.id)) as dup`, [source.id]) as Rec;
    const last = await one(sql, `select id, state, checkpoint, updated_at from ${S}.runs where source_id=$1 order by created_at desc limit 1`, [source.id]);
    return {
      scope: 'source', ref: ref('source', source.id), state: source.blocked ? 'blocked' : source.stale ? 'stale' : 'active', discovered: total, linkOnly: counts.discovered ?? 0, acquiredMetadata: counts.metadata_acquired ?? 0, acquiredBytes: counts.bytes_acquired ?? 0, unchanged: 0,
      failed: counts.failed ?? 0, skippedByPolicy: counts.skipped_policy ?? 0, accessRestricted: counts.access_restricted ?? 0, notFound: counts.not_found ?? 0, pending: 0, newItems: 0, duplicateContent: x.dup,
      gaps: { open, byKind }, pages: { fetched: x.pages_ok, unavailable: x.pages_bad }, independentSourceFamilies: x.fam, bytesAcquired: Number(x.bytes),
      lastCheckpoint: last === undefined ? null : { run: ref('run', last.id), state: last.state, phase: last.checkpoint.phase, pagesDone: last.checkpoint.pagesDone, updatedAt: new Date(last.updated_at).toISOString(), openFailures: x.failing },
      note: 'Source coverage counts each item once by its current state: discovered = linkOnly + acquiredMetadata + acquiredBytes + failed + skippedByPolicy + accessRestricted + notFound. Only acquiredBytes are held originals.',
    };
  }
  async function getFamily(ctx: ServiceContext, id: string): Promise<Rec> {
    kit.requireCapability(ctx, 'discovery:read');
    const f = (isUuid(id) ? await one(sql, `select * from ${S}.families where tenant_id=$1 and project_id=$2 and id=$3`, [ctx.tenantId, ctx.projectId, id]) : undefined) ?? notFound();
    const locations = await sql.query(`select distinct i.id, i.url, i.source_id from ${S}.acquisitions a join ${S}.items i on i.id=a.item_id where ${sc('a')} and a.family_id=$4 order by i.url`, [...P(ctx), id]);
    if (locations.length === 0) notFound();
    const hints = await sql.query(`select * from ${S}.mirror_hints where tenant_id=$1 and project_id=$2 and (family_id=$3 or other_family_id=$3) order by at`, [ctx.tenantId, ctx.projectId, id]);
    const { sketch: _s, ...rest } = camel(f);
    return { ...rest, ref: ref('family', f.id), sourceFamily: ref('source_family', f.source_family), locations: locations.map((l) => ({ item: ref('item', l.id), url: l.url, source: ref('source', l.source_id) })), hints: hints.map((h) => ({ relation: h.relation, method: h.method, similarity: h.similarity, family: ref('family', h.family_id), other: ref('family', h.other_family_id) })) };
  }
  /** Groups items by source family. Identical bytes and detected mirrors count as ONE source; unacquired items count as none. */
  async function corroboration(ctx: ServiceContext, input: { items: string[] }): Promise<Rec> {
    kit.requireCapability(ctx, 'discovery:read');
    invariant(Array.isArray(input.items) && input.items.length >= 1 && input.items.length <= 500, 'invalid_input', 'items must list 1-500 item references');
    const ids = input.items.map((r) => { const p = kit.parseUref(r); invariant(p.engine === 'E04' && p.kind === 'item', 'invalid_input', 'Only E04 item references are accepted'); return p.id; });
    const rows = await sql.query(`select i.id, i.url, i.state, i.family_id, f.source_family, f.sha256 from ${S}.items i left join ${S}.families f on f.id=i.family_id where ${sc('i')} and i.id::text = any($4::text[])`, [...P(ctx), ids]);
    const groups = new Map<string, Rec[]>(); const unassessed: Rec[] = [];
    for (const id of ids) {
      const r = rows.find((x) => x.id === id);
      if (r === undefined) { unassessed.push({ item: ref('item', id), reason: 'not_found' }); continue; }
      if (r.source_family === null) { unassessed.push({ item: ref('item', id), url: r.url, reason: `no acquired content (${r.state}); a discovered or failed link corroborates nothing` }); continue; }
      groups.set(String(r.source_family), [...(groups.get(String(r.source_family)) ?? []), r]);
    }
    return {
      independentCount: groups.size,
      groups: [...groups.entries()].map(([family, members]) => ({ sourceFamily: ref('source_family', family), relation: members.length === 1 ? 'single' : new Set(members.map((m) => m.sha256)).size === 1 ? 'identical_bytes' : 'same_source_family', members: members.map((m) => ({ item: ref('item', m.id), url: m.url, family: ref('family', m.family_id), sha256: m.sha256 })) })),
      unassessed,
      note: 'independentCount is an upper bound established only by content comparison: copies and detected mirrors are merged, but undetected syndication, shared wire copy or common authorship can still make separate families dependent.',
    };
  }

  // ───────────── lead extraction on demand ─────────────
  async function extractLeadsFromAcquisition(ctx: ServiceContext, acquisitionId: string, input: { questionRef?: string; why?: string } = {}): Promise<Rec[]> {
    kit.requireCapability(ctx, 'discovery:write_leads');
    if (input.questionRef !== undefined) kit.parseUref(input.questionRef);
    const a = await loadAcq(ctx, acquisitionId); const source = await loadSource(sql, ctx, a.source_id); assertUsable(source);
    invariant(a.level === 'bytes' && /html/.test(a.media_type), 'invalid_state', 'Lead extraction needs an acquired HTML original');
    let bytes: Uint8Array;
    if (a.storage === 'object_store') { if (objects === undefined) throw new DomainError('unavailable', 'Object store is not configured'); bytes = await objects.get(a.object_key); }
    else { if (ports.evidence === undefined) throw new DomainError('unavailable', 'No EvidencePort is configured'); bytes = await ports.evidence.getBytes(ctx, a.evidence_ref); }
    const item = await loadItem(ctx, a.item_id);
    const pageUrl = String(a.origin?.url ?? item.url);
    const found = extractLeads(decodeText(bytes, null), pageUrl, { ...(Array.isArray(source.config.contactTerms) ? { contactTerms: source.config.contactTerms } : {}) });
    const ids = await sql.tx((tx) => storeExtracted(tx, ctx, found, { acquisitionRef: ref('acquisition', a.id, a.revision), itemRef: ref('item', item.id), pageUrl, questionRef: input.questionRef ?? item.question_ref ?? null, why: input.why ?? null, compartment: a.compartment }));
    return Promise.all(ids.map(async (id) => leadPublic(sql, await one(sql, `select * from ${S}.leads where id=$1`, [id]) as Rec)));
  }

  // ───────────── private archive import ─────────────
  async function importArchive(ctx: ServiceContext, input: { sourceId: string; format: 'zip' | 'warc' | 'directory'; bytes?: Uint8Array; path?: string; manifest?: ArchiveManifest; idempotencyKey?: string }): Promise<Rec> {
    kit.requireCapability(ctx, 'discovery:acquire');
    requireStorage('bytes');
    const source = await loadSource(sql, ctx, input.sourceId); assertUsable(source);
    invariant(source.kind === 'archive_import', 'invalid_state', 'Imports go into an archive_import source');
    const archive = await readArchive(ctx, { format: input.format, ...(input.bytes === undefined ? {} : { bytes: input.bytes }), ...(input.path === undefined ? {} : { path: input.path }), ...(input.manifest === undefined ? {} : { manifest: input.manifest }), ...(cfg.importRoot === undefined ? {} : { importRoot: cfg.importRoot }), userAgent: fetchPolicy.userAgent });
    const runId = randomUUID();
    const prepared: Rec[] = [];
    for (const e of archive.entries) {
      const sha256 = createHash('sha256').update(e.bytes).digest('hex');
      const mediaType = sniffMediaType(e.bytes, e.mediaType ?? null);
      const receiptId = randomUUID(); const hasUrl = e.originalUrl !== null && /^https?:\/\//i.test(e.originalUrl);
      const url = hasUrl ? e.originalUrl as string : `import://${source.id}/${e.path.split('/').map(encodeURIComponent).join('/')}`;
      const missing = [...(hasUrl ? [] : ['originalUrl']), ...(e.retrievedAt === null ? ['retrievedAt'] : []), ...(e.listed ? [] : ['manifest entry'])];
      const origin: Rec = { kind: 'discovery', receipt: ref('receipt', receiptId), url: hasUrl ? url : null, retrievedAt: e.retrievedAt, importedAt: ctx.now, sha256, source: ref('source', source.id, source.revision), import: { format: input.format, archiveSha256: archive.sha256, path: e.path, recordId: e.recordId ?? null }, history: e.history, note: e.note, provenanceMissing: missing, reuse: source.reuse, accessTerms: source.access_terms };
      const storage = await storeOriginal(ctx, source, e.bytes, { sha256, mediaType, filename: filenameFor(`https://x.invalid/${e.path}`, { headers: {}, mediaType }), origin, key: `e04-import-${source.id}-${sha256}` });
      const text = /html|^text\//.test(mediaType) ? decodeText(e.bytes, null) : null;
      prepared.push({ e, sha256, mediaType, receiptId, url, missing, origin, storage, sketch: text === null ? null : shingleSketch(/html/.test(mediaType) ? mainText(parseHtml(text)) : text), title: e.title ?? (text !== null && /html/.test(mediaType) ? pageMetadata(parseHtml(text), 'https://x.invalid/').title : null) });
    }
    return sql.tx((tx) => kit.idempotent(tx, S, ctx, input.idempotencyKey, { op: 'importArchive', s: source.id, a: archive.sha256, m: input.manifest ?? null }, async () => {
      const cp = { phase: 'done', queue: [], seq: 0, pagesDone: 0, pageGaps: 0, bytes: prepared.reduce((n, p) => n + p.e.bytes.byteLength, 0), listed: prepared.length };
      await tx.query(`insert into ${S}.runs (tenant_id, project_id, id, source_id, kind, state, level, options, checkpoint, compartment, created_by, created_at, started_at, finished_at, updated_at) values ($1,$2,$3,$4,'import','completed','bytes',$5::jsonb,$6::jsonb,$7,$8,$9,$9,$9,$9)`,
        [ctx.tenantId, ctx.projectId, runId, source.id, JSON.stringify({ format: input.format, archiveSha256: archive.sha256, manifest: archive.manifestSummary, skipped: archive.skipped }), JSON.stringify(cp), source.compartment, ctx.actor.id, ctx.now]);
      let acquired = 0; let unchanged = 0;
      for (const p of prepared) {
        const up = await upsertItem(tx, ctx, source, runId, { url: p.url, title: p.title, metadata: { importPath: p.e.path } }, null);
        const prior = up.row.current_acquisition === null ? undefined : await one(tx, `select * from ${S}.acquisitions where id=$1`, [up.row.current_acquisition]);
        const receipt = buildReceipt(ctx, source, null, { id: p.receiptId, kind: 'import', purpose: 'import', runId, itemId: up.id, requestUrl: /^https?:/.test(p.url) ? p.url : undefined as never, outcome: 'imported', message: `Imported from private ${input.format} archive ${archive.sha256.slice(0, 16)} entry ${p.e.path}; not retrieved from the network by this engine`, storage: p.storage, sha256: p.sha256, size: p.e.bytes.byteLength, mediaType: p.mediaType, robots: { policy: 'not_applicable', basis: 'private archive import' } });
        await insertReceipt(tx, receipt);
        if (prior !== undefined && prior.sha256 === p.sha256) { unchanged++; await tx.query(`insert into ${S}.run_items (tenant_id, project_id, run_id, item_id, is_new, outcome, detail, receipt_id, at) values ($1,$2,$3,$4,false,'unchanged','Same bytes already held',$5,$6) on conflict do nothing`, [ctx.tenantId, ctx.projectId, runId, up.id, receipt.id, ctx.now]); continue; }
        const family = await assignFamily(tx, ctx, { sha256: p.sha256, size: p.e.bytes.byteLength, mediaType: p.mediaType, sketch: p.sketch, canonicalTarget: null, itemId: up.id });
        const acqId = randomUUID(); const revision = prior === undefined ? 1 : Number(prior.revision) + 1;
        await tx.query(`insert into ${S}.acquisitions (tenant_id, project_id, id, item_id, source_id, run_id, revision, level, sha256, size, media_type, storage, evidence_ref, object_key, family_id, reuse, access_terms, receipt_id, metadata, origin, changed, supersedes, compartment, acquired_at)
          values ($1,$2,$3,$4,$5,$6,$7,'bytes',$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18::jsonb,$19::jsonb,$20,$21,$22,$23)`,
          [ctx.tenantId, ctx.projectId, acqId, up.id, source.id, runId, revision, p.sha256, p.e.bytes.byteLength, p.mediaType, p.storage.kind, p.storage.evidenceRef ?? null, p.storage.objectKey ?? null, family.id, source.reuse, source.access_terms, receipt.id,
            JSON.stringify({ title: p.title, importPath: p.e.path, retrievedAt: p.e.retrievedAt, history: p.e.history, note: p.e.note, manifestSha256Mismatch: p.e.sha256Mismatch }), JSON.stringify(p.origin), prior !== undefined, prior?.id ?? null, source.compartment, ctx.now]);
        await tx.query(`update ${S}.items set current_acquisition=$2, family_id=$3, state='bytes_acquired', last_outcome='bytes' where id=$1`, [up.id, acqId, family.id]);
        await tx.query(`insert into ${S}.run_items (tenant_id, project_id, run_id, item_id, is_new, outcome, detail, acquisition_id, receipt_id, duplicate, at) values ($1,$2,$3,$4,$5,'bytes','Imported original',$6,$7,$8,$9)
          on conflict (run_id, item_id) do update set acquisition_id=excluded.acquisition_id, receipt_id=excluded.receipt_id, detail='Imported original (several captures of this item were imported in date order)'`, [ctx.tenantId, ctx.projectId, runId, up.id, up.inserted, acqId, receipt.id, family.duplicate, ctx.now]);
        acquired++;
        if (p.missing.length > 0) await recordGap(tx, ctx, source, { kind: 'provenance_missing', expected: p.url, detail: `Imported item lacks origin information: ${p.missing.join(', ')}`, runId, itemId: up.id, receiptId: receipt.id });
        if (p.e.sha256Mismatch) await recordGap(tx, ctx, source, { kind: 'integrity_mismatch', expected: `${p.url}#sha256`, detail: 'Bytes differ from the digest recorded in the manifest', runId, itemId: up.id, receiptId: receipt.id });
        await emit(tx, ctx, 'acquisition.completed', ref('acquisition', acqId, revision), { item: ref('item', up.id), level: 'bytes', sha256: p.sha256, imported: true, changed: prior !== undefined, evidenceRef: p.storage.evidenceRef ?? null, reuse: source.reuse });
      }
      for (const m of archive.missing) await recordGap(tx, ctx, source, { kind: 'expected_unresolved', expected: m.originalUrl !== null ? canonicalUrl(m.originalUrl) : `import://${source.id}/${m.path}`, detail: `Listed in the import manifest (${m.path}) but absent from the archive`, runId });
      await audit(tx, ctx, 'archive.imported', ref('run', runId), { format: input.format, archiveSha256: archive.sha256, acquired, unchanged, provenanceGaps: prepared.filter((p) => p.missing.length > 0).length, missing: archive.missing.length });
      await emit(tx, ctx, 'collection.completed', ref('run', runId), { state: 'completed', imported: true, acquiredBytes: acquired });
      if (acquired > 0) await emit(tx, ctx, 'collection.changed', ref('source', source.id), { run: ref('run', runId), added: acquired });
      return { run: ref('run', runId), runId, archiveSha256: archive.sha256, acquired, unchanged, provenanceGaps: prepared.filter((p) => p.missing.length > 0).length, missingFromArchive: archive.missing.length, skipped: archive.skipped } as Json;
    })) as Promise<Rec>;
  }

  // ───────────── standard surface ─────────────
  async function inspect(ctx: ServiceContext, value: string): Promise<Inspection | null> {
    kit.requireCapability(ctx, 'discovery:read');
    let p: ReturnType<typeof kit.parseUref>;
    try { p = kit.parseUref(value); } catch { return null; }
    if (p.engine !== 'E04' || !isUuid(p.id)) return null;
    const table: Record<string, string> = { source: 'sources', run: 'runs', item: 'items', acquisition: 'acquisitions', receipt: 'receipts', gap: 'gaps', lead: 'leads', search_attempt: 'search_attempts' };
    const t = table[p.kind]; if (t === undefined) return null;
    if (p.kind === 'lead' && !kit.hasCapability(ctx, 'discovery:read_leads')) return null;
    const r = await one(sql, `select * from ${S}.${t} where ${SC} and id=$4`, [...P(ctx), p.id]);
    if (r === undefined) return null;
    const subject = ref(p.kind, r.id);
    const history = (await kit.listAudit(sql, S, ctx, { subject, limit: 200 })).map((a) => ({ at: a.at, actorId: a.actorId, action: a.action, detail: a.detail }));
    const reasons = (Array.isArray(r.reasons) ? r.reasons : []).filter((x: Rec) => x.cleared !== true).map((x: Rec) => `${x.kind ?? 'change'}: ${x.reason ?? ''}`);
    let versions: Inspection['versions'] = []; let sources: string[] = []; let dependents: string[] = []; let permissions: Json[] = []; let data: Rec = camel(r); let title = String(r.name ?? r.title ?? r.url ?? r.query ?? r.kind ?? p.kind); let state = String(r.state ?? r.outcome ?? 'recorded');
    let blocked = r.blocked === true;
    if (p.kind === 'source') {
      data = sourcePublic(r); state = r.blocked ? 'blocked' : r.stale ? 'stale' : 'active'; sources = [...r.permission_refs];
      versions = (await sql.query(`select revision, at, actor_id, summary from ${S}.source_revisions where source_id=$1 order by revision`, [r.id])).map((v) => ({ revision: v.revision as number, at: new Date(v.at as Date).toISOString(), actorId: v.actor_id as string, summary: v.summary as string }));
      permissions = [{ reuse: r.reuse, accessTerms: r.access_terms, robotsPolicy: r.robots_policy, hasCredential: r.credential !== null }];
      dependents = (await sql.query(`select id from ${S}.runs where source_id=$1 order by created_at desc limit 20`, [r.id])).map((x) => ref('run', x.id as string));
    } else if (p.kind === 'item') {
      const acqs = await sql.query(`select * from ${S}.acquisitions where item_id=$1 order by revision`, [r.id]);
      versions = acqs.map((a) => ({ revision: a.revision as number, at: new Date(a.acquired_at as Date).toISOString(), actorId: 'worker', summary: `${a.level} ${String(a.sha256).slice(0, 12)}` }));
      sources = [ref('source', r.source_id), ...(r.question_ref ? [r.question_ref] : [])]; dependents = acqs.map((a) => ref('acquisition', a.id as string, a.revision as number));
      const src = await one(sql, `select blocked from ${S}.sources where id=$1`, [r.source_id]); blocked = blocked || src?.blocked === true;
    } else if (p.kind === 'acquisition') {
      data = acqPublic(r); state = r.blocked ? 'blocked' : r.level === 'bytes' ? 'bytes_acquired' : 'metadata_acquired'; title = `${r.level} ${String(r.sha256).slice(0, 12)}`;
      sources = [ref('item', r.item_id), ref('source', r.source_id), ref('receipt', r.receipt_id)]; dependents = r.evidence_ref ? [r.evidence_ref] : [];
      permissions = [{ reuse: r.reuse, accessTerms: r.access_terms, note: 'Acquisition is not republication permission' }];
      const src = await one(sql, `select blocked from ${S}.sources where id=$1`, [r.source_id]); blocked = blocked || src?.blocked === true;
    } else if (p.kind === 'lead') { data = await leadPublic(sql, r); title = String(r.person_name ?? r.role ?? r.organization ?? 'contact lead'); state = r.blocked ? 'blocked' : r.stale ? 'stale' : 'recorded'; sources = [r.question_ref, r.source_item_ref].filter((x): x is string => typeof x === 'string'); }
    else if (p.kind === 'run') { data = { ...runPublic(r), coverage: await runCoverageRow(sql, r) }; sources = [ref('source', r.source_id)]; title = `${r.kind} run`; }
    else if (p.kind === 'receipt') { data = receiptPublic(r); title = String(r.request_url ?? r.purpose); sources = [ref('source', r.source_id)]; }
    else if (p.kind === 'gap') { sources = [ref('source', r.source_id)]; title = `${r.kind}: ${r.expected}`; }
    return { ref: p.kind === 'source' || p.kind === 'acquisition' ? ref(p.kind, r.id, r.revision) : subject, kind: p.kind, title: title.slice(0, 300), state, stale: r.stale === true, blocked, staleReasons: reasons, versions, sources, dependents, permissions, decisions: [], history, data: JSON.parse(JSON.stringify(data)) as Json };
  }
  async function search(ctx: ServiceContext, query: { q: string; limit?: number }): Promise<SearchHit[]> {
    kit.requireCapability(ctx, 'discovery:read');
    const q = String(query.q ?? '').trim(); if (q === '') return [];
    const lim = int(query.limit, 'limit', 1, 200, 50); const pat = like(q.slice(0, 200)); const out: SearchHit[] = [];
    for (const r of await sql.query(`select id, name, kind, base_url, blocked from ${S}.sources where ${SC} and (name ilike $4 or base_url ilike $4) order by name limit ${lim}`, [...P(ctx), pat])) out.push({ ref: ref('source', r.id as string), kind: 'source', title: r.name as string, snippet: `${r.kind} ${r.base_url}`, state: r.blocked ? 'blocked' : 'active' });
    for (const r of await sql.query(`select id, title, url, state from ${S}.items where ${SC} and (title ilike $4 or url ilike $4) order by discovered_at, id limit ${lim}`, [...P(ctx), pat])) out.push({ ref: ref('item', r.id as string), kind: 'item', title: (r.title ?? r.url) as string, snippet: r.url as string, state: r.state as string });
    if (kit.hasCapability(ctx, 'discovery:read_leads')) for (const r of await sql.query(`select id, person_name, role, organization from ${S}.leads where ${SC} and (person_name ilike $4 or organization ilike $4 or role ilike $4) order by created_at limit ${lim}`, [...P(ctx), pat])) out.push({ ref: ref('lead', r.id as string), kind: 'lead', title: String(r.person_name ?? r.role ?? r.organization), snippet: [r.role, r.organization].filter(Boolean).join(', '), state: 'recorded' });
    return out.slice(0, lim);
  }
  async function auditFeed(ctx: ServiceContext, options: { after?: string; limit?: number; subject?: string } = {}): Promise<AuditRecord[]> { kit.requireCapability(ctx, 'discovery:read'); return kit.listAudit(sql, S, ctx, options); }
  async function events(ctx: ServiceContext, options: { after?: string; limit?: number } = {}): Promise<EngineEvent[]> {
    kit.requireCapability(ctx, 'discovery:events');
    return (await kit.readEvents(sql, S, { ...options, tenantId: ctx.tenantId })).map((e) => ({ ...e, engine: 'E04' }));
  }
  async function applyUpstreamChange(ctx: ServiceContext, change: UpstreamChange): Promise<{ affected: string[] }> {
    kit.requireCapability(ctx, 'discovery:events');
    invariant(change !== null && typeof change === 'object' && typeof change.eventId === 'string' && change.eventId !== '' && change.eventId.length <= 200 && Array.isArray(change.refs) && change.refs.length <= 1000, 'invalid_input', 'Invalid upstream change');
    for (const r of change.refs) kit.parseUref(r);
    const blocks = ['permission_withdrawn', 'permission_changed', 'rights_changed'].includes(change.kind);
    return sql.tx(async (tx) => {
      await tx.query('select pg_advisory_xact_lock(hashtext($1))', [`e04-upstream:${ctx.tenantId}:${ctx.projectId}:${change.eventId}`]);
      const prior = await one(tx, `select affected from ${S}.upstream_changes where tenant_id=$1 and project_id=$2 and event_id=$3`, [ctx.tenantId, ctx.projectId, change.eventId]);
      if (prior !== undefined) return { affected: prior.affected as string[] };
      const hit = (candidates: (string | null | undefined)[]): boolean => candidates.some((c) => typeof c === 'string' && change.refs.some((r) => { try { return kit.urefMatches(r, c); } catch { return false; } }));
      const reason = { kind: change.kind, reason: String(change.reason ?? '').slice(0, 500), cause: change.eventId, at: ctx.now };
      const affected: string[] = []; const flag = blocks ? 'blocked' : 'stale';
      const mark = async (table: string, kind: string, id: string, type: string): Promise<void> => {
        await tx.query(`update ${S}.${table} set ${flag}=true, reasons=reasons || $2::jsonb where id=$1`, [id, JSON.stringify([reason])]);
        const subject = ref(kind, id); affected.push(subject);
        await audit(tx, ctx, `${kind}.${flag}`, subject, { cause: change.eventId, kind: change.kind });
        await emit(tx, ctx, type, subject, { reason: reason.reason, cause: change.eventId, kind: change.kind });
      };
      for (const s of await tx.query(`select id, permission_refs from ${S}.sources where tenant_id=$1 and project_id=$2`, [ctx.tenantId, ctx.projectId])) {
        if (!hit([ref('source', s.id as string), ...(s.permission_refs as string[])])) continue;
        await mark('sources', 'source', s.id as string, blocks ? 'source.blocked' : 'source.stale');
        if (blocks) for (const run of await tx.query(`select id, job_id from ${S}.runs where source_id=$1 and state in ('queued','running','paused')`, [s.id])) {
          try { await kit.controlJob(tx, S, ctx, run.job_id as string, 'cancel'); } catch { /* job already settled */ }
          await tx.query(`update ${S}.runs set state='blocked', error=$2, finished_at=$3, updated_at=$3 where id=$1`, [run.id, `Blocked by upstream ${change.kind}`, ctx.now]);
          await emit(tx, ctx, 'acquisition.blocked', ref('run', run.id as string), { reason: reason.reason, cause: change.eventId });
          affected.push(ref('run', run.id as string));
        }
      }
      const directItems = change.refs.map((r) => kit.parseUref(r)).filter((p) => p.engine === 'E04' && p.kind === 'item' && isUuid(p.id)).map((p) => p.id);
      for (const i of await tx.query(`select id, question_ref from ${S}.items where tenant_id=$1 and project_id=$2 and (question_ref is not null or id::text = any($3::text[]))`, [ctx.tenantId, ctx.projectId, directItems])) {
        if (hit([ref('item', i.id as string), i.question_ref as string | null])) await mark('items', 'item', i.id as string, blocks ? 'acquisition.blocked' : 'source.stale');
      }
      const directAcq = change.refs.map((r) => kit.parseUref(r));
      for (const a of await tx.query(`select id, evidence_ref from ${S}.acquisitions where tenant_id=$1 and project_id=$2 and (evidence_ref = any($3::text[]) or id::text = any($4::text[]) or evidence_ref is not null and split_part(evidence_ref,'@',1) = any($5::text[]))`,
        [ctx.tenantId, ctx.projectId, change.refs, directAcq.filter((p) => p.engine === 'E04' && p.kind === 'acquisition').map((p) => p.id), change.refs.map((r) => r.split('@')[0])])) {
        if (blocks) await mark('acquisitions', 'acquisition', a.id as string, 'acquisition.blocked');
      }
      for (const l of await tx.query(`select id, question_ref, source_item_ref from ${S}.leads where tenant_id=$1 and project_id=$2`, [ctx.tenantId, ctx.projectId])) {
        if (hit([ref('lead', l.id as string), l.question_ref as string | null, l.source_item_ref as string | null])) await mark('leads', 'lead', l.id as string, blocks ? 'lead.blocked' : 'lead.stale');
      }
      await tx.query(`insert into ${S}.upstream_changes (tenant_id, project_id, event_id, kind, affected, at) values ($1,$2,$3,$4,$5::jsonb,$6)`, [ctx.tenantId, ctx.projectId, change.eventId, String(change.kind), JSON.stringify(affected), ctx.now]);
      return { affected };
    });
  }
  async function health(): Promise<{ ok: boolean; detail: Json }> {
    try {
      const j = await one(sql, `select count(*) filter (where state in ('queued','leased'))::int as active, count(*) filter (where state='dead')::int as dead from ${S}._jobs`, []) as Rec;
      return { ok: true, detail: { jobs: { active: j.active, dead: j.dead }, originals: ports.evidence !== undefined ? 'evidence_port' : objects !== undefined ? 'object_store' : 'unavailable', credentialKey: credKey !== null, importRoot: cfg.importRoot !== undefined, allowedPrivateHosts: fetchPolicy.allowedPrivateHosts.length } };
    } catch { return { ok: false, detail: { database: 'unavailable' } }; }
  }

  const engine = {
    manifest, createSource, updateSource, getSource, listSources, setSourceCredential, setRobotsPolicy, unblockSource,
    startCollection, refreshSource, acquire, retryFailures, getRun, listRuns, controlRun, coverage,
    listItems, getItem, getAcquisition, getAcquisitionBytes, getReceipt, listReceipts, listFailures, listGaps, declareExpected, resolveGap,
    getFamily, corroboration, searchSource, getSearchAttempt, listSearchAttempts, importArchive,
    createLead, getLead, listLeads, setRouteVerification, setLeadIdentity, extractLeadsFromAcquisition,
    runWorkerOnce, runDueWork,
    inspect, search, audit: auditFeed, events, applyUpstreamChange, health,
  };
  return engine satisfies StandardEngine;
}

// ───────────────────────────── HTTP ─────────────────────────────
export function routes(engine: DiscoveryEngine): Route[] {
  const body = (r: kit.HttpRequest): Rec => { invariant(r.body !== null && typeof r.body === 'object' && !Array.isArray(r.body), 'invalid_input', 'JSON object body required'); return r.body as Rec; };
  const key = (r: kit.HttpRequest): Rec => { const k = r.headers['idempotency-key']; return typeof k === 'string' && k !== '' ? { idempotencyKey: k } : {}; };
  const q = (r: kit.HttpRequest, names: string[]): Rec => { const out: Rec = {}; for (const n of names) { const v = r.query.get(n); if (v !== null) out[n] = n === 'limit' ? Number(v) : v; } return out; };
  type H = (r: kit.HttpRequest) => Promise<unknown>;
  const R = (method: Route['method'], path: string, h: H, status = 200): Route => ({ method, path, handler: async (r) => {
    try { const out = await h(r); return out !== null && typeof out === 'object' && Object.hasOwn(out, 'bytes') ? out as kit.HttpResponse : { status, json: out }; }
    catch (e) { if (e instanceof DomainError && (e.code === 'unavailable' || e.code === 'provider_unavailable')) return { status: 503, json: { error: { code: e.code, message: e.message } } }; throw e; }
  } });
  return [
    ...kit.standardRoutes(engine),
    R('POST', '/v1/sources', (r) => engine.createSource(r.ctx, { ...body(r), ...key(r) } as SourceInput), 201),
    R('GET', '/v1/sources', (r) => engine.listSources(r.ctx, q(r, ['kind', 'limit']))),
    R('GET', '/v1/sources/:id', (r) => engine.getSource(r.ctx, r.params.id as string)),
    R('PATCH', '/v1/sources/:id', (r) => engine.updateSource(r.ctx, r.params.id as string, { ...body(r), ...key(r) })),
    R('POST', '/v1/sources/:id/credential', (r) => engine.setSourceCredential(r.ctx, r.params.id as string, body(r) as never)),
    R('POST', '/v1/sources/:id/robots-policy', (r) => engine.setRobotsPolicy(r.ctx, r.params.id as string, body(r) as never)),
    R('POST', '/v1/sources/:id/unblock', (r) => engine.unblockSource(r.ctx, r.params.id as string, body(r) as never)),
    R('GET', '/v1/sources/:id/coverage', (r) => engine.coverage(r.ctx, { sourceId: r.params.id as string })),
    R('POST', '/v1/sources/:id/expected', (r) => engine.declareExpected(r.ctx, { sourceId: r.params.id as string, expected: body(r).expected, ...key(r) })),
    R('POST', '/v1/sources/:id/retry-failures', (r) => engine.retryFailures(r.ctx, { sourceId: r.params.id as string, force: (r.body as Rec | undefined)?.force === true, ...key(r) })),
    R('POST', '/v1/connectors/:id/refresh', (r) => engine.refreshSource(r.ctx, r.params.id as string, { ...((r.body ?? {}) as Rec), ...key(r) }), 202),
    R('POST', '/v1/collections', (r) => engine.startCollection(r.ctx, { ...body(r), ...key(r) } as never), 202),
    R('GET', '/v1/collections', (r) => engine.listRuns(r.ctx, q(r, ['sourceId', 'state', 'limit']))),
    R('GET', '/v1/collections/:id', (r) => engine.getRun(r.ctx, r.params.id as string)),
    R('GET', '/v1/collections/:id/coverage', (r) => engine.coverage(r.ctx, { runId: r.params.id as string })),
    R('POST', '/v1/collections/:id/control', (r) => engine.controlRun(r.ctx, r.params.id as string, body(r).action)),
    R('POST', '/v1/acquisitions', (r) => engine.acquire(r.ctx, { ...body(r), ...key(r) } as never), 202),
    R('GET', '/v1/acquisitions/:id', (r) => engine.getAcquisition(r.ctx, r.params.id as string)),
    R('GET', '/v1/acquisitions/:id/bytes', async (r) => { const b = await engine.getAcquisitionBytes(r.ctx, r.params.id as string); return { bytes: b.bytes, headers: { 'content-type': 'application/octet-stream', 'x-media-type': b.mediaType, 'x-sha256': b.sha256, 'content-disposition': 'attachment' } }; }),
    R('POST', '/v1/acquisitions/:id/extract-leads', (r) => engine.extractLeadsFromAcquisition(r.ctx, r.params.id as string, (r.body ?? {}) as never)),
    R('GET', '/v1/receipts', (r) => engine.listReceipts(r.ctx, q(r, ['runId', 'itemId', 'limit']))),
    R('GET', '/v1/receipts/:id', (r) => engine.getReceipt(r.ctx, r.params.id as string)),
    R('GET', '/v1/items', (r) => engine.listItems(r.ctx, q(r, ['sourceId', 'runId', 'state', 'limit', 'after']))),
    R('GET', '/v1/items/:id', (r) => engine.getItem(r.ctx, r.params.id as string)),
    R('GET', '/v1/failures', (r) => engine.listFailures(r.ctx, q(r, ['sourceId', 'state', 'limit']))),
    R('GET', '/v1/gaps', (r) => engine.listGaps(r.ctx, q(r, ['sourceId', 'runId', 'kind', 'state', 'limit']))),
    R('POST', '/v1/gaps/:id/resolve', (r) => engine.resolveGap(r.ctx, r.params.id as string, body(r) as never)),
    R('GET', '/v1/families/:id', (r) => engine.getFamily(r.ctx, r.params.id as string)),
    R('POST', '/v1/corroboration', (r) => engine.corroboration(r.ctx, body(r) as never)),
    R('POST', '/v1/discovery/searches', (r) => engine.searchSource(r.ctx, { ...body(r), ...key(r) } as never), 202),
    R('GET', '/v1/discovery/searches', (r) => engine.listSearchAttempts(r.ctx, q(r, ['sourceId', 'questionRef', 'limit']))),
    R('GET', '/v1/discovery/searches/:id', (r) => engine.getSearchAttempt(r.ctx, r.params.id as string)),
    R('POST', '/v1/imports', (r) => { const b = body(r); return engine.importArchive(r.ctx, { sourceId: b.sourceId, format: b.format, ...(typeof b.bytesBase64 === 'string' ? { bytes: new Uint8Array(Buffer.from(b.bytesBase64, 'base64')) } : {}), ...(typeof b.path === 'string' ? { path: b.path } : {}), ...(b.manifest === undefined ? {} : { manifest: b.manifest }), ...key(r) }); }, 201),
    R('POST', '/v1/leads', (r) => engine.createLead(r.ctx, { ...body(r), ...key(r) } as LeadInput), 201),
    R('GET', '/v1/leads', (r) => engine.listLeads(r.ctx, q(r, ['questionRef', 'sourceItemRef', 'limit']))),
    R('GET', '/v1/leads/:id', (r) => engine.getLead(r.ctx, r.params.id as string)),
    R('POST', '/v1/leads/:id/identity', (r) => engine.setLeadIdentity(r.ctx, r.params.id as string, body(r) as never)),
    R('POST', '/v1/leads/:id/routes/:routeId/verification', (r) => engine.setRouteVerification(r.ctx, r.params.id as string, r.params.routeId as string, body(r) as never)),
  ];
}
