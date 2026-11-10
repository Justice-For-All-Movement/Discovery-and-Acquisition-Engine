// SSRF-defended retrieval: URL vetting, self-resolved and pinned addresses, per-hop revalidation, streaming limits,
// decompression ceiling, content sniffing and robots.txt evaluation. No cookies are ever sent or stored.
import { request as httpRequest } from 'node:http';
import type { IncomingMessage, IncomingHttpHeaders } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { createHash } from 'node:crypto';
import { Transform, pipeline } from 'node:stream';
import type { Readable } from 'node:stream';
import { createBrotliDecompress, createGunzip, createInflate } from 'node:zlib';

export type ResolvedAddress = Readonly<{ address: string; family: number }>;
export type Resolver = (hostname: string) => Promise<readonly ResolvedAddress[]>;
export type FetchPolicy = Readonly<{
  userAgent: string;
  /** Exact `host:port` entries allowed to resolve to non-public addresses (tests / deliberate deployment choice). */
  allowedPrivateHosts: readonly string[];
  allowedPorts: readonly number[];
  maxRedirects: number;
  maxBytes: number;
  maxDecompressedBytes: number;
  timeoutMs: number;
  resolver?: Resolver;
}>;
export type FetchRequest = Readonly<{
  url: string;
  headers?: Readonly<Record<string, string>>;
  /** Sent only to hops whose origin equals `origin` exactly. */
  credential?: Readonly<{ origin: string; header: string; value: string }>;
  signal?: AbortSignal;
  maxBytes?: number;
}>;
export type RedirectHop = Readonly<{ url: string; status: number; location: string; ip: string | null }>;
export type FetchOutcome = Readonly<{
  ok: boolean;
  /** ok | not_modified | http_error | blocked_url | blocked_address | dns_failed | too_many_redirects | redirect_loop | timeout | cancelled | too_large | decompression_limit | unsupported_encoding | network_error */
  code: string;
  message: string;
  requestUrl: string; finalUrl: string; redirects: readonly RedirectHop[]; resolvedIp: string | null;
  status: number | null; headers: Readonly<Record<string, string>>;
  bytes: Uint8Array | null; sha256: string | null; size: number | null;
  mediaType: string | null; declaredMediaType: string | null;
  credentialSent: boolean; startedAt: string; finishedAt: string;
}>;

export class FetchBlock extends Error {
  readonly code: string;
  constructor(code: string, message: string) { super(message); this.code = code; }
}

// ───────────────────────────── Address classification ─────────────────────────────
/** Returns null for a publicly routable IPv4 address, otherwise the reason it is refused. */
export function ipv4Refusal(ip: string): string | null {
  if (isIP(ip) !== 4) return 'not_ipv4';
  const [a, b, c] = ip.split('.').map(Number) as [number, number, number, number];
  if (a === 0) return 'unspecified';
  if (a === 10) return 'private';
  if (a === 127) return 'loopback';
  if (a === 100 && b >= 64 && b <= 127) return 'cgnat';
  if (a === 169 && b === 254) return 'link_local_or_metadata';
  if (a === 172 && b >= 16 && b <= 31) return 'private';
  if (a === 192 && b === 168) return 'private';
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return 'reserved';
  if (a === 192 && b === 88 && c === 99) return 'reserved';
  if (a === 198 && (b === 18 || b === 19)) return 'benchmark';
  if (a === 198 && b === 51 && c === 100) return 'documentation';
  if (a === 203 && b === 0 && c === 113) return 'documentation';
  if (a >= 224 && a <= 239) return 'multicast';
  if (a >= 240) return 'reserved';
  return null;
}
export function ipv6Bytes(input: string): Uint8Array | null {
  if (isIP(input) !== 6 || input.includes('%')) return null;
  let s = input; let tail: number[] | null = null;
  if (s.includes('.')) {
    const at = s.lastIndexOf(':'); const v4 = s.slice(at + 1);
    if (isIP(v4) !== 4) return null;
    tail = v4.split('.').map(Number); s = `${s.slice(0, at + 1)}0:0`;
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const parse = (h: string): number[] => (h === '' ? [] : h.split(':').map((g) => (/^[0-9a-f]{1,4}$/i.test(g) ? parseInt(g, 16) : NaN)));
  const head = parse(halves[0] ?? ''); const rest = halves.length === 2 ? parse(halves[1] ?? '') : [];
  if ([...head, ...rest].some((n) => Number.isNaN(n))) return null;
  const groups = halves.length === 2 ? [...head, ...new Array<number>(Math.max(0, 8 - head.length - rest.length)).fill(0), ...rest] : head;
  if (groups.length !== 8) return null;
  const out = new Uint8Array(16);
  groups.forEach((g, i) => { out[i * 2] = g >> 8; out[i * 2 + 1] = g & 0xff; });
  if (tail !== null) tail.forEach((v, i) => { out[12 + i] = v; });
  return out;
}
/** Returns null only for global unicast IPv6 (2000::/3) outside transition/documentation ranges. */
export function ipv6Refusal(ip: string): string | null {
  const b = ipv6Bytes(ip);
  if (b === null) return 'not_ipv6';
  const zero = (from: number, to: number): boolean => b.subarray(from, to).every((x) => x === 0);
  if (zero(0, 16)) return 'unspecified';
  if (zero(0, 15) && b[15] === 1) return 'loopback';
  if (zero(0, 10) && b[10] === 0xff && b[11] === 0xff) return 'ipv4_mapped';
  if (zero(0, 12)) return 'ipv4_compatible';
  if (b[0] === 0 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) return 'nat64';
  if (((b[0] as number) & 0xfe) === 0xfc) return 'unique_local';
  if (b[0] === 0xfe && ((b[1] as number) & 0xc0) === 0x80) return 'link_local';
  if (b[0] === 0xfe && ((b[1] as number) & 0xc0) === 0xc0) return 'site_local';
  if (b[0] === 0xff) return 'multicast';
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return 'documentation';
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0 && b[3] === 0) return 'teredo';
  if (b[0] === 0x20 && b[1] === 0x02) return '6to4';
  if (((b[0] as number) & 0xe0) !== 0x20) return 'not_global_unicast';
  return null;
}
export function addressRefusal(ip: string): string | null {
  const v = isIP(ip);
  return v === 4 ? ipv4Refusal(ip) : v === 6 ? ipv6Refusal(ip) : 'not_an_address';
}

// ───────────────────────────── URL vetting ─────────────────────────────
export type VettedUrl = Readonly<{ url: URL; hostname: string; port: number; hostPort: string; privateAllowed: boolean }>;
export function vetUrl(raw: string, policy: Pick<FetchPolicy, 'allowedPrivateHosts' | 'allowedPorts'>): VettedUrl {
  let url: URL;
  try { url = new URL(raw); } catch { throw new FetchBlock('blocked_url', 'URL is not parseable'); }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new FetchBlock('blocked_url', 'Only http and https URLs are retrieved');
  if (url.username !== '' || url.password !== '') throw new FetchBlock('blocked_url', 'URLs carrying credentials are refused');
  const hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (hostname === '') throw new FetchBlock('blocked_url', 'URL has no host');
  const port = url.port === '' ? (url.protocol === 'https:' ? 443 : 80) : Number(url.port);
  const hostPort = `${hostname}:${port}`;
  const privateAllowed = policy.allowedPrivateHosts.includes(hostPort);
  if (!privateAllowed && !policy.allowedPorts.includes(port)) throw new FetchBlock('blocked_url', `Port ${port} is not on the allowlist`);
  url.hash = '';
  return { url, hostname, port, hostPort, privateAllowed };
}
const systemResolver: Resolver = async (hostname) => (await dnsLookup(hostname, { all: true, verbatim: true })).map((a) => ({ address: a.address, family: a.family }));

/** Resolves once and returns the single address the connection will be pinned to. Every answer must be public. */
export async function resolveVetted(v: VettedUrl, policy: Pick<FetchPolicy, 'resolver'>): Promise<ResolvedAddress> {
  let answers: readonly ResolvedAddress[];
  if (isIP(v.hostname) !== 0) answers = [{ address: v.hostname, family: isIP(v.hostname) }];
  else {
    try { answers = await (policy.resolver ?? systemResolver)(v.hostname); }
    catch { throw new FetchBlock('dns_failed', 'Host name did not resolve'); }
  }
  answers = answers.map((a) => ({ address: String(a.address), family: isIP(String(a.address)) }));
  if (answers.length === 0 || answers.some((a) => a.family === 0)) throw new FetchBlock('dns_failed', 'Host name did not resolve to an address');
  if (!v.privateAllowed) {
    for (const a of answers) {
      const why = addressRefusal(a.address);
      if (why !== null) throw new FetchBlock('blocked_address', `Destination address is not public (${why})`);
    }
  }
  return answers[0] as ResolvedAddress;
}

// ───────────────────────────── Sniffing ─────────────────────────────
const starts = (b: Uint8Array, sig: readonly number[], at = 0): boolean => sig.every((x, i) => b[at + i] === x);
export function sniffMediaType(bytes: Uint8Array, declared: string | null): string {
  if (bytes.length === 0) return declared ?? 'application/octet-stream';
  if (starts(bytes, [0x25, 0x50, 0x44, 0x46, 0x2d])) return 'application/pdf';
  if (starts(bytes, [0x50, 0x4b, 0x03, 0x04]) || starts(bytes, [0x50, 0x4b, 0x05, 0x06])) return 'application/zip';
  if (starts(bytes, [0x89, 0x50, 0x4e, 0x47])) return 'image/png';
  if (starts(bytes, [0xff, 0xd8, 0xff])) return 'image/jpeg';
  if (starts(bytes, [0x47, 0x49, 0x46, 0x38])) return 'image/gif';
  if (starts(bytes, [0x1f, 0x8b])) return 'application/gzip';
  if (starts(bytes, [0x57, 0x41, 0x52, 0x43, 0x2f])) return 'application/warc';
  const head = Buffer.from(bytes.subarray(0, 2048)).toString('latin1').replace(/^﻿|^\xEF\xBB\xBF/, '').trimStart().toLowerCase();
  if (/^<\?xml/.test(head) || /^<(rss|feed|urlset|sitemapindex)\b/.test(head)) {
    if (/<rss\b/.test(head)) return 'application/rss+xml';
    if (/<feed\b/.test(head)) return 'application/atom+xml';
    if (/<html\b/.test(head)) return 'application/xhtml+xml';
    return 'application/xml';
  }
  if (/^<!doctype html/.test(head) || /^<html\b/.test(head) || /<(head|body|title)\b/.test(head)) return 'text/html';
  if (bytes.subarray(0, 4096).includes(0)) return 'application/octet-stream';
  if (head.startsWith('{') || head.startsWith('[')) {
    if (declared !== null && /json/.test(declared)) return 'application/json';
    if (bytes.length <= 4 * 1024 * 1024) { try { JSON.parse(Buffer.from(bytes).toString('utf8')); return 'application/json'; } catch { /* not JSON */ } }
  }
  if (declared !== null && /^(text\/|application\/(json|xml|[a-z.+-]*\+xml|[a-z.+-]*\+json))/.test(declared)) return declared;
  try { new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, 65536 - (bytes.length > 65536 ? 4 : 0))); return 'text/plain'; } catch { return 'application/octet-stream'; }
}

// ───────────────────────────── One hop ─────────────────────────────
const KEEP_HEADERS = ['content-type', 'content-length', 'content-encoding', 'content-disposition', 'content-language', 'etag', 'last-modified', 'date', 'expires', 'cache-control', 'link', 'location', 'retry-after', 'x-robots-tag', 'cf-mitigated', 'www-authenticate'];
function selectedHeaders(h: IncomingHttpHeaders): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of KEEP_HEADERS) { const v = h[k]; if (v !== undefined) out[k] = (Array.isArray(v) ? v.join(', ') : String(v)).slice(0, 2000); }
  if (out['www-authenticate'] !== undefined) out['www-authenticate'] = (out['www-authenticate'].split(/\s/)[0] ?? '').slice(0, 40);
  return out;
}
type HopResult = { status: number; headers: IncomingHttpHeaders; ip: string | null; body: Buffer | null };

function hop(v: VettedUrl, pin: ResolvedAddress, headers: Record<string, string>, signal: AbortSignal, readBody: (status: number) => boolean, maxBytes: number, maxDecoded: number): Promise<HopResult> {
  return new Promise((resolvePromise, reject) => {
    let settled = false;
    const fail = (e: unknown): void => { if (!settled) { settled = true; reject(e); } };
    const secure = v.url.protocol === 'https:';
    const lookup = (_host: string, opts: unknown, cb: (...args: unknown[]) => void): void => {
      if (opts !== null && typeof opts === 'object' && (opts as { all?: boolean }).all === true) cb(null, [{ address: pin.address, family: pin.family }]);
      else cb(null, pin.address, pin.family);
    };
    const req = (secure ? httpsRequest : httpRequest)({
      protocol: v.url.protocol, host: v.hostname, port: v.port, path: `${v.url.pathname}${v.url.search}`, method: 'GET', headers,
      agent: false, lookup: lookup as never, signal, ...(secure && isIP(v.hostname) === 0 ? { servername: v.hostname } : {}),
    }, (res: IncomingMessage) => {
      const ip = res.socket.remoteAddress ?? null;
      const norm = (x: string | null): string => (x ?? '').replace(/^::ffff:/i, '');
      if (ip === null || (isIP(v.hostname) === 0 && norm(ip) !== norm(pin.address))) { req.destroy(); return fail(new FetchBlock('blocked_address', 'Connection did not reach the vetted address')); }
      const status = res.statusCode ?? 0;
      if (!readBody(status)) { res.destroy(); settled = true; return resolvePromise({ status, headers: res.headers, ip, body: null }); }
      const declaredLength = Number(res.headers['content-length'] ?? NaN);
      if (Number.isFinite(declaredLength) && declaredLength > maxBytes) { req.destroy(); return fail(new FetchBlock('too_large', `Declared length ${declaredLength} exceeds the byte ceiling`)); }
      let raw = 0;
      const counter = new Transform({ transform(chunk: Buffer, _enc, cb) { raw += chunk.byteLength; if (raw > maxBytes) cb(new FetchBlock('too_large', 'Response exceeds the byte ceiling')); else cb(null, chunk); } });
      const encoding = String(res.headers['content-encoding'] ?? 'identity').trim().toLowerCase();
      const decoder = encoding === '' || encoding === 'identity' ? null : encoding === 'gzip' || encoding === 'x-gzip' ? createGunzip() : encoding === 'deflate' ? createInflate() : encoding === 'br' ? createBrotliDecompress() : undefined;
      if (decoder === undefined) { req.destroy(); return fail(new FetchBlock('unsupported_encoding', 'Unsupported content encoding')); }
      const chunks: Buffer[] = []; let decoded = 0;
      const done = (error: unknown): void => {
        if (error) { req.destroy(); fail(error); }
      };
      const out: Readable = decoder === null ? pipeline(res, counter, done) : pipeline(res, counter, decoder, done);
      out.on('data', (chunk: Buffer) => {
        decoded += chunk.byteLength;
        if (decoded > maxDecoded) { out.destroy(new FetchBlock(decoder === null ? 'too_large' : 'decompression_limit', 'Decoded response exceeds the expansion ceiling')); return; }
        chunks.push(chunk);
      });
      out.on('end', () => { if (!settled) { settled = true; resolvePromise({ status, headers: res.headers, ip, body: Buffer.concat(chunks) }); } });
    });
    req.on('error', fail);
    req.end();
  });
}

function outcomeBase(request: FetchRequest, startedAt: string) {
  return { ok: false, message: '', requestUrl: request.url, finalUrl: request.url, redirects: [] as RedirectHop[], resolvedIp: null as string | null, status: null as number | null, headers: {} as Record<string, string>, bytes: null as Uint8Array | null, sha256: null as string | null, size: null as number | null, mediaType: null as string | null, declaredMediaType: null as string | null, credentialSent: false, startedAt };
}

/** Retrieves one URL. Never throws for network or policy outcomes: the outcome code says what happened. */
export async function safeFetch(request: FetchRequest, policy: FetchPolicy): Promise<FetchOutcome> {
  const startedAt = new Date().toISOString();
  const state = outcomeBase(request, startedAt);
  const finish = (code: string, message: string, ok = false): FetchOutcome => ({ ...state, ok, code, message, redirects: [...state.redirects], finishedAt: new Date().toISOString() });
  const timeout = new AbortController();
  const timer = setTimeout(() => timeout.abort(new FetchBlock('timeout', 'Retrieval exceeded its time limit')), policy.timeoutMs);
  const onAbort = (): void => timeout.abort(new FetchBlock('cancelled', 'Retrieval was cancelled'));
  if (request.signal?.aborted === true) onAbort(); else request.signal?.addEventListener('abort', onAbort, { once: true });
  const maxBytes = Math.min(request.maxBytes ?? policy.maxBytes, policy.maxBytes);
  try {
    let current = request.url;
    const visited = new Set<string>();
    for (let hops = 0; ; hops++) {
      const v = vetUrl(current, policy);
      state.finalUrl = v.url.href;
      if (visited.has(v.url.href)) return finish('redirect_loop', 'Redirect loop detected');
      visited.add(v.url.href);
      const pin = await Promise.race([resolveVetted(v, policy), new Promise<never>((_, rej) => { if (timeout.signal.aborted) rej(timeout.signal.reason); else timeout.signal.addEventListener('abort', () => rej(timeout.signal.reason), { once: true }); })]);
      state.resolvedIp = pin.address;
      const headers: Record<string, string> = { 'user-agent': policy.userAgent, accept: '*/*', 'accept-encoding': 'gzip, deflate, br', ...(hops === 0 ? request.headers ?? {} : {}) };
      delete headers.cookie; delete headers.Cookie;
      if (request.credential !== undefined && v.url.origin === request.credential.origin) { headers[request.credential.header] = request.credential.value; state.credentialSent = true; }
      const isRedirect = (s: number): boolean => [301, 302, 303, 307, 308].includes(s);
      const r = await hop(v, pin, headers, timeout.signal, (s) => !isRedirect(s) && s !== 304, maxBytes, policy.maxDecompressedBytes);
      state.status = r.status; state.headers = selectedHeaders(r.headers); state.resolvedIp = r.ip ?? pin.address;
      if (isRedirect(r.status)) {
        const location = String(r.headers.location ?? '');
        if (location === '') return finish('http_error', 'Redirect without a location');
        let next: string;
        try { next = new URL(location, v.url).href; } catch { return finish('blocked_url', 'Redirect location is not parseable'); }
        state.redirects.push({ url: v.url.href, status: r.status, location: next, ip: r.ip });
        if (state.redirects.length > policy.maxRedirects) return finish('too_many_redirects', 'Redirect limit exceeded');
        current = next;
        continue;
      }
      if (r.status === 304) return finish('not_modified', 'Not modified', true);
      const body = r.body ?? Buffer.alloc(0);
      const declared = typeof r.headers['content-type'] === 'string' ? (r.headers['content-type'].split(';')[0] ?? '').trim().toLowerCase() || null : null;
      state.bytes = new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
      state.size = body.byteLength; state.sha256 = createHash('sha256').update(body).digest('hex');
      state.declaredMediaType = declared; state.mediaType = sniffMediaType(state.bytes, declared);
      if (r.status >= 200 && r.status < 300) return finish('ok', 'Retrieved', true);
      return finish('http_error', `HTTP ${r.status}`);
    }
  } catch (error) {
    const reason = timeout.signal.aborted && timeout.signal.reason instanceof FetchBlock ? timeout.signal.reason : error;
    if (reason instanceof FetchBlock) return finish(reason.code, reason.message);
    const code = (error as NodeJS.ErrnoException)?.code ?? '';
    if (code === 'Z_BUF_ERROR' || code === 'Z_DATA_ERROR' || /^ERR_BROTLI|^ERR_ZLIB/.test(code)) return finish('network_error', 'Response body could not be decoded');
    return finish('network_error', `Connection failed${/^[A-Z_]{3,40}$/.test(code) ? ` (${code})` : ''}`);
  } finally {
    clearTimeout(timer);
    request.signal?.removeEventListener('abort', onAbort);
  }
}

// ───────────────────────────── robots.txt (RFC 9309) ─────────────────────────────
export type RobotsGroup = Readonly<{ agents: readonly string[]; rules: readonly Readonly<{ allow: boolean; path: string }>[]; crawlDelay: number | null }>;
export function parseRobots(text: string): RobotsGroup[] {
  const groups: { agents: string[]; rules: { allow: boolean; path: string }[]; crawlDelay: number | null }[] = [];
  let current: (typeof groups)[number] | null = null; let lastWasAgent = false;
  for (const rawLine of text.slice(0, 500_000).split(/\r\n|\r|\n/)) {
    const line = rawLine.replace(/#.*$/, '').trim();
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    const key = line.slice(0, colon).trim().toLowerCase(); const value = line.slice(colon + 1).trim();
    if (key === 'user-agent') {
      if (!lastWasAgent || current === null) { current = { agents: [], rules: [], crawlDelay: null }; groups.push(current); }
      current.agents.push(value.toLowerCase()); lastWasAgent = true; continue;
    }
    lastWasAgent = false;
    if (current === null) continue;
    if (key === 'allow' || key === 'disallow') { if (value !== '') current.rules.push({ allow: key === 'allow', path: value }); }
    else if (key === 'crawl-delay') { const n = Number(value); if (Number.isFinite(n) && n >= 0) current.crawlDelay = n; }
  }
  return groups;
}
/** Linear-time robots path match: `*` matches any run, a trailing `$` anchors the end; otherwise the rule is a prefix. */
export function robotsMatch(rule: string, path: string): boolean {
  const anchored = rule.endsWith('$'); const parts = (anchored ? rule.slice(0, -1) : rule).split('*');
  const first = parts[0] as string;
  if (!path.startsWith(first)) return false;
  if (parts.length === 1) return anchored ? path.length === first.length : true;
  let at = first.length;
  for (let i = 1; i < parts.length; i++) {
    const part = parts[i] as string; const last = i === parts.length - 1;
    if (last && anchored) return path.length - part.length >= at && path.endsWith(part);
    const found = path.indexOf(part, at); if (found < 0) return false;
    at = found + part.length;
  }
  return true;
}
export type RobotsDecision = Readonly<{ allowed: boolean; rule: string | null; group: string | null; crawlDelaySeconds: number | null }>;
export function robotsDecide(groups: readonly RobotsGroup[], userAgent: string, pathAndQuery: string): RobotsDecision {
  const token = (userAgent.split(/[\s/]/)[0] ?? '').toLowerCase();
  let chosen: RobotsGroup[] = []; let best = -1; let name: string | null = null;
  for (const g of groups) for (const a of g.agents) {
    if (a !== '*' && a !== '' && token === a && a.length > best) { best = a.length; chosen = groups.filter((x) => x.agents.includes(a)); name = a; }
  }
  if (chosen.length === 0) { chosen = groups.filter((g) => g.agents.includes('*')); name = chosen.length > 0 ? '*' : null; }
  let match: { allow: boolean; path: string } | null = null;
  for (const g of chosen) for (const r of g.rules) {
    if (!robotsMatch(r.path, pathAndQuery)) continue;
    if (match === null || r.path.length > match.path.length || (r.path.length === match.path.length && r.allow)) match = r;
  }
  const delay = chosen.map((g) => g.crawlDelay).find((d) => d !== null) ?? null;
  return { allowed: match === null ? true : match.allow, rule: match === null ? null : `${match.allow ? 'allow' : 'disallow'}: ${match.path}`, group: name, crawlDelaySeconds: delay };
}
