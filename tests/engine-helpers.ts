// Shared fixtures for the service-layer tests: a controlled local HTTP source on 127.0.0.1 and context builders.
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { gzipSync } from 'node:zlib';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DomainError } from '../src/contracts.ts';
import * as kit from '../src/service-kit.ts';
import type { DiscoveryEngine } from '../src/engine/index.ts';

export const ADMIN = process.env.TEST_DATABASE_URL ?? '';
export const needsPg = ADMIN === '' ? { skip: 'TEST_DATABASE_URL is not set; real-PostgreSQL test not executed' } : {};
export const ALL_CAPS = ['discovery:read', 'discovery:configure', 'discovery:acquire', 'discovery:search', 'discovery:read_bytes', 'discovery:read_leads', 'discovery:write_leads', 'discovery:admin', 'discovery:events'];
export const ctx = (over: Partial<kit.ServiceContext> = {}): kit.ServiceContext => ({ tenantId: 't1', projectId: 'p1', purpose: 'test research', requestId: 'req-1', now: new Date().toISOString(), actor: { id: 'researcher-1', kind: 'human', roles: [] }, capabilities: ALL_CAPS, compartments: [], ...over });
export const rejects = async (p: Promise<unknown>, code: string): Promise<void> => {
  try { await p; } catch (e) { if (e instanceof DomainError && e.code === code) return; throw new Error(`expected ${code}, got ${e instanceof DomainError ? e.code : String(e)}`); }
  throw new Error(`expected ${code}, but the call succeeded`);
};
export const tempStore = async (): Promise<{ store: kit.FsObjectStore; dir: string }> => { const dir = await mkdtemp(join(tmpdir(), 'e04-objects-')); return { store: new kit.FsObjectStore(dir), dir }; };
export async function drain(engine: DiscoveryEngine, max = 50): Promise<void> { for (let i = 0; i < max; i++) if (await engine.runWorkerOnce({ limit: 5 }) === 0) return; throw new Error('worker did not drain'); }
export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
export async function until(cond: () => boolean | Promise<boolean>, ms = 10_000): Promise<void> { const end = Date.now() + ms; while (Date.now() < end) { if (await cond()) return; await sleep(15); } throw new Error('condition not reached in time'); }

const ARTICLE = `The harbour authority of the fictional town of Port Example published its annual ledger on a wet Tuesday morning,
and the document shows that the dredging contract was extended twice without a new tender. Council minutes record that the
extension was discussed for eleven minutes. The ledger lists three payments to Example Dredging Limited, each slightly below
the threshold that would have required a public notice. A former clerk, who asked that her role be described only in general
terms, said the files had been moved to the basement archive in the spring. The authority says every payment was lawful and
that the tender rules allow extensions when the works are continuous. Residents interviewed at the quay said they had not
been told about the extension and wanted the minutes to be published in full before the next budget meeting takes place.`;
export const articlePage = (title: string, chrome: string, body = ARTICLE): string => `<!doctype html><html lang="en"><head><title>${title}</title><meta name="description" content="Ledger report"></head><body>
<header><nav><a href="/">Home</a> <a href="/about">${chrome}</a></nav></header><main><article><h1>${title}</h1>${body.split('\n').map((l) => `<p>${l}</p>`).join('')}</article></main><footer>${chrome} footer text, all rights reserved.</footer></body></html>`;
export const PDF = Buffer.concat([Buffer.from('%PDF-1.4\n%\xe2\xe3\xcf\xd3\n', 'latin1'), Buffer.from(Array.from({ length: 2048 }, (_, i) => (i * 37) % 251)), Buffer.from('\n%%EOF\n')]);
export const STAFF_PAGE = `<!doctype html><html><head><title>Records office — staff</title>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","name":"Example Records Office","email":"office@records.example.org","address":{"@type":"PostalAddress","streetAddress":"1 Archive Lane","addressLocality":"Port Example","postalCode":"00001"},
"employee":[{"@type":"Person","name":"Ada Quill","jobTitle":"Head Archivist","email":"mailto:ada.quill@records.example.org","worksFor":{"@type":"Organization","name":"Example Records Office"}}]}</script></head>
<body><main><h1>Our staff</h1><ul>
<li class="staff-member"><h3 class="name">Ada Quill</h3><span class="role">Head Archivist</span> <a href="mailto:ada.quill@records.example.org">Email Ada</a></li>
<li class="staff-member"><h3 class="name">Ben Folio</h3><span class="role">Reading Room Supervisor</span> <a href="mailto:ben.folio@records.example.org">Email</a></li></ul>
<p>Press: <a href="mailto:press@records.example.org">Cy Vellum</a></p>
<section id="contact"><h2>Contact us</h2><p>Write to enquiries@records.example.org or use the form.</p><form action="/contact/send" method="post"><input name="m"></form>
<address>Example Records Office, 1 Archive Lane, Port Example 00001</address></section></main></body></html>`;

export type Fixture = {
  server: Server; port: number; base: string; hostPort: string; hits: Map<string, number>; times: { path: string; at: number; ua: string | undefined; auth: string | undefined; cookie: string | undefined }[];
  state: { version: number; delayMs: number; otherPort: number; failOnce: Set<string> }; close(): Promise<void>; count(path: string): number;
};
/** Starts the controlled source. Everything it serves is fictional. */
export async function startFixture(): Promise<Fixture> {
  const hits = new Map<string, number>(); const times: Fixture['times'] = [];
  const state = { version: 1, delayMs: 0, otherPort: 9, failOnce: new Set<string>() };
  const send = (res: ServerResponse, status: number, type: string, body: string | Buffer, headers: Record<string, string> = {}): void => { res.writeHead(status, { 'content-type': type, 'set-cookie': 'tracker=1', ...headers }); res.end(body); };
  const html = (res: ServerResponse, body: string, headers: Record<string, string> = {}): void => send(res, 200, 'text/html; charset=utf-8', body, headers);
  const handler = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? '/', 'http://x'); const path = `${url.pathname}${url.search}`;
    hits.set(path, (hits.get(path) ?? 0) + 1); times.push({ path, at: Date.now(), ua: req.headers['user-agent'], auth: req.headers.authorization as string | undefined, cookie: req.headers.cookie });
    if (state.delayMs > 0 && url.pathname !== '/robots.txt') await sleep(state.delayMs);
    const p = url.pathname; const page = Number(url.searchParams.get('page') ?? 1);
    if (p === '/robots.txt') return send(res, 200, 'text/plain', 'User-agent: *\nDisallow: /private/\nAllow: /\n');
    if (state.failOnce.delete(path)) return send(res, 503, 'text/plain', 'try later', { 'retry-after': '0' });
    if (p === '/index') {
      const sets: Record<number, string[]> = {
        1: ['/docs/one.html', '/files/report.pdf', '/docs/missing.html', '/docs/copy-of-one.html'],
        2: ['/docs/mirror-of-one.html', '/docs/error.html', '/private/secret.html', '/docs/paywall.html', '/docs/one.html'],
        3: ['/docs/big.bin', '/docs/loop-a', '/docs/to-private', '/docs/two.html', '/docs/slow.html', '/docs/captcha.html'],
      };
      const links = (sets[page] ?? []).map((h) => `<li><a href="${h}?utm_source=index">Entry ${h}</a></li>`).join('');
      return html(res, `<html><head><title>Index ${page}</title>${page < 3 ? `<link rel="next" href="/index?page=${page + 1}">` : ''}</head><body><a href="/about">About</a><ul>${links}</ul></body></html>`);
    }
    if (p === '/plain-index') { // small clean collection used for resume, pause and rate tests
      const per = Number(url.searchParams.get('per') ?? 3); const pages = Number(url.searchParams.get('pages') ?? 4); const tag = url.searchParams.get('tag') ?? 'x';
      const links = Array.from({ length: per }, (_, i) => `<a href="/clean/${tag}-${page}-${i}.html">Doc ${page}-${i}</a>`).join(' ');
      const next = new URL(url.href); next.searchParams.set('page', String(page + 1));
      return html(res, `<html><head>${page < pages ? `<link rel="next" href="${next.pathname}${next.search}">` : ''}</head><body>${links}</body></html>`);
    }
    if (p.startsWith('/clean/')) return html(res, articlePage(`Clean ${p}`, 'Clean site', `Unique body for ${p}. `.repeat(30)));
    if (p === '/docs/one.html' || p === '/docs/copy-of-one.html') {
      const etag = `"one-v${state.version}"`;
      if (req.headers['if-none-match'] === etag) { res.writeHead(304, { etag }); return void res.end(); }
      return html(res, articlePage('Harbour ledger shows untendered extension', 'Example Gazette', state.version === 1 ? undefined : `${ARTICLE}\nCorrection: the discussion lasted fourteen minutes, not eleven.`), { etag, 'last-modified': 'Tue, 03 Mar 2026 10:00:00 GMT' });
    }
    if (p === '/docs/mirror-of-one.html') return html(res, articlePage('Harbour ledger shows untendered extension — syndicated', 'Coastal Mirror Network'));
    if (p === '/docs/two.html') return send(res, 200, 'text/html', gzipSync(articlePage('Budget meeting postponed', 'Example Gazette', 'The council postponed its budget meeting to the following month after the clerk reported that the printed papers had not arrived from the supplier in time for members to read them. '.repeat(4))), { 'content-encoding': 'gzip', etag: '"two"' });
    if (p === '/files/report.pdf' && req.headers['if-none-match'] === '"pdf1"') { res.writeHead(304, { etag: '"pdf1"' }); return void res.end(); }
    if (p === '/files/report.pdf') return send(res, 200, 'application/octet-stream', PDF, { 'content-disposition': 'attachment; filename="annual report.pdf"', etag: '"pdf1"' });
    if (p === '/docs/missing.html') return send(res, 404, 'text/html', '<html><body>gone</body></html>');
    if (p === '/docs/error.html') return send(res, 500, 'text/plain', 'boom');
    if (p === '/docs/paywall.html') return send(res, 403, 'text/html', '<html><body>Subscribers only</body></html>');
    if (p === '/docs/captcha.html') return html(res, '<html><head><title>Just a moment</title></head><body><form id="challenge-form"><div class="g-recaptcha"></div></form></body></html>');
    if (p === '/private/secret.html') return html(res, '<html><body>should never be fetched</body></html>');
    if (p === '/docs/big.bin') return send(res, 200, 'application/octet-stream', Buffer.alloc(600_000, 7));
    if (p === '/docs/bomb.html') return send(res, 200, 'text/html', gzipSync(Buffer.alloc(8_000_000, 0x20)), { 'content-encoding': 'gzip' });
    if (p === '/docs/loop-a') { res.writeHead(302, { location: '/docs/loop-b' }); return void res.end(); }
    if (p === '/docs/loop-b') { res.writeHead(302, { location: '/docs/loop-a' }); return void res.end(); }
    if (p === '/docs/to-private') { res.writeHead(302, { location: `http://127.0.0.1:${state.otherPort}/internal/admin` }); return void res.end(); }
    if (p === '/docs/to-metadata') { res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data/' }); return void res.end(); }
    if (p === '/docs/hops') { const n = Number(url.searchParams.get('n') ?? 0); res.writeHead(302, { location: `/docs/hops?n=${n + 1}` }); return void res.end(); }
    if (p === '/docs/moved.html') { res.writeHead(301, { location: '/docs/two.html' }); return void res.end(); }
    if (p === '/docs/slow.html') return; // never answers
    if (p === '/staff.html') return html(res, STAFF_PAGE);
    if (p === '/protected/list') { if (req.headers.authorization !== 'Bearer s3cr3t-token-value') return send(res, 401, 'text/plain', 'auth required', { 'www-authenticate': 'Bearer realm="x"' }); return html(res, '<html><body><a href="/clean/prot-1-0.html">P</a></body></html>'); }
    if (p === '/api/items') {
      const cursor = url.searchParams.get('cursor') ?? 'c0'; const n = Number(cursor.slice(1));
      const items = n > 2 ? [] : [0, 1].map((i) => ({ id: `rec-${n}-${i}`, title: `Record ${n}-${i}`, url: `/clean/api-${n}-${i}.html`, year: 2020 + n, body: 'x'.repeat(10) }));
      return send(res, 200, 'application/json', JSON.stringify({ data: { items }, next_cursor: n >= 2 ? null : `c${n + 1}`, total: 6 }));
    }
    if (p === '/sitemap.xml') return send(res, 200, 'application/xml', `<?xml version="1.0"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>http://127.0.0.1:${port}/sitemap-a.xml</loc></sitemap><sitemap><loc>http://127.0.0.1:${port}/sitemap-b.xml</loc></sitemap></sitemapindex>`);
    if (p === '/sitemap-a.xml' || p === '/sitemap-b.xml') { const t = p.includes('-a') ? 'a' : 'b'; return send(res, 200, 'application/xml', `<?xml version="1.0"?><urlset>${[0, 1].map((i) => `<url><loc>http://127.0.0.1:${port}/clean/sm-${t}-${i}.html</loc><lastmod>2026-01-0${i + 1}</lastmod></url>`).join('')}</urlset>`); }
    if (p === '/feed.xml') return send(res, 200, 'application/rss+xml', `<?xml version="1.0"?><rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel><title>Example feed</title>${page < 2 ? `<atom:link rel="next" href="/feed.xml?page=${page + 1}"/>` : ''}
        ${[0, 1].map((i) => `<item><title>Feed story ${page}-${i} &amp; more</title><link>/clean/feed-${page}-${i}.html</link><guid>g-${page}-${i}</guid><pubDate>Mon, 02 Mar 2026 0${i}:00:00 GMT</pubDate><description><![CDATA[Summary <b>${i}</b>]]></description></item>`).join('')}</channel></rss>`);
    if (p === '/search') {
      const q = url.searchParams.get('q') ?? '';
      if (q === 'explode') return send(res, 500, 'text/plain', 'search down');
      const results = q === 'nothing' ? [] : [{ id: 's1', title: `Result for ${q}`, url: '/clean/search-1-0.html' }, { id: 's2', title: 'Second', url: '/clean/search-1-1.html' }];
      return send(res, 200, 'application/json', JSON.stringify({ results, total: results.length }));
    }
    if (p === '/opensearch') return send(res, 200, 'application/atom+xml', `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom" xmlns:opensearch="http://a9.com/-/spec/opensearch/1.1/"><opensearch:totalResults>1</opensearch:totalResults><entry><title>OS hit ${url.searchParams.get('q')}</title><link rel="alternate" href="/clean/os-1-0.html"/><id>os1</id><updated>2026-03-01T00:00:00Z</updated></entry></feed>`);
    return send(res, 404, 'text/plain', 'not found');
  };
  const server = createServer((req, res) => { void handler(req, res); });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  return { server, port, base: `http://127.0.0.1:${port}`, hostPort: `127.0.0.1:${port}`, hits, times, state, count: (path) => hits.get(path) ?? 0,
    close: () => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()); }) };
}
/** A second loopback listener standing in for an internal service that must never be reached. */
export async function startInternal(): Promise<{ port: number; hits: () => number; close(): Promise<void> }> {
  let n = 0; const server = createServer((_req, res) => { n++; res.end('internal secret'); });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return { port: (server.address() as { port: number }).port, hits: () => n, close: () => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()); }) };
}
/** In-test EvidencePort that keeps what it is handed, to check the hand-over contract. */
export function recordingEvidencePort(): kit.EvidencePort & { accepted: { ctx: kit.ServiceContext; input: Parameters<kit.EvidencePort['accept']>[1]; info: kit.EvidenceVersionInfo }[] } {
  const accepted: { ctx: kit.ServiceContext; input: Parameters<kit.EvidencePort['accept']>[1]; info: kit.EvidenceVersionInfo }[] = [];
  const byKey = new Map<string, kit.EvidenceVersionInfo>(); const bytesByRef = new Map<string, Uint8Array>();
  return {
    accepted,
    async describe(_c, ref) { return [...byKey.values()].find((i) => i.ref === ref) ?? null; },
    async getBytes(_c, ref) { const b = bytesByRef.get(ref); if (b === undefined) throw new DomainError('not_found', 'Not found'); return b; },
    async accept(c, input) {
      const key = `${c.tenantId}/${input.idempotencyKey ?? Math.random()}`; const prior = byKey.get(key); if (prior !== undefined) return prior;
      const id = `ev${byKey.size + 1}`; const sha256 = (await import('node:crypto')).createHash('sha256').update(input.bytes).digest('hex');
      const info: kit.EvidenceVersionInfo = { ref: kit.uref('E05', 'evidence_version', id, 1), evidenceId: id, revision: 1, sha256, size: input.bytes.byteLength, mediaType: input.mediaType, filename: input.filename, compartment: input.compartment ?? null, available: false };
      byKey.set(key, info); bytesByRef.set(info.ref, Uint8Array.from(input.bytes)); accepted.push({ ctx: c, input, info }); return info;
    },
    async addDerivative() { throw new DomainError('unavailable', 'not used'); },
  };
}
