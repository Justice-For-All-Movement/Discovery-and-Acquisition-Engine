import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import * as kit from '../src/service-kit.ts';
import { createEngine, migrate, routes, SCHEMA } from '../src/engine/index.ts';
import type { DiscoveryConfig, DiscoveryEngine } from '../src/engine/index.ts';
import { ADMIN, ALL_CAPS, ctx, drain, needsPg, rejects, sleep, startFixture, tempStore, until } from './engine-helpers.ts';
import type { Fixture } from './engine-helpers.ts';

const config = (hostPort: string, over: DiscoveryConfig = {}): DiscoveryConfig => ({ userAgent: 'PamTestBot/1.0 (+https://example.org/bot)', allowedPrivateHosts: [hostPort], defaultMinIntervalMs: 0, timeoutMs: 2000, maxBytes: 200_000, pageRetryBaseMs: 10, retryBaseMs: 10, ...over });
const plain = (engine: DiscoveryEngine, fx: Fixture, tag: string, per: number, pages: number, minIntervalMs = 0) => engine.createSource(ctx(), { name: `Plain ${tag}`, kind: 'html_index', baseUrl: `${fx.base}/plain-index?per=${per}&pages=${pages}&tag=${tag}`, config: { itemPattern: '/clean/' }, accessTerms: 'Public pages', rateLimit: { minIntervalMs } });
const cleanHits = (fx: Fixture, tag: string): number => fx.times.filter((t) => t.path.startsWith(`/clean/${tag}-`)).length;

test('crash mid-run (SIGKILL) then resume from the checkpoint without missing, double-counting or re-downloading', needsPg, async () => {
  const fx = await startFixture();
  try {
    await kit.withDisposableDatabase(pg, ADMIN, async (url, sql) => {
      await migrate(sql);
      const { store, dir } = await tempStore();
      const engine = createEngine({ sql, objects: store, config: config(fx.hostPort) });
      const source = await plain(engine, fx, 'cr', 3, 4);
      const run = await engine.startCollection(ctx(), { sourceId: source.id });
      fx.state.delayMs = 40;
      const crashWorker = async (stopWhen: () => boolean): Promise<void> => {
        const child = spawn(process.execPath, ['tests/engine-worker-child.ts'], { env: { ...process.env, E04_CHILD_DB: url, E04_CHILD_OBJECTS: dir, E04_CHILD_CONFIG: JSON.stringify(config(fx.hostPort, { leaseMs: 400 })) }, stdio: 'ignore' });
        const exited = new Promise<void>((r) => child.once('exit', () => r()));
        await until(stopWhen, 20_000); child.kill('SIGKILL'); await exited;
      };
      // Crash 1: while walking index pages (two pages committed, third in flight).
      await crashWorker(() => fx.times.some((t) => t.path.includes('tag=cr&page=3')));
      let state = await engine.getRun(ctx(), run.id); assert.equal(state.state, 'running'); assert.equal(state.checkpoint.phase, 'pages'); assert.ok(state.checkpoint.pagesDone >= 2 && state.checkpoint.pagesDone <= 3);
      const pagesBefore = state.checkpoint.pagesDone;
      // Crash 2: while downloading originals.
      await crashWorker(() => cleanHits(fx, 'cr') >= 5);
      state = await engine.getRun(ctx(), run.id); assert.equal(state.state, 'running'); assert.equal(state.checkpoint.phase, 'items');
      const mid = await engine.coverage(ctx(), { runId: run.id }); assert.equal(mid.discovered, 12); assert.ok(mid.acquiredBytes >= 3 && mid.acquiredBytes < 12, `acquired before crash: ${mid.acquiredBytes}`); assert.equal(mid.pending, 12 - mid.acquiredBytes);
      const doneBefore = (await engine.listItems(ctx(), { runId: run.id, state: 'bytes' })).map((i) => new URL(i.url).pathname); const hitsBefore = new Map(doneBefore.map((p) => [p, fx.count(p)]));
      assert.ok([...hitsBefore.values()].every((n) => n === 1));
      // Resume in a fresh worker once the dead worker's lease has expired.
      fx.state.delayMs = 0;
      await until(async () => (await engine.runWorkerOnce()) > 0, 20_000);
      const cov = await engine.coverage(ctx(), { runId: run.id });
      assert.equal(cov.state, 'completed'); assert.deepEqual({ d: cov.discovered, b: cov.acquiredBytes, p: cov.pending, f: cov.failed, n: cov.newItems }, { d: 12, b: 12, p: 0, f: 0, n: 12 });
      for (const [p, n] of hitsBefore) assert.equal(fx.count(p), n, `${p} was not downloaded again after the crash`);
      assert.ok(fx.times.filter((t) => t.path.startsWith('/clean/cr-')).length <= 14, 'at most the two in-flight originals were requested twice');
      const pages = await sql.query(`select seq, url, item_count from ${SCHEMA}.run_pages where run_id=$1 order by seq`, [run.id]);
      assert.deepEqual(pages.map((p) => [p.seq, p.item_count]), [[0, 3], [1, 3], [2, 3], [3, 3]], 'every page checkpointed exactly once');
      assert.ok(fx.times.filter((t) => t.path.startsWith('/plain-index') && t.path.includes('tag=cr')).length <= 4 + (3 - pagesBefore) + 1);
      assert.equal(fx.count('/plain-index?per=3&pages=4&tag=cr'), 1, 'a checkpointed page is not fetched again');
      assert.equal(Number((await sql.query(`select count(*)::int as n from ${SCHEMA}.acquisitions`))[0]!.n), 12);
      assert.equal(Number((await sql.query(`select count(*)::int as n from ${SCHEMA}.items`))[0]!.n), 12);
      assert.equal(Number((await sql.query(`select count(*)::int as n from ${SCHEMA}.receipts where purpose='item' and outcome='ok'`))[0]!.n), 12);
      const job = (await kit.listJobs(sql, SCHEMA, ctx()))[0]!; assert.equal(job.state, 'done'); assert.equal(job.attempts, 3);
    });
  } finally { await fx.close(); }
});

test('pause, resume and cancel are honoured between side effects; page retry; run limits', needsPg, async () => {
  const fx = await startFixture();
  try {
    await kit.withDisposableDatabase(pg, ADMIN, async (_url, sql) => {
      await migrate(sql);
      const engine = createEngine({ sql, objects: (await tempStore()).store, config: config(fx.hostPort) });
      const source = await plain(engine, fx, 'pa', 4, 3);
      const run = await engine.startCollection(ctx(), { sourceId: source.id });
      fx.state.delayMs = 30;
      const worker = engine.runWorkerOnce();
      await until(() => cleanHits(fx, 'pa') >= 3);
      assert.equal((await engine.controlRun(ctx(), run.id, 'pause')).state, 'paused');
      await worker; const hits = cleanHits(fx, 'pa'); await sleep(200);
      assert.equal(cleanHits(fx, 'pa'), hits, 'no request after the pause took effect'); assert.equal(await engine.runWorkerOnce(), 0);
      const paused = await engine.coverage(ctx(), { runId: run.id }); assert.equal(paused.state, 'paused'); assert.equal(paused.discovered, 12); assert.ok(paused.pending >= 8 && paused.acquiredBytes >= 2);
      assert.equal(paused.acquiredBytes + paused.pending, 12);
      assert.equal((await engine.controlRun(ctx(), run.id, 'resume')).state, 'queued'); fx.state.delayMs = 0; await drain(engine);
      const done = await engine.coverage(ctx(), { runId: run.id }); assert.equal(done.state, 'completed'); assert.equal(done.acquiredBytes, 12);
      assert.ok(cleanHits(fx, 'pa') <= 13, 'at most the one in-flight original is requested again');
      await rejects(engine.controlRun(ctx(), run.id, 'pause'), 'invalid_state');
      // Cancel.
      const source2 = await plain(engine, fx, 'ca', 4, 3); const run2 = await engine.startCollection(ctx(), { sourceId: source2.id });
      fx.state.delayMs = 30; const w2 = engine.runWorkerOnce(); await until(() => cleanHits(fx, 'ca') >= 2);
      assert.equal((await engine.controlRun(ctx(), run2.id, 'cancel')).state, 'cancelled'); await w2; fx.state.delayMs = 0;
      const n = cleanHits(fx, 'ca'); await drain(engine); assert.equal(cleanHits(fx, 'ca'), n);
      const cancelled = await engine.coverage(ctx(), { runId: run2.id }); assert.equal(cancelled.state, 'cancelled'); assert.ok(cancelled.pending > 0); assert.equal(cancelled.acquiredBytes + cancelled.pending, 12);
      await rejects(engine.controlRun(ctx(), run2.id, 'resume'), 'invalid_state');
      assert.deepEqual((await engine.audit(ctx(), { subject: `E04:run:${run.id}` })).map((a) => a.action), ['collection.collect_started', 'collection.pause', 'collection.resume', 'collection.completed']);

      // A transient index-page failure is retried inside the run and recorded; nothing is lost.
      const source3 = await plain(engine, fx, 'pr', 2, 2); fx.state.failOnce.add('/plain-index?per=2&pages=2&tag=pr&page=2');
      const run3 = await engine.startCollection(ctx(), { sourceId: source3.id, level: 'links' }); await drain(engine);
      const c3 = await engine.coverage(ctx(), { runId: run3.id }); assert.deepEqual({ d: c3.discovered, l: c3.linkOnly, pages: c3.pages }, { d: 4, l: 4, pages: { fetched: 2, unavailable: 0 } });
      assert.deepEqual((await engine.listReceipts(ctx(), { runId: run3.id })).map((r) => [r.purpose, r.outcome, r.status]), [['index_page', 'ok', 200], ['index_page', 'http_error', 503], ['index_page', 'ok', 200]]);
      assert.equal(cleanHits(fx, 'pr'), 0, 'a links-level run downloads nothing');
      assert.ok((await engine.listItems(ctx(), { runId: run3.id })).every((i) => i.state === 'discovered' && i.currentAcquisition === null));
      // Limits are reported as gaps, never silently truncated.
      const source4 = await plain(engine, fx, 'lim', 3, 4);
      const run4 = await engine.startCollection(ctx(), { sourceId: source4.id, level: 'links', maxPages: 2 }); await drain(engine);
      const c4 = await engine.coverage(ctx(), { runId: run4.id }); assert.equal(c4.discovered, 6); assert.deepEqual(c4.gaps.byKind, { page_limit_reached: 1 }); assert.equal((c4.lastCheckpoint as { truncated: boolean }).truncated, true);
      const run5 = await engine.startCollection(ctx(), { sourceId: source4.id, level: 'links', maxItems: 4 }); await drain(engine);
      const c5 = await engine.coverage(ctx(), { runId: run5.id }); assert.equal(c5.discovered, 4); assert.equal(c5.gaps.byKind.item_limit_reached, 1);
      await rejects(engine.startCollection(ctx(), { sourceId: source4.id, maxPages: 0 }), 'invalid_input');
      // Without a store for originals, a bytes run is refused as unavailable rather than faked.
      const bare = createEngine({ sql, config: config(fx.hostPort) });
      await rejects(bare.startCollection(ctx(), { sourceId: source4.id, level: 'bytes' }), 'unavailable');
      assert.equal((await bare.startCollection(ctx(), { sourceId: source4.id, level: 'metadata', maxPages: 1 })).level, 'metadata'); await drain(bare);
      const meta = await bare.coverage(ctx(), { sourceId: source4.id }); assert.equal(meta.acquiredMetadata, 3); assert.equal(meta.acquiredBytes, 0); assert.equal(meta.bytesAcquired, 0);
      const metaItem = (await bare.listItems(ctx(), { sourceId: source4.id, state: 'metadata_acquired' }))[0]!; const acq = (await bare.getItem(ctx(), metaItem.id)).acquisitions[0];
      assert.equal(acq.level, 'metadata'); assert.equal(acq.storage, 'none'); await rejects(bare.getAcquisitionBytes(ctx(), acq.id), 'invalid_state');
    });
  } finally { await fx.close(); }
});

test('per-host rate limit is shared by two concurrent workers through PostgreSQL', needsPg, async () => {
  const fx = await startFixture();
  try {
    await kit.withDisposableDatabase(pg, ADMIN, async (_url, sql) => {
      await migrate(sql);
      const a = createEngine({ sql, config: config(fx.hostPort, { workerId: 'worker-a' }) }); const b = createEngine({ sql, config: config(fx.hostPort, { workerId: 'worker-b' }) });
      const s1 = await plain(a, fx, 'r1', 1, 4, 120); const s2 = await plain(a, fx, 'r2', 1, 4, 120);
      await a.startCollection(ctx(), { sourceId: s1.id, level: 'links' }); await a.startCollection(ctx(), { sourceId: s2.id, level: 'links' });
      const [na, nb] = await Promise.all([a.runWorkerOnce(), b.runWorkerOnce()]);
      assert.deepEqual([na, nb], [1, 1], 'each worker processed one run concurrently');
      const at = fx.times.map((t) => t.at); const gaps = at.slice(1).map((t, i) => t - (at[i] as number));
      assert.ok(at.length >= 9, `requests: ${at.length}`);
      assert.ok(Math.min(...gaps) >= 95, `requests to one host are spaced by the source interval even across workers: ${gaps.join(',')}`);
      const order = fx.times.filter((t) => t.path.startsWith('/plain-index')).map((t) => (t.path.includes('tag=r1') ? 1 : 2));
      assert.ok(order.slice(1).some((v, i) => v !== order[i]), 'the two runs interleaved');
      assert.equal(Number((await sql.query(`select count(*)::int as n from ${SCHEMA}.host_leases`))[0]!.n), 0, 'concurrency leases are released');
    });
  } finally { await fx.close(); }
});

test('JSON cursor API, sitemap index, RSS, search adapters with attempt records, credentials, robots override, HTTP API', needsPg, async () => {
  const fx = await startFixture();
  try {
    await kit.withDisposableDatabase(pg, ADMIN, async (_url, sql) => {
      await migrate(sql);
      const key = randomBytes(32).toString('base64');
      const engine = createEngine({ sql, objects: (await tempStore()).store, config: config(fx.hostPort, { credentialKey: key }) });
      // JSON API with cursor pagination: record metadata is acquired metadata; documents are fetched only at bytes level.
      const api = await engine.createSource(ctx(), { name: 'Records API', kind: 'json_api', baseUrl: `${fx.base}/api/items`, accessTerms: 'Open API', reuse: 'public_domain',
        config: { itemsPath: 'data.items', urlField: 'url', titleField: 'title', idField: 'id', metadataFields: ['year'], pagination: { type: 'cursor', cursorPath: 'next_cursor', cursorParam: 'cursor' } } });
      const r1 = await engine.startCollection(ctx(), { sourceId: api.id, level: 'metadata' }); await drain(engine);
      const c1 = await engine.coverage(ctx(), { runId: r1.id });
      assert.deepEqual({ d: c1.discovered, m: c1.acquiredMetadata, b: c1.acquiredBytes, pages: c1.pages.fetched, bytes: c1.bytesAcquired }, { d: 6, m: 6, b: 0, pages: 3, bytes: 0 });
      assert.deepEqual(['/api/items', '/api/items?cursor=c1', '/api/items?cursor=c2'].map((p) => fx.count(p)), [1, 1, 1]); assert.equal(cleanHits(fx, 'api'), 0);
      const rec = (await engine.listItems(ctx(), { runId: r1.id })).find((i) => i.title === 'Record 1-0')!; const recAcq = (await engine.getItem(ctx(), rec.id)).acquisitions[0];
      assert.deepEqual(recAcq.metadata, { title: 'Record 1-0', id: 'rec-1-0', year: 2021, fromListing: true }); assert.equal(recAcq.level, 'metadata'); assert.equal(recAcq.reuse, 'public_domain');
      const r2 = await engine.startCollection(ctx(), { sourceId: api.id, level: 'bytes' }); await drain(engine);
      const c2 = await engine.coverage(ctx(), { runId: r2.id }); assert.deepEqual({ d: c2.discovered, b: c2.acquiredBytes, n: c2.newItems }, { d: 6, b: 6, n: 0 });
      assert.equal((await engine.getItem(ctx(), rec.id)).acquisitions.length, 2);
      // Sitemap index → nested sitemaps.
      const sm = await engine.createSource(ctx(), { name: 'Sitemap', kind: 'sitemap', baseUrl: `${fx.base}/sitemap.xml`, accessTerms: 'Public' });
      const r3 = await engine.startCollection(ctx(), { sourceId: sm.id, level: 'links' }); await drain(engine);
      const c3 = await engine.coverage(ctx(), { runId: r3.id }); assert.deepEqual({ d: c3.discovered, l: c3.linkOnly, p: c3.pages.fetched }, { d: 4, l: 4, p: 3 });
      assert.equal((await engine.listItems(ctx(), { runId: r3.id }))[0]!.listing.lastmod.slice(0, 8), '2026-01-');
      // RSS with RFC 5005 paging.
      const feed = await engine.createSource(ctx(), { name: 'Feed', kind: 'feed', baseUrl: `${fx.base}/feed.xml`, accessTerms: 'Public feed' });
      const r4 = await engine.startCollection(ctx(), { sourceId: feed.id, level: 'links' }); await drain(engine);
      const c4 = await engine.coverage(ctx(), { runId: r4.id }); assert.deepEqual({ d: c4.discovered, m: c4.acquiredMetadata, p: c4.pages.fetched }, { d: 4, m: 4, p: 2 });
      const story = (await engine.listItems(ctx(), { runId: r4.id })).find((i) => i.url.endsWith('/clean/feed-1-0.html'))!; assert.equal(story.title, 'Feed story 1-0 & more'); assert.equal(story.listing.summary, 'Summary 0'); assert.equal(story.state, 'metadata_acquired');

      // Search adapters: every query is an attempt record, including zero-result and failed attempts.
      const sj = await engine.createSource(ctx(), { name: 'Search JSON', kind: 'search_json', baseUrl: `${fx.base}/search`, accessTerms: 'Public search', config: { itemsPath: 'results', totalPath: 'total' } });
      const os = await engine.createSource(ctx(), { name: 'OpenSearch', kind: 'search_opensearch', baseUrl: `${fx.base}/opensearch?q={searchTerms}&n={count?}`, accessTerms: 'Public search' });
      const q = 'E08:question:q-9';
      const a1 = await engine.searchSource(ctx(), { sourceId: sj.id, query: 'harbour ledger', questionRef: q, idempotencyKey: 's1' });
      assert.equal((await engine.searchSource(ctx(), { sourceId: sj.id, query: 'harbour ledger', questionRef: q, idempotencyKey: 's1' })).id, a1.id); assert.equal(a1.state, 'queued');
      const a2 = await engine.searchSource(ctx(), { sourceId: sj.id, query: 'nothing', questionRef: q });
      const a3 = await engine.searchSource(ctx(), { sourceId: sj.id, query: 'explode', questionRef: q });
      const a4 = await engine.searchSource(ctx(), { sourceId: os.id, query: 'tender & notice', questionRef: q });
      await drain(engine);
      const attempts = await engine.listSearchAttempts(ctx(), { questionRef: q });
      assert.deepEqual(attempts.map((a) => [a.query, a.state, a.resultCount, a.totalReported]), [['harbour ledger', 'completed', 2, 2], ['nothing', 'completed', 0, 0], ['explode', 'failed', null, null], ['tender & notice', 'completed', 1, 1]]);
      assert.match(attempts[2]!.error, /HTTP 500 after 3 attempts/); assert.equal(fx.count('/search?q=explode'), 3);
      assert.equal(fx.count('/opensearch?q=tender%20%26%20notice&n=20'), 1);
      assert.equal((await engine.getSearchAttempt(ctx(), a2.id)).resultCount, 0); assert.equal((await engine.getSearchAttempt(ctx(), a4.id)).requestUrl, `${fx.base}/opensearch?q=tender%20%26%20notice&n=20`);
      const found = await engine.listItems(ctx(), { runId: kit.parseUref(a1.run).id }); assert.equal(found.length, 2); assert.equal(found[0]!.questionRef, q);
      assert.equal(kit.parseUref(a3.run).kind, 'run'); await rejects(engine.searchSource(ctx(), { sourceId: api.id, query: 'x' }), 'invalid_state'); await rejects(engine.startCollection(ctx(), { sourceId: sj.id }), 'invalid_state');

      // Authorized credential: encrypted at rest, sent only to the source origin, never echoed.
      const prot = await engine.createSource(ctx(), { name: 'Protected', kind: 'html_index', baseUrl: `${fx.base}/protected/list`, config: { itemPattern: '/clean/' }, accessTerms: 'Access by written agreement' });
      const r5 = await engine.startCollection(ctx(), { sourceId: prot.id, level: 'links' }); await drain(engine);
      const c5 = await engine.coverage(ctx(), { runId: r5.id }); assert.equal(c5.discovered, 0); assert.deepEqual(c5.gaps.byKind, { access_restricted: 1 }); assert.equal(fx.count('/protected/list'), 1, 'a 401 is recorded as a gap, not retried');
      await rejects(createEngine({ sql, config: config(fx.hostPort) }).setSourceCredential(ctx(), prot.id, { value: 'Bearer x', authorizationNote: 'n' }), 'unavailable');
      const withCred = await engine.setSourceCredential(ctx(), prot.id, { value: 'Bearer s3cr3t-token-value', authorizationNote: 'Token issued to the project by the archive on request 41' });
      assert.equal(withCred.hasCredential, true); assert.equal(withCred.credential, undefined);
      const r6 = await engine.startCollection(ctx(), { sourceId: prot.id, level: 'links' }); await drain(engine);
      assert.equal((await engine.coverage(ctx(), { runId: r6.id })).discovered, 1);
      const dump = JSON.stringify([await engine.getSource(ctx(), prot.id), await engine.listReceipts(ctx(), { runId: r6.id }), await engine.audit(ctx(), { limit: 1000 }), await engine.inspect(ctx(), prot.ref), await sql.query(`select * from ${SCHEMA}.sources`), await sql.query(`select * from ${SCHEMA}._jobs`)]);
      assert.ok(!dump.includes('s3cr3t-token-value'), 'the credential never appears in API output, receipts, audit, jobs or the database in clear');
      assert.equal((await engine.listReceipts(ctx(), { runId: r6.id })).find((r) => r.purpose === 'index_page')!.credentialUsed, true);
      assert.ok(fx.times.filter((t) => t.auth !== undefined).every((t) => t.path === '/protected/list' || t.path === '/robots.txt'));

      // robots.txt can only be set aside by an explicit, audited human operator decision.
      const news = await engine.createSource(ctx(), { name: 'Gazette single', kind: 'file_list', baseUrl: `${fx.base}/list`, config: { urls: [`${fx.base}/private/secret.html`] }, accessTerms: 'Written permission from the publisher' });
      const r7 = await engine.startCollection(ctx(), { sourceId: news.id }); await drain(engine);
      assert.equal((await engine.coverage(ctx(), { runId: r7.id })).skippedByPolicy, 1); assert.equal(fx.count('/private/secret.html'), 0);
      await rejects(engine.setRobotsPolicy(ctx({ actor: { id: 'agent-1', kind: 'agent', roles: [] } }), news.id, { policy: 'ignore', decisionNote: 'I decided' }), 'forbidden');
      await rejects(engine.setRobotsPolicy(ctx({ capabilities: ['discovery:configure', 'discovery:acquire'] }), news.id, { policy: 'ignore', decisionNote: 'x' }), 'forbidden');
      await rejects(engine.setRobotsPolicy(ctx(), news.id, { policy: 'ignore', decisionNote: '' }), 'invalid_input');
      await engine.setRobotsPolicy(ctx(), news.id, { policy: 'ignore', decisionNote: 'Publisher confirmed in writing that the archive path may be collected' });
      const decision = (await engine.audit(ctx(), { subject: `E04:source:${news.id}` })).find((x) => x.action === 'source.robots_policy_changed')!; assert.equal((decision.detail as { decidedBy: string }).decidedBy, 'researcher-1');
      const r8 = await engine.acquire(ctx(), { sourceId: news.id, url: `${fx.base}/private/secret.html` }); await drain(engine);
      assert.equal(fx.count('/private/secret.html'), 1); const rc = (await engine.listReceipts(ctx(), { runId: r8.id }))[0]!; assert.equal(rc.robots.honoured, false); assert.match(rc.robots.basis, /operator decision/);
      await rejects(engine.acquire(ctx(), { sourceId: news.id, url: 'http://other.example.org/x' }), 'invalid_input'); await rejects(engine.acquire(ctx(), { sourceId: news.id, url: 'file:///etc/passwd' }), 'invalid_input');

      // HTTP surface.
      const keys = kit.generateSigningKey('k1'); const now = Math.floor(Date.now() / 1000);
      const token = (caps: string[], tid = 't1') => kit.signAccessToken({ iss: 'iap', sub: 'u1', kind: 'human', tid, pid: 'p1', roles: [], caps, cmp: [], purpose: 'research', pv: '1', iat: now, exp: now + 300, jti: 'j' }, keys);
      const bareEngine = createEngine({ sql, config: config(fx.hostPort) });
      const server = await kit.serve(kit.createHttpHandler({ name: 'E04', version: '1', routes: routes(bareEngine), verify: kit.createTokenVerifier({ publicKeys: { k1: keys.publicKeyPem } }), health: bareEngine.health }), 0);
      try {
        const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
        const call = async (method: string, path: string, body?: unknown, caps = ALL_CAPS, tid = 't1'): Promise<{ status: number; json: any }> => { const r = await fetch(`${base}${path}`, { method, headers: { authorization: `Bearer ${token(caps, tid)}`, 'content-type': 'application/json', 'idempotency-key': `http-${path}` }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }); return { status: r.status, json: await r.json() }; };
        assert.equal((await fetch(`${base}/healthz`)).status, 200); assert.equal((await fetch(`${base}/v1/sources`)).status, 401); assert.equal((await (await fetch(`${base}/v1/manifest`)).json()).id, 'E04');
        const made = await call('POST', '/v1/sources', { name: 'HTTP source', kind: 'html_index', baseUrl: `${fx.base}/plain-index?per=2&pages=1&tag=http`, config: { itemPattern: '/clean/' }, accessTerms: 'Public' }); assert.equal(made.status, 201);
        assert.equal((await call('POST', '/v1/sources', { name: 'HTTP source', kind: 'html_index', baseUrl: `${fx.base}/plain-index?per=2&pages=1&tag=http`, config: { itemPattern: '/clean/' }, accessTerms: 'Public' })).json.id, made.json.id, 'Idempotency-Key header replays');
        assert.equal((await call('GET', `/v1/sources/${made.json.id}`, undefined, ALL_CAPS, 't2')).status, 404); assert.equal((await call('GET', `/v1/sources/${made.json.id}`, undefined, ['discovery:acquire'])).status, 403);
        const unavailable = await call('POST', '/v1/collections', { sourceId: made.json.id, level: 'bytes' }); assert.equal(unavailable.status, 503); assert.equal(unavailable.json.error.code, 'unavailable');
        const started = await call('POST', '/v1/collections', { sourceId: made.json.id, level: 'links' }); assert.equal(started.status, 202); await drain(bareEngine);
        const cov = await call('GET', `/v1/collections/${started.json.id}/coverage`); assert.equal(cov.json.discovered, 2); assert.equal(cov.json.linkOnly, 2);
        assert.equal((await call('GET', `/v1/items?runId=${started.json.id}&limit=1`)).json.length, 1); assert.equal((await call('POST', `/v1/connectors/${made.json.id}/refresh`, { level: 'links' })).status, 202);
        assert.equal((await call('GET', `/v1/inspect?ref=${encodeURIComponent(made.json.ref)}`)).json.kind, 'source'); assert.equal((await call('GET', '/v1/inspect?ref=E04:source:00000000-0000-4000-8000-000000000000')).status, 404);
        assert.equal((await call('POST', '/v1/discovery/searches', { sourceId: sj.id, query: 'via http' })).status, 202); assert.equal((await call('POST', '/v1/sources', { name: 'bad', kind: 'html_index', baseUrl: 'ftp://example.org/', accessTerms: 'x' })).status, 400);
        assert.equal((await call('GET', '/v1/events', undefined, ['discovery:read'])).status, 403); assert.ok((await call('GET', '/v1/events?limit=5')).json.length >= 0);
      } finally { server.close(); }
    });
  } finally { await fx.close(); }
});
