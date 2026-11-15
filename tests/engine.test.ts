import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import * as kit from '../src/service-kit.ts';
import { createEngine, migrate, SCHEMA } from '../src/engine/index.ts';
import type { DiscoveryConfig } from '../src/engine/index.ts';
import { ADMIN, PDF, ctx, drain, needsPg, recordingEvidencePort, rejects, sleep, startFixture, startInternal, tempStore } from './engine-helpers.ts';

const baseConfig = (hostPort: string, over: DiscoveryConfig = {}): DiscoveryConfig => ({ userAgent: 'PamTestBot/1.0 (+https://example.org/bot)', allowedPrivateHosts: [hostPort], defaultMinIntervalMs: 0, timeoutMs: 700, maxBytes: 200_000, maxDecompressedBytes: 1_000_000, pageRetryBaseMs: 10, retryBaseMs: 10, maxItemAttempts: 3, ...over });
const eventsOf = async (sql: kit.Sql, type?: string): Promise<kit.EngineEvent[]> => { for (let i = 0; ; i++) { const all = await kit.readEvents(sql, SCHEMA, { limit: 1000 }); const pending = Number(((await sql.query(`select count(*)::int as n from ${SCHEMA}._events`))[0] as { n: number }).n); if (all.length === pending || i > 100) return type === undefined ? all : all.filter((e) => e.type === type); await sleep(50); } };

test('collection run: paginated index, receipts, dedupe, mirrors, gaps, failures, coverage, retry, refresh', needsPg, async () => {
  const fx = await startFixture(); const internal = await startInternal(); fx.state.otherPort = internal.port;
  try {
    await kit.withDisposableDatabase(pg, ADMIN, async (_url, sql) => {
      await migrate(sql);
      const { store } = await tempStore();
      const engine = createEngine({ sql, objects: store, config: baseConfig(fx.hostPort) });
      const source = await engine.createSource(ctx(), { name: 'Example Gazette archive', kind: 'html_index', baseUrl: `${fx.base}/index`, config: { itemPattern: '/(docs|files|private)/' }, accessTerms: 'Public website; terms permit reading and citation.', reuse: 'citation_only', rateLimit: { minIntervalMs: 0 }, idempotencyKey: 'src-1' });
      assert.equal((await engine.createSource(ctx(), { name: 'Example Gazette archive', kind: 'html_index', baseUrl: `${fx.base}/index`, config: { itemPattern: '/(docs|files|private)/' }, accessTerms: 'Public website; terms permit reading and citation.', reuse: 'citation_only', rateLimit: { minIntervalMs: 0 }, idempotencyKey: 'src-1' })).id, source.id, 'idempotent replay returns the same source');
      await engine.declareExpected(ctx(), { sourceId: source.id, expected: [{ url: `${fx.base}/docs/one.html` }, { url: `${fx.base}/docs/never-listed.html`, note: 'Cited in the ledger index' }] });

      const run = await engine.startCollection(ctx(), { sourceId: source.id, level: 'bytes', idempotencyKey: 'run-1' });
      assert.equal((await engine.startCollection(ctx(), { sourceId: source.id, level: 'bytes', idempotencyKey: 'run-1' })).id, run.id);
      await rejects(engine.startCollection(ctx(), { sourceId: source.id, level: 'links', idempotencyKey: 'run-1' }), 'idempotency_conflict');
      assert.equal(run.state, 'queued');
      await drain(engine);

      const cov = await engine.coverage(ctx(), { runId: run.id });
      assert.equal(cov.state, 'completed');
      assert.deepEqual({ d: cov.discovered, b: cov.acquiredBytes, m: cov.acquiredMetadata, l: cov.linkOnly, f: cov.failed, s: cov.skippedByPolicy, r: cov.accessRestricted, n: cov.notFound, p: cov.pending },
        { d: 14, b: 5, m: 0, l: 0, f: 2, s: 4, r: 2, n: 1, p: 0 }, 'every discovered item is in exactly one category');
      assert.equal(cov.pages.fetched, 3); assert.equal(cov.newItems, 14); assert.equal(cov.duplicateContent, 1);
      assert.equal(cov.independentSourceFamilies, 3, 'one.html, its byte copy and its mirror are one source family; plus the PDF and two.html');
      assert.equal(cov.bytesAcquired > PDF.byteLength, true);
      assert.deepEqual(cov.gaps.byKind, { not_found: 1, robots_disallowed: 1, access_restricted: 2, too_large: 1, redirect_loop: 1, blocked_target: 1, expected_unresolved: 1 });
      // No double fetch, robots honoured, internal listener never touched, honest UA, no cookies echoed.
      for (const p of ['/index', '/index?page=2', '/index?page=3', '/docs/one.html?utm_source=index', '/files/report.pdf?utm_source=index']) assert.equal(fx.count(p), 1, p);
      assert.equal(fx.count('/private/secret.html?utm_source=index'), 0); assert.equal(internal.hits(), 0); assert.equal(fx.count('/robots.txt'), 1);
      assert.ok(fx.times.every((t) => t.ua === 'PamTestBot/1.0 (+https://example.org/bot)' && t.cookie === undefined && t.auth === undefined));

      const items = await engine.listItems(ctx(), { runId: run.id });
      const by = (suffix: string) => { const i = items.find((x) => x.url.includes(suffix)); assert.ok(i, suffix); return i; };
      assert.equal(by('/docs/one.html').state, 'bytes_acquired'); assert.equal(by('/docs/error.html').state, 'failed'); assert.equal(by('/private/secret.html').state, 'skipped_policy');
      assert.equal(by('/docs/paywall.html').state, 'access_restricted'); assert.equal(by('/docs/captcha.html').state, 'access_restricted'); assert.equal(by('/docs/missing.html').state, 'not_found');
      assert.equal(by('/docs/one.html').canonicalUrl, `${fx.base}/docs/one.html`, 'tracking parameters are removed from the canonical URL');

      // Receipt of a real binary original.
      const pdfItem = await engine.getItem(ctx(), by('/files/report.pdf').id); const pdfAcq = pdfItem.acquisitions[0];
      assert.equal(pdfAcq.level, 'bytes'); assert.equal(pdfAcq.mediaType, 'application/pdf', 'sniffed type overrides the declared octet-stream'); assert.equal(pdfAcq.size, PDF.byteLength);
      assert.equal(pdfAcq.reuse, 'citation_only'); assert.equal(pdfAcq.storage, 'object_store'); assert.ok(pdfAcq.objectKey.startsWith('t1/p1/discovery/originals/'));
      const receipt = await engine.getReceipt(ctx(), kit.parseUref(pdfAcq.receipt).id);
      assert.equal(receipt.requestUrl, `${fx.base}/files/report.pdf?utm_source=index`); assert.equal(receipt.finalUrl, receipt.requestUrl); assert.equal(receipt.resolvedIp, '127.0.0.1'); assert.equal(receipt.status, 200);
      assert.equal(receipt.sha256, pdfAcq.sha256); assert.equal(receipt.size, PDF.byteLength); assert.equal(receipt.mediaType, 'application/pdf'); assert.equal(receipt.declaredMediaType, 'application/octet-stream');
      assert.equal(receipt.headers.etag, '"pdf1"'); assert.equal(receipt.headers['set-cookie'], undefined); assert.equal(receipt.robots.allowed, true); assert.equal(receipt.robots.honoured, true);
      assert.equal(receipt.tool.version, '1.0.0'); assert.equal(receipt.reuse, 'citation_only'); assert.match(receipt.storage.note, /No EvidencePort was supplied/); assert.ok(receipt.startedAt <= receipt.finishedAt);
      await assert.rejects(sql.query(`update ${SCHEMA}.receipts set status=201 where id=$1`, [receipt.id]), /immutable/);
      await assert.rejects(sql.query(`delete from ${SCHEMA}.receipts where id=$1`, [receipt.id]), /immutable/);
      const got = await engine.getAcquisitionBytes(ctx(), pdfAcq.id); assert.deepEqual(Buffer.from(got.bytes), PDF);
      await rejects(engine.getAcquisitionBytes(ctx({ capabilities: ['discovery:read'] }), pdfAcq.id), 'forbidden');
      // gzip transport decoded; redirect receipts.
      const two = (await engine.getItem(ctx(), by('/docs/two.html').id)).acquisitions[0]; assert.equal(two.mediaType, 'text/html'); assert.equal(two.metadata.title, 'Budget meeting postponed');
      const loopReceipt = (await engine.listReceipts(ctx(), { itemId: by('/docs/loop-a').id }))[0]!; assert.equal(loopReceipt.outcome, 'redirect_loop'); assert.equal(loopReceipt.redirectChain.length, 3);
      const privReceipt = (await engine.listReceipts(ctx(), { itemId: by('/docs/to-private').id }))[0]!; assert.equal(privReceipt.outcome, 'blocked_url', 'redirect target port is not on the allowlist'); assert.equal(privReceipt.redirectChain.length, 1);
      const robotsReceipt = (await engine.listReceipts(ctx(), { itemId: by('/private/secret.html').id }))[0]!; assert.equal(robotsReceipt.outcome, 'robots_disallowed'); assert.equal(robotsReceipt.robots.rule, 'disallow: /private/'); assert.equal(robotsReceipt.status, null);
      const wall = (await engine.listReceipts(ctx(), { itemId: by('/docs/paywall.html').id })); assert.equal(wall.length, 1, 'access-restricted responses are not retried'); assert.equal(wall[0]!.outcome, 'access_restricted');

      // Dedupe: identical bytes from two URLs are one content family with two locations; the mirror is same_source_family.
      const one = await engine.getItem(ctx(), by('/docs/one.html').id); const copy = await engine.getItem(ctx(), by('/docs/copy-of-one.html').id); const mirror = await engine.getItem(ctx(), by('/docs/mirror-of-one.html').id);
      assert.equal(one.familyId, copy.familyId); assert.notEqual(one.familyId, mirror.familyId);
      const fam = await engine.getFamily(ctx(), one.familyId); assert.equal(fam.locations.length, 2);
      const mfam = await engine.getFamily(ctx(), mirror.familyId); assert.equal(mfam.sourceFamily, fam.sourceFamily); assert.equal(mfam.hints[0].relation, 'same_source_family'); assert.equal(mfam.hints[0].method, 'text_shingle_similarity'); assert.ok(mfam.hints[0].similarity > 0.8);
      const corr = await engine.corroboration(ctx(), { items: [one.ref, copy.ref, mirror.ref, by('/docs/two.html').ref, by('/docs/error.html').ref] });
      assert.equal(corr.independentCount, 2, 'a mirrored article is never counted as independent'); assert.equal(corr.unassessed.length, 1);
      assert.equal(corr.groups.find((g: { members: unknown[] }) => g.members.length === 3).relation, 'same_source_family');

      // Failures with reason, attempts and next retry; gaps.
      const failures = await engine.listFailures(ctx(), { sourceId: source.id });
      assert.deepEqual(failures.map((f) => [new URL(f.url).pathname, f.reason, f.attempts, f.state]).sort(), [['/docs/error.html', 'http_500', 1, 'open'], ['/docs/slow.html', 'timeout', 1, 'open']]);
      assert.ok(failures.every((f) => f.nextRetryAt !== null));
      const expectedGap = (await engine.listGaps(ctx(), { sourceId: source.id, kind: 'expected_unresolved' })); assert.equal(expectedGap.length, 2);
      assert.deepEqual(expectedGap.map((g) => [new URL(g.expected).pathname, g.state]).sort(), [['/docs/never-listed.html', 'open'], ['/docs/one.html', 'resolved']]);

      // Scheduled retries are respectful and bounded; exhaustion becomes a gap.
      await sleep(30);
      for (let i = 0; i < 4; i++) { const due = await engine.runDueWork(new Date(Date.now() + 10_000)); if (due.length === 0) break; await drain(engine); }
      const after = await engine.listFailures(ctx(), { sourceId: source.id });
      assert.deepEqual(after.map((f) => [f.attempts, f.state]), [[3, 'exhausted'], [3, 'exhausted']]);
      assert.equal(fx.count('/docs/error.html?utm_source=index'), 3); assert.equal(fx.count('/docs/paywall.html?utm_source=index'), 1);
      assert.equal((await engine.listGaps(ctx(), { sourceId: source.id, kind: 'retries_exhausted', state: 'open' })).length, 2);

      // Source coverage and events.
      const scov = await engine.coverage(ctx(), { sourceId: source.id });
      assert.deepEqual({ d: scov.discovered, b: scov.acquiredBytes, f: scov.failed, s: scov.skippedByPolicy, r: scov.accessRestricted, n: scov.notFound }, { d: 14, b: 5, f: 2, s: 4, r: 2, n: 1 });
      assert.equal((await eventsOf(sql, 'source.discovered')).length, 14); assert.equal((await eventsOf(sql, 'acquisition.completed')).length, 5);
      assert.ok((await eventsOf(sql, 'acquisition.blocked')).length >= 4); assert.equal((await eventsOf(sql, 'collection.changed')).length, 1);

      // Refresh: conditional GET; unchanged → 304, changed content → new acquisition revision + events.
      fx.state.version = 2; const before = fx.times.length;
      const refresh = await engine.refreshSource(ctx(), source.id, { level: 'bytes' }); await drain(engine);
      const rcov = await engine.coverage(ctx(), { runId: refresh.id }); assert.equal(rcov.state, 'completed');
      const oneAfter = await engine.getItem(ctx(), one.id);
      assert.equal(oneAfter.acquisitions.length, 2); assert.equal(oneAfter.acquisitions[1].changed, true); assert.equal(oneAfter.acquisitions[1].supersedes, oneAfter.acquisitions[0].id); assert.notEqual(oneAfter.acquisitions[1].sha256, oneAfter.acquisitions[0].sha256);
      assert.match(oneAfter.acquisitions[1].metadata.title, /Harbour ledger/);
      const sent = fx.times.slice(before).filter((t) => t.path.startsWith('/files/report.pdf'));
      assert.equal(sent.length, 1); const pdfRefresh = (await engine.listReceipts(ctx(), { runId: refresh.id })).find((r) => r.requestUrl.includes('report.pdf'))!;
      assert.equal(pdfRefresh.outcome, 'not_modified'); assert.deepEqual(pdfRefresh.conditional, { 'if-none-match': '"pdf1"' });
      assert.equal((await engine.getItem(ctx(), pdfItem.id)).acquisitions.length, 1, 'unchanged content creates no new acquisition');
      const changedEvents = (await eventsOf(sql, 'acquisition.completed')).filter((e) => (e.payload as { changed: boolean }).changed);
      assert.equal(changedEvents.length, 2, 'one.html and its byte-identical copy both changed'); assert.ok((changedEvents[0]!.payload as { supersedes: string }).supersedes.startsWith('E04:acquisition:'));
      const changed = (await eventsOf(sql, 'collection.changed')).at(-1)!; assert.deepEqual({ c: (changed.payload as { changed: number }).changed, a: (changed.payload as { added: number }).added }, { c: 2, a: 0 });
      assert.equal(rcov.unchanged >= 2, true);
      // Audit chain intact.
      assert.ok(kit.verifyAuditChain(await kit.listAudit(sql, SCHEMA, ctx(), { allProjects: true, limit: 1000 })));
      assert.ok((await store.list('')).every((k) => k.startsWith('t1/p1/')));
    });
  } finally { await fx.close(); await internal.close(); }
});

test('evidence hand-over, tenant isolation, fail-closed authorization, upstream blocking', needsPg, async () => {
  const fx = await startFixture();
  try {
    await kit.withDisposableDatabase(pg, ADMIN, async (_url, sql) => {
      await migrate(sql);
      const evidence = recordingEvidencePort();
      const engine = createEngine({ sql, ports: { evidence }, config: baseConfig(fx.hostPort) });
      const source = await engine.createSource(ctx(), { name: 'Clean', kind: 'html_index', baseUrl: `${fx.base}/plain-index?per=2&pages=2&tag=ev`, config: { itemPattern: '/clean/' }, accessTerms: 'Licensed for research by agreement 12.', reuse: 'licensed', permissionRefs: ['E11:permission:perm-1'], rateLimit: { minIntervalMs: 0 } });
      const run = await engine.startCollection(ctx(), { sourceId: source.id, questionRef: 'E08:question:q-1' }); await drain(engine);
      const cov = await engine.coverage(ctx(), { runId: run.id }); assert.equal(cov.acquiredBytes, 4);
      assert.equal(evidence.accepted.length, 4);
      const handed = evidence.accepted[0]!; const origin = handed.input.origin as Record<string, string>;
      assert.equal(origin.kind, 'discovery'); assert.match(origin.receipt!, /^E04:receipt:/); assert.match(origin.url!, /\/clean\/ev-1-0\.html$/); assert.ok(Date.parse(origin.retrievedAt!) > 0); assert.equal(origin.reuse, 'licensed');
      assert.equal(handed.input.mediaType, 'text/html'); assert.equal(handed.input.filename, 'ev-1-0.html'); assert.equal(handed.ctx.tenantId, 't1');
      const item = (await engine.listItems(ctx(), { runId: run.id }))[0]!; const acq = (await engine.getItem(ctx(), item.id)).acquisitions[0];
      assert.equal(acq.storage, 'evidence_port'); assert.match(acq.evidenceRef, /^E05:evidence_version:/); assert.equal(acq.objectKey, null);
      const receipt = await engine.getReceipt(ctx(), kit.parseUref(acq.receipt).id); assert.equal(receipt.storage.kind, 'evidence_port'); assert.equal(receipt.storage.evidenceRef, acq.evidenceRef);
      assert.equal(kit.parseUref(origin.receipt!).id.length, 36);

      // Second tenant and second project see nothing through any method.
      for (const other of [ctx({ tenantId: 't2' }), ctx({ projectId: 'p2' })]) {
        assert.deepEqual(await engine.listSources(other), []); assert.deepEqual(await engine.listItems(other), []); assert.deepEqual(await engine.listItems(other, { runId: run.id }), []); assert.deepEqual(await engine.listRuns(other), []);
        assert.deepEqual(await engine.listReceipts(other), []); assert.deepEqual(await engine.listGaps(other), []); assert.deepEqual(await engine.listFailures(other), []); assert.deepEqual(await engine.listLeads(other), []);
        assert.deepEqual(await engine.search(other, { q: 'clean' }), []); assert.deepEqual(await engine.audit(other), []);
        assert.equal(await engine.inspect(other, source.ref), null); assert.equal(await engine.inspect(other, item.ref), null); assert.equal(await engine.inspect(other, acq.ref), null);
        for (const [n, p] of ([() => engine.getSource(other, source.id), () => engine.getRun(other, run.id), () => engine.coverage(other, { runId: run.id }), () => engine.coverage(other, { sourceId: source.id }), () => engine.getItem(other, item.id), () => engine.getAcquisition(other, acq.id), () => engine.getAcquisitionBytes(other, acq.id),
          () => engine.getReceipt(other, receipt.id), () => engine.getFamily(other, item.familyId), () => engine.startCollection(other, { sourceId: source.id }), () => engine.refreshSource(other, source.id), () => engine.controlRun(other, run.id, 'cancel'), () => engine.acquire(other, { sourceId: source.id, itemId: item.id }),
          () => engine.updateSource(other, source.id, { name: 'x' }), () => engine.declareExpected(other, { sourceId: source.id, expected: [{ url: 'https://example.org/a' }] }), () => engine.extractLeadsFromAcquisition(other, acq.id)] as (() => Promise<unknown>)[]).entries()) await rejects(p(), 'not_found').catch((e) => { throw new Error(`isolation call ${n}: ${(e as Error).message}`); });
        assert.equal((await engine.corroboration(other, { items: [item.ref] })).independentCount, 0);
        assert.deepEqual((await engine.applyUpstreamChange(other, { eventId: 'x1', kind: 'permission_withdrawn', refs: ['E11:permission:perm-1'], reason: 'r' })).affected, []);
        assert.deepEqual((await engine.events(other)).filter((e) => e.tenantId !== other.tenantId), []);
      }
      assert.equal((await engine.search(ctx(), { q: 'clean' })).length > 0, true);
      // Compartments hide a source completely.
      const hidden = await engine.createSource(ctx({ compartments: ['sealed'] }), { name: 'Sealed', kind: 'file_list', baseUrl: `${fx.base}/list`, accessTerms: 'x', compartment: 'sealed' });
      await rejects(engine.getSource(ctx(), hidden.id), 'not_found'); assert.equal((await engine.listSources(ctx())).length, 1); assert.equal(await engine.inspect(ctx(), hidden.ref), null);
      await rejects(engine.createSource(ctx(), { name: 'Sealed2', kind: 'file_list', baseUrl: `${fx.base}/list`, accessTerms: 'x', compartment: 'sealed' }), 'not_found');

      // Fail closed: no capability, wrong capability, wildcard never grants sensitive actions.
      const none = ctx({ capabilities: [] });
      const calls: [string, (c: kit.ServiceContext) => Promise<unknown>][] = [
        ['createSource', (c) => engine.createSource(c, { name: 'n', kind: 'sitemap', baseUrl: `${fx.base}/sitemap.xml`, accessTerms: 'x' })], ['listSources', (c) => engine.listSources(c)], ['getSource', (c) => engine.getSource(c, source.id)],
        ['updateSource', (c) => engine.updateSource(c, source.id, {})], ['setSourceCredential', (c) => engine.setSourceCredential(c, source.id, { value: 'v', authorizationNote: 'n' })], ['setRobotsPolicy', (c) => engine.setRobotsPolicy(c, source.id, { policy: 'ignore', decisionNote: 'n' })],
        ['unblockSource', (c) => engine.unblockSource(c, source.id, { decisionNote: 'n' })], ['startCollection', (c) => engine.startCollection(c, { sourceId: source.id })], ['refreshSource', (c) => engine.refreshSource(c, source.id)],
        ['acquire', (c) => engine.acquire(c, { sourceId: source.id, itemId: item.id })], ['retryFailures', (c) => engine.retryFailures(c, { sourceId: source.id })], ['getRun', (c) => engine.getRun(c, run.id)], ['listRuns', (c) => engine.listRuns(c)],
        ['controlRun', (c) => engine.controlRun(c, run.id, 'cancel')], ['coverage', (c) => engine.coverage(c, { runId: run.id })], ['listItems', (c) => engine.listItems(c)], ['getItem', (c) => engine.getItem(c, item.id)], ['getAcquisition', (c) => engine.getAcquisition(c, acq.id)],
        ['getAcquisitionBytes', (c) => engine.getAcquisitionBytes(c, acq.id)], ['getReceipt', (c) => engine.getReceipt(c, receipt.id)], ['listReceipts', (c) => engine.listReceipts(c)], ['listFailures', (c) => engine.listFailures(c)], ['listGaps', (c) => engine.listGaps(c)],
        ['declareExpected', (c) => engine.declareExpected(c, { sourceId: source.id, expected: [{ url: 'https://example.org/' }] })], ['resolveGap', (c) => engine.resolveGap(c, item.id, { resolution: 'r' })], ['getFamily', (c) => engine.getFamily(c, item.familyId)],
        ['corroboration', (c) => engine.corroboration(c, { items: [item.ref] })], ['searchSource', (c) => engine.searchSource(c, { sourceId: source.id, query: 'q' })], ['getSearchAttempt', (c) => engine.getSearchAttempt(c, item.id)], ['listSearchAttempts', (c) => engine.listSearchAttempts(c)],
        ['importArchive', (c) => engine.importArchive(c, { sourceId: source.id, format: 'zip', bytes: new Uint8Array([1]) })], ['createLead', (c) => engine.createLead(c, { why: 'w', personName: 'n', routes: [{ kind: 'email', value: 'a@example.org', provenanceNote: 'n' }] })],
        ['getLead', (c) => engine.getLead(c, item.id)], ['listLeads', (c) => engine.listLeads(c)], ['setRouteVerification', (c) => engine.setRouteVerification(c, item.id, item.id, { state: 'invalid', note: 'n' })], ['setLeadIdentity', (c) => engine.setLeadIdentity(c, item.id, { identityState: 'disputed', note: 'n' })],
        ['extractLeads', (c) => engine.extractLeadsFromAcquisition(c, acq.id)], ['inspect', (c) => engine.inspect(c, source.ref)], ['search', (c) => engine.search(c, { q: 'x' })], ['audit', (c) => engine.audit(c)], ['events', (c) => engine.events(c)],
        ['applyUpstreamChange', (c) => engine.applyUpstreamChange(c, { eventId: 'e', kind: 'permission_withdrawn', refs: [], reason: '' })],
      ];
      for (const [name, call] of calls) { await rejects(call(none), 'forbidden').catch((e) => { throw new Error(`${name}: ${(e as Error).message}`); }); await rejects(call(undefined as unknown as kit.ServiceContext), 'unauthenticated').catch((e) => { throw new Error(`${name}: ${(e as Error).message}`); }); }
      const wild = ctx({ capabilities: ['discovery:*'] });
      await rejects(engine.events(wild), 'forbidden'); await rejects(engine.setRobotsPolicy(wild, source.id, { policy: 'ignore', decisionNote: 'n' }), 'forbidden'); await rejects(engine.applyUpstreamChange(wild, { eventId: 'e', kind: 'permission_withdrawn', refs: [], reason: '' }), 'forbidden');
      await rejects(engine.startCollection(ctx({ capabilities: ['discovery:read'] }), { sourceId: source.id }), 'forbidden');
      await rejects(engine.startCollection(ctx({ capabilities: ['discovery:acquire'] }), { sourceId: source.id, extractLeads: true }), 'forbidden');

      // Upstream permission withdrawal blocks refresh of the affected source; idempotent by eventId; visible in inspect.
      const pending = await engine.startCollection(ctx(), { sourceId: source.id, level: 'links' });
      const change: kit.UpstreamChange = { eventId: 'evt-77', kind: 'permission_withdrawn', refs: ['E11:permission:perm-1'], reason: 'Licence agreement 12 was withdrawn' };
      const applied = await engine.applyUpstreamChange(ctx(), change);
      assert.deepEqual(applied.affected, [`E04:source:${source.id}`, `E04:run:${pending.id}`]);
      assert.deepEqual(await engine.applyUpstreamChange(ctx(), change), applied);
      assert.equal((await engine.getRun(ctx(), pending.id)).state, 'blocked'); assert.equal(await engine.runWorkerOnce(), 0, 'the queued job was cancelled');
      const before = fx.times.length;
      for (const p of [() => engine.refreshSource(ctx(), source.id), () => engine.startCollection(ctx(), { sourceId: source.id }), () => engine.acquire(ctx(), { sourceId: source.id, itemId: item.id }), () => engine.getAcquisitionBytes(ctx(), acq.id), () => engine.extractLeadsFromAcquisition(ctx(), acq.id)]) await rejects(p(), 'consent_denied');
      assert.deepEqual(await engine.runDueWork(new Date(Date.now() + 1e9)), []); assert.equal(fx.times.length, before, 'no request leaves after the block');
      const insp = (await engine.inspect(ctx(), source.ref))!; assert.equal(insp.blocked, true); assert.equal(insp.state, 'blocked'); assert.match(insp.staleReasons[0]!, /permission_withdrawn: Licence agreement 12/); assert.deepEqual(insp.sources, ['E11:permission:perm-1']);
      assert.equal((await engine.inspect(ctx(), acq.ref))!.blocked, true);
      const blockedEvents = (await eventsOf(sql, 'source.blocked')); assert.equal(blockedEvents.length, 1); assert.deepEqual(blockedEvents[0]!.payload, { reason: change.reason, cause: 'evt-77', kind: 'permission_withdrawn' });
      // A question change makes dependent items stale rather than blocked.
      const stale = await engine.applyUpstreamChange(ctx(), { eventId: 'evt-78', kind: 'claim_changed', refs: ['E08:question:q-1'], reason: 'Question was narrowed' });
      assert.equal(stale.affected.length, 4); assert.equal((await engine.inspect(ctx(), item.ref))!.stale, true);
      // Only an explicit, audited operator decision lifts the block.
      await rejects(engine.unblockSource(ctx({ capabilities: ['discovery:configure', 'discovery:read'] }), source.id, { decisionNote: 'x' }), 'forbidden');
      await engine.unblockSource(ctx(), source.id, { decisionNote: 'New agreement 13 signed', permissionRef: 'E11:permission:perm-2' });
      assert.equal((await engine.inspect(ctx(), source.ref))!.blocked, false);
      assert.ok((await engine.audit(ctx(), { subject: `E04:source:${source.id}` })).some((a) => a.action === 'source.unblocked'));
      await engine.refreshSource(ctx(), source.id, { level: 'links' });
    });
  } finally { await fx.close(); }
});
