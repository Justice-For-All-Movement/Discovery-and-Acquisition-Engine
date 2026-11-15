// Page-level robots directives: X-Robots-Tag and <meta name="robots"> are enforced under the `honour` policy
// (nofollow/none on index pages, noarchive on items), recorded on receipts, and set aside only by the audited `ignore` decision.
import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import * as kit from '../src/service-kit.ts';
import { createEngine, migrate } from '../src/engine/index.ts';
import type { DiscoveryConfig } from '../src/engine/index.ts';
import { pageRobotsDirectives } from '../src/engine/net.ts';
import { ADMIN, ctx, drain, needsPg, startFixture, tempStore } from './engine-helpers.ts';

const UA = 'PamTestBot/1.0 (+https://example.org/bot)';
const config = (hostPort: string): DiscoveryConfig => ({ userAgent: UA, allowedPrivateHosts: [hostPort], defaultMinIntervalMs: 0, timeoutMs: 2000, maxBytes: 200_000, maxDecompressedBytes: 1_000_000, pageRetryBaseMs: 10, retryBaseMs: 10, maxItemAttempts: 2 });

test('page robots directives: header scoping, meta tags, valued directives', () => {
  const none = pageRobotsDirectives(UA, undefined, []);
  assert.deepEqual(none, { directives: [], follow: true, archive: true });
  assert.deepEqual(pageRobotsDirectives(UA, 'noindex, nofollow', []), { directives: ['nofollow', 'noindex'], follow: false, archive: true });
  assert.equal(pageRobotsDirectives(UA, 'NONE', []).follow, false, 'none implies nofollow');
  assert.deepEqual(pageRobotsDirectives(UA, 'otherbot: noarchive, nofollow', []).directives, [], 'an entry scoped to another robot, and what follows it, does not apply');
  assert.deepEqual(pageRobotsDirectives(UA, 'otherbot: nofollow, pamtestbot: noarchive', []), { directives: ['noarchive'], follow: true, archive: false });
  assert.deepEqual(pageRobotsDirectives(UA, 'unavailable_after: 2026-01-01, max-snippet: 20', []).directives, ['max-snippet', 'unavailable_after'], 'valued directives are not mistaken for a robot scope');
  assert.deepEqual(pageRobotsDirectives(UA, null, [{ name: 'robots', content: 'NoArchive' }, { name: 'PamTestBot', content: 'nofollow' }, { name: 'otherbot', content: 'none' }, { name: 'description', content: 'nofollow' }]), { directives: ['noarchive', 'nofollow'], follow: false, archive: false });
  assert.ok(pageRobotsDirectives(UA, Array.from({ length: 500 }, (_, i) => `x${i}`).join(','), []).directives.length <= 20, 'bounded');
  assert.deepEqual(pageRobotsDirectives(UA, '<script>, 1234, nofollow', []).directives, ['nofollow'], 'malformed tokens are dropped');
});

test('nofollow/none index pages are not followed and noarchive items keep no bytes under honour; ignore records but does not enforce', needsPg, async () => {
  const fx = await startFixture();
  try {
    await kit.withDisposableDatabase(pg, ADMIN, async (_url, sql) => {
      await migrate(sql);
      const { store } = await tempStore();
      const engine = createEngine({ sql, objects: store, config: config(fx.hostPort) });
      const src = (path: string, key: string) => engine.createSource(ctx(), { name: `Robots ${path}`, kind: 'html_index', baseUrl: `${fx.base}${path}`, config: { itemPattern: '/(clean|robots-docs)/', linkScope: 'any' }, accessTerms: 'Fictional fixture', reuse: 'citation_only', rateLimit: { minIntervalMs: 0 }, idempotencyKey: key });

      // meta robots nofollow: the index page is fetched (receipt) but none of its links are listed or fetched.
      const meta = await src('/robots-meta/index', 's-meta');
      const r1 = await engine.startCollection(ctx(), { sourceId: meta.id, level: 'bytes', idempotencyKey: 'r1' });
      await drain(engine);
      const c1 = await engine.coverage(ctx(), { runId: r1.id });
      assert.equal(c1.discovered, 0); assert.equal(fx.count('/clean/rd-meta-0.html'), 0);
      assert.equal(c1.gaps.byKind.robots_disallowed, 1);
      const pr = (await engine.listReceipts(ctx(), { runId: r1.id })).find((x) => x.outcome === 'robots_nofollow')!;
      assert.deepEqual(pr.robots.pageDirectives, ['nofollow', 'noindex']); assert.equal(pr.robots.pageDirectiveEnforced, 'nofollow');

      // X-Robots-Tag scoped to this robot's product token, `none`.
      const hdr = await src('/robots-header/index', 's-hdr');
      const r2 = await engine.startCollection(ctx(), { sourceId: hdr.id, level: 'bytes', idempotencyKey: 'r2' });
      await drain(engine);
      assert.equal((await engine.coverage(ctx(), { runId: r2.id })).discovered, 0); assert.equal(fx.count('/clean/rd-hdr-0.html'), 0);

      // Directives scoped to another robot do not apply; item-level noarchive (meta or header) keeps no bytes; noindex is recorded only.
      const other = await src('/robots-other/index', 's-other');
      const r3 = await engine.startCollection(ctx(), { sourceId: other.id, level: 'bytes', idempotencyKey: 'r3' });
      await drain(engine);
      const c3 = await engine.coverage(ctx(), { runId: r3.id });
      assert.equal(c3.discovered, 5); assert.equal(c3.acquiredBytes, 3); assert.equal(c3.acquiredMetadata, 2);
      const items = await engine.listItems(ctx(), { sourceId: other.id });
      const by = (s: string) => items.find((i) => String(i.url).includes(s))!;
      for (const path of ['noarchive-meta.html', 'noarchive-header.pdf']) {
        const acq = await engine.getAcquisition(ctx(), by(path).currentAcquisition as string);
        assert.equal(acq.level, 'metadata', path); assert.equal(acq.storage, 'none', path); assert.deepEqual(acq.metadata.robotsDirectives, ['noarchive']);
        const rc = (await engine.listReceipts(ctx(), { itemId: by(path).id }))[0]!;
        assert.equal(rc.robots.pageDirectiveEnforced, 'noarchive'); assert.match(String(rc.storage.note), /noarchive/);
      }
      const noindex = await engine.getAcquisition(ctx(), by('noindex.html').currentAcquisition as string);
      assert.equal(noindex.level, 'bytes'); assert.deepEqual(noindex.metadata.robotsDirectives, ['noindex']);
      assert.equal((await engine.getAcquisition(ctx(), by('noarchive-other.html').currentAcquisition as string)).level, 'bytes');

      // A recorded human decision to ignore robots: directives are still recorded, nothing is enforced.
      await engine.setRobotsPolicy(ctx(), meta.id, { policy: 'ignore', decisionNote: 'Fixture: operator decision recorded for the test' });
      const r4 = await engine.startCollection(ctx(), { sourceId: meta.id, level: 'bytes', idempotencyKey: 'r4' });
      await drain(engine);
      assert.equal((await engine.coverage(ctx(), { runId: r4.id })).acquiredBytes, 1); assert.equal(fx.count('/clean/rd-meta-0.html'), 1);
      const ig = (await engine.listReceipts(ctx(), { runId: r4.id })).find((x) => String(x.requestUrl).endsWith('/robots-meta/index'))!;
      assert.deepEqual(ig.robots.pageDirectives, ['nofollow', 'noindex']); assert.equal(ig.robots.pageDirectiveEnforced, null);
    });
  } finally { await fx.close(); }
});
