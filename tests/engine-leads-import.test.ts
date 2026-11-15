import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import pg from 'pg';
import * as kit from '../src/service-kit.ts';
import { createEngine, migrate } from '../src/engine/index.ts';
import { ADMIN, PDF, articlePage, ctx, drain, needsPg, recordingEvidencePort, rejects, startFixture, tempStore } from './engine-helpers.ts';

test('contact leads: extraction with provenance, manual entry, channel verification kept apart from identity and truth', needsPg, async () => {
  const fx = await startFixture();
  try {
    await kit.withDisposableDatabase(pg, ADMIN, async (_url, sql) => {
      await migrate(sql);
      const engine = createEngine({ sql, objects: (await tempStore()).store, config: { userAgent: 'PamTestBot/1.0', allowedPrivateHosts: [fx.hostPort], defaultMinIntervalMs: 0 } });
      const source = await engine.createSource(ctx(), { name: 'Records office', kind: 'file_list', baseUrl: `${fx.base}/list`, config: { urls: [`${fx.base}/staff.html`] }, accessTerms: 'Public staff directory' });
      const question = 'E08:question:q-archive';
      const run = await engine.startCollection(ctx(), { sourceId: source.id, questionRef: question, extractLeads: { why: 'Staff of the office that holds the harbour ledger; may know where the 2019 volume is shelved' } }); await drain(engine);
      const item = (await engine.listItems(ctx(), { runId: run.id }))[0]!; const acq = (await engine.getItem(ctx(), item.id)).acquisitions[0];
      const leads = await engine.listLeads(ctx(), { questionRef: question });
      assert.equal(leads.length, 5);
      const ada = leads.find((l) => l.personName === 'Ada Quill')!;
      assert.equal(ada.role, 'Head Archivist'); assert.equal(ada.organization, 'Example Records Office'); assert.match(ada.why, /may know where the 2019 volume/); assert.equal(ada.questionRef, question); assert.equal(ada.sourceItemRef, item.ref);
      assert.equal(ada.origin, 'extracted'); assert.equal(ada.extractor, 'json_ld'); assert.match(ada.confidenceNote, /proves neither who answers it nor that they know anything/);
      assert.equal(ada.identityState, 'unconfirmed'); assert.equal(ada.knowledgeState, 'unverified');
      const route = ada.routes[0]; assert.deepEqual([route.kind, route.value, route.provenanceRef, route.provenanceUrl, route.verificationState], ['email', 'ada.quill@records.example.org', acq.ref, `${fx.base}/staff.html`, 'unverified']);
      assert.deepEqual(leads.find((l) => l.extractor === 'contact_section')!.routes.map((r: { kind: string }) => r.kind), ['email', 'web_form', 'postal']);
      // Channel verification changes the route only.
      const verified = await engine.setRouteVerification(ctx(), ada.id, route.id, { state: 'channel_verified', note: 'Auto-reply received from the address on 3 March' });
      assert.equal(verified.routes[0].verificationState, 'channel_verified'); assert.equal(verified.identityState, 'unconfirmed'); assert.equal(verified.knowledgeState, 'unverified');
      const confirmed = await engine.setLeadIdentity(ctx(), ada.id, { identityState: 'confirmed_by_operator', note: 'Met in person at the reading room' });
      assert.equal(confirmed.identityState, 'confirmed_by_operator'); assert.equal(confirmed.knowledgeState, 'unverified', 'confirming identity never asserts that the person knows anything');
      await rejects(engine.setRouteVerification(ctx(), ada.id, leads.find((l) => l.id !== ada.id)!.routes[0].id, { state: 'invalid', note: 'n' }), 'not_found');
      // Re-extraction is idempotent.
      assert.equal((await engine.extractLeadsFromAcquisition(ctx(), acq.id, { questionRef: question })).length, 5); assert.equal((await engine.listLeads(ctx())).length, 5);
      // Manual entry needs a reason and a provenance for every route.
      await rejects(engine.createLead(ctx(), { personName: 'Dee Margin', why: 'Former clerk', routes: [{ kind: 'postal', value: '2 Quay Street, Port Example' }] }), 'invalid_input');
      await rejects(engine.createLead(ctx(), { personName: 'Dee Margin', why: '', routes: [{ kind: 'postal', value: 'x', provenanceNote: 'n' }] }), 'invalid_input');
      const manual = await engine.createLead(ctx(), { personName: 'Dee Margin', role: 'Former clerk', why: 'Named in council minutes as the clerk who moved the files', questionRef: question, sourceItemRef: item.ref, confidenceNote: 'Second-hand', idempotencyKey: 'lead-1',
        routes: [{ kind: 'postal', value: '2 Quay Street, Port Example', provenanceNote: 'Address given by the reading room on request', provenanceRef: acq.ref }] });
      assert.equal(manual.origin, 'manual'); assert.equal(manual.routes[0].provenanceRef, acq.ref);
      assert.equal((await engine.createLead(ctx(), { personName: 'Dee Margin', role: 'Former clerk', why: 'Named in council minutes as the clerk who moved the files', questionRef: question, sourceItemRef: item.ref, confidenceNote: 'Second-hand', idempotencyKey: 'lead-1',
        routes: [{ kind: 'postal', value: '2 Quay Street, Port Example', provenanceNote: 'Address given by the reading room on request', provenanceRef: acq.ref }] })).id, manual.id);
      // Leads are personal data behind their own capability.
      const reader = ctx({ capabilities: ['discovery:read'] });
      await rejects(engine.listLeads(reader), 'forbidden'); await rejects(engine.getLead(reader, ada.id), 'forbidden'); assert.equal(await engine.inspect(reader, ada.ref), null); assert.deepEqual((await engine.search(reader, { q: 'Quill' })).filter((h) => h.kind === 'lead'), []);
      assert.equal((await engine.search(ctx(), { q: 'Quill' })).filter((h) => h.kind === 'lead').length, 1);
      const insp = (await engine.inspect(ctx(), ada.ref))!; assert.deepEqual(insp.sources, [question, item.ref]); assert.ok(insp.history.some((h) => h.action === 'lead.route_verification_changed'));
      // Upstream change to the question marks leads stale; withdrawal of the page's item blocks them.
      const stale = await engine.applyUpstreamChange(ctx(), { eventId: 'q-1', kind: 'claim_changed', refs: [question], reason: 'Question rewritten' });
      assert.equal(stale.affected.filter((r) => r.startsWith('E04:lead:')).length, 6); assert.equal((await engine.inspect(ctx(), ada.ref))!.stale, true);
      assert.ok((await kit.listAudit(sql, 'e04_discovery', ctx(), { limit: 1000 })).every((a) => !JSON.stringify(a.detail).includes('ada.quill@')), 'contact values are not copied into the audit trail');
    });
  } finally { await fx.close(); }
});

const warcRecord = (type: string, uri: string | null, date: string, contentType: string, payload: Buffer, n: number): Buffer => Buffer.concat([Buffer.from(`WARC/1.0\r\nWARC-Type: ${type}\r\nWARC-Record-ID: <urn:uuid:00000000-0000-4000-8000-00000000000${n}>\r\nWARC-Date: ${date}\r\n${uri === null ? '' : `WARC-Target-URI: ${uri}\r\n`}Content-Type: ${contentType}\r\nContent-Length: ${payload.byteLength}\r\n\r\n`), payload, Buffer.from('\r\n\r\n')]);
const httpResponse = (status: number, type: string, body: string): Buffer => Buffer.from(`HTTP/1.1 ${status} X\r\nContent-Type: ${type}\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);

test('private research import: ZIP with manifest, WARC history, directory; provenance gaps recorded', needsPg, async () => {
  await kit.withDisposableDatabase(pg, ADMIN, async (_url, sql) => {
    await migrate(sql);
    const work = await mkdtemp(join(tmpdir(), 'e04-import-')); const root = join(work, 'root');
    await mkdir(join(root, 'box1', 'docs'), { recursive: true });
    const pageA = articlePage('Minutes of the harbour board', 'Private scan');
    await writeFile(join(root, 'box1', 'docs', 'a.html'), pageA); await writeFile(join(root, 'box1', 'docs', 'b.pdf'), PDF); await writeFile(join(root, 'box1', 'loose.txt'), 'A loose note with no recorded origin.');
    const manifest = { collection: 'Harbour box 1', collectedBy: 'Researcher R', entries: [
      { path: 'docs/a.html', originalUrl: 'https://archive.example.org/minutes/a.html?utm_source=mail', retrievedAt: '2024-05-01T10:00:00Z', title: 'Minutes A', history: [{ at: '2024-05-01T10:00:00Z', event: 'downloaded', by: 'Researcher R' }, { at: '2025-01-10T09:00:00Z', event: 'moved to project drive' }] },
      { path: 'docs/b.pdf', retrievedAt: '2024-05-02T10:00:00Z', sha256: 'f'.repeat(64) },
      { path: 'docs/ghost.pdf', originalUrl: 'https://archive.example.org/minutes/ghost.pdf' }] };
    await writeFile(join(root, 'box1', 'manifest.json'), JSON.stringify(manifest));
    execFileSync('zip', ['-q', '-r', '-D', join(work, 'box1.zip'), '.'], { cwd: join(root, 'box1') });
    const zip = new Uint8Array(await readFile(join(work, 'box1.zip')));
    const { store } = await tempStore();
    const engine = createEngine({ sql, objects: store, config: { userAgent: 'PamTestBot/1.0', importRoot: root } });
    const source = await engine.createSource(ctx(), { name: 'Private harbour archive', kind: 'archive_import', baseUrl: '', accessTerms: 'Private research copies; not for redistribution', reuse: 'restricted' });
    const web = await engine.createSource(ctx(), { name: 'Web', kind: 'sitemap', baseUrl: 'https://example.org/sitemap.xml', accessTerms: 'x' });
    await rejects(engine.importArchive(ctx(), { sourceId: web.id, format: 'zip', bytes: zip }), 'invalid_state');
    const out = await engine.importArchive(ctx(), { sourceId: source.id, format: 'zip', bytes: zip, idempotencyKey: 'imp-1' });
    assert.deepEqual({ a: out.acquired, u: out.unchanged, g: out.provenanceGaps, m: out.missingFromArchive }, { a: 3, u: 0, g: 2, m: 1 });
    assert.deepEqual(await engine.importArchive(ctx(), { sourceId: source.id, format: 'zip', bytes: zip, idempotencyKey: 'imp-1' }), out);
    const cov = await engine.coverage(ctx(), { runId: out.runId }); assert.equal(cov.state, 'completed'); assert.equal(cov.acquiredBytes, 3);
    assert.deepEqual(cov.gaps.byKind, { provenance_missing: 2, integrity_mismatch: 1, expected_unresolved: 1 });
    const items = await engine.listItems(ctx(), { sourceId: source.id });
    const a = await engine.getItem(ctx(), items.find((i) => i.canonicalUrl === 'https://archive.example.org/minutes/a.html')!.id); const acq = a.acquisitions[0];
    assert.equal(acq.reuse, 'restricted'); assert.equal(acq.origin.retrievedAt, '2024-05-01T10:00:00.000Z'); assert.deepEqual(acq.origin.history, manifest.entries[0]!.history); assert.deepEqual(acq.origin.provenanceMissing, []);
    assert.equal(acq.origin.import.path, 'docs/a.html'); assert.equal(acq.origin.kind, 'discovery'); assert.equal(a.title, 'Minutes A');
    const receipt = await engine.getReceipt(ctx(), kit.parseUref(acq.receipt).id); assert.equal(receipt.kind, 'import'); assert.equal(receipt.outcome, 'imported'); assert.match(receipt.message, /not retrieved from the network/); assert.equal(receipt.resolvedIp, null);
    assert.deepEqual(Buffer.from((await engine.getAcquisitionBytes(ctx(), acq.id)).bytes).toString(), pageA);
    const gaps = await engine.listGaps(ctx(), { sourceId: source.id, kind: 'provenance_missing' });
    assert.deepEqual(gaps.map((g) => g.detail).sort(), ['Imported item lacks origin information: originalUrl', 'Imported item lacks origin information: originalUrl, retrievedAt, manifest entry']);
    assert.ok(gaps.every((g) => g.expected.startsWith(`import://${source.id}/`)));
    assert.match((await engine.listGaps(ctx(), { sourceId: source.id, kind: 'expected_unresolved' }))[0]!.detail, /absent from the archive/);
    // Same bytes again: nothing duplicated.
    const again = await engine.importArchive(ctx(), { sourceId: source.id, format: 'zip', bytes: zip }); assert.deepEqual({ a: again.acquired, u: again.unchanged }, { a: 0, u: 3 }); assert.equal((await engine.listItems(ctx(), { sourceId: source.id })).length, 3);
    // Hostile archives are rejected.
    const evil = join(work, 'evil.zip'); execFileSync('python3', ['-I', '-c', 'import sys,zipfile\nz=zipfile.ZipFile(sys.argv[1],"w")\nz.writestr("../../escape.txt","x")\nz.close()', evil]);
    await rejects(engine.importArchive(ctx(), { sourceId: source.id, format: 'zip', bytes: new Uint8Array(await readFile(evil)) }), 'invalid_input');
    await rejects(engine.importArchive(ctx(), { sourceId: source.id, format: 'zip', bytes: new Uint8Array([1, 2, 3]) }), 'invalid_input');
    await rejects(engine.importArchive(ctx(), { sourceId: source.id, format: 'zip', bytes: zip, manifest: { entries: [{ path: '' }] } as never }), 'invalid_input');

    // WARC (gzip): two captures of one URL become successive revisions in capture order; non-response records are counted, not imported.
    const uri = 'https://archive.example.org/notices/tender.html';
    const warc = gzipSync(Buffer.concat([
      warcRecord('warcinfo', null, '2023-01-01T00:00:00Z', 'application/warc-fields', Buffer.from('software: example\r\n'), 1),
      warcRecord('response', uri, '2023-06-01T00:00:00Z', 'application/http; msgtype=response', httpResponse(200, 'text/html', articlePage('Tender notice', 'Archive', 'Second capture text. '.repeat(20))), 2),
      warcRecord('response', uri, '2023-02-01T00:00:00Z', 'application/http; msgtype=response', httpResponse(200, 'text/html', articlePage('Tender notice', 'Archive', 'First capture text. '.repeat(20))), 3),
      warcRecord('request', uri, '2023-02-01T00:00:00Z', 'application/http; msgtype=request', Buffer.from('GET /notices/tender.html HTTP/1.1\r\nHost: archive.example.org\r\n\r\n'), 4),
      warcRecord('response', 'https://archive.example.org/gone', '2023-02-01T00:00:00Z', 'application/http; msgtype=response', httpResponse(404, 'text/html', 'gone'), 5),
      warcRecord('resource', 'https://archive.example.org/files/report.pdf', '2023-03-01T00:00:00Z', 'application/pdf', PDF, 6),
    ]));
    const w = await engine.importArchive(ctx(), { sourceId: source.id, format: 'warc', bytes: new Uint8Array(warc) });
    assert.deepEqual({ a: w.acquired, g: w.provenanceGaps, s: w.skipped }, { a: 3, g: 0, s: { warcinfo: 1, request: 1, http_404: 1 } });
    const tender = await engine.getItem(ctx(), (await engine.listItems(ctx(), { sourceId: source.id })).find((i) => i.url === uri)!.id);
    assert.deepEqual(tender.acquisitions.map((x: { revision: number; origin: { retrievedAt: string } }) => [x.revision, x.origin.retrievedAt]), [[1, '2023-02-01T00:00:00.000Z'], [2, '2023-06-01T00:00:00.000Z']]);
    assert.equal(tender.acquisitions[1].supersedes, tender.acquisitions[0].id); assert.match(tender.acquisitions[0].origin.import.recordId, /^<urn:uuid:/);
    const pdfItem = (await engine.listItems(ctx(), { sourceId: source.id })).find((i) => i.url.endsWith('/files/report.pdf'))!; const bItem = (await engine.listItems(ctx(), { sourceId: source.id })).find((i) => i.url.endsWith('/docs/b.pdf'))!;
    assert.equal(pdfItem.familyId, bItem.familyId, 'the same PDF from the ZIP and the WARC is one content family');
    assert.equal((await engine.corroboration(ctx(), { items: [pdfItem.ref, bItem.ref] })).independentCount, 1);

    // Directory import is confined to the configured root.
    await symlink('/etc/hostname', join(root, 'box1', 'link.txt'));
    const d = await engine.importArchive(ctx(), { sourceId: source.id, format: 'directory', path: 'box1' });
    assert.deepEqual({ a: d.acquired, u: d.unchanged, s: d.skipped }, { a: 0, u: 3, s: { symlink: 1 } });
    for (const path of ['..', '../..', '/etc', 'box1/../../..', 'missing']) await rejects(engine.importArchive(ctx(), { sourceId: source.id, format: 'directory', path }), 'invalid_input');
    await rejects(createEngine({ sql, objects: store }).importArchive(ctx(), { sourceId: source.id, format: 'directory', path: 'box1' }), 'unavailable');
    await rejects(engine.refreshSource(ctx(), source.id), 'invalid_state');
    // With an EvidencePort the imported originals are handed over with their history.
    const evidence = recordingEvidencePort(); const handing = createEngine({ sql, ports: { evidence }, config: { importRoot: root } });
    const source2 = await handing.createSource(ctx(), { name: 'Second private archive', kind: 'archive_import', baseUrl: '', accessTerms: 'Private' });
    await handing.importArchive(ctx(), { sourceId: source2.id, format: 'zip', bytes: zip });
    assert.equal(evidence.accepted.length, 3); const handed = evidence.accepted.find((x) => x.input.filename === 'a.html')!.input.origin as { history: unknown[]; provenanceMissing: string[]; import: { format: string } };
    assert.equal(handed.history.length, 2); assert.equal(handed.import.format, 'zip');
    assert.ok((await store.list('')).every((k) => k.startsWith('t1/p1/discovery/originals/')));
  });
});
