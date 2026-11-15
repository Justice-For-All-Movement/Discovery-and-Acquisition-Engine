// SSRF and resource-limit matrix for the retrieval worker. Uses real sockets on 127.0.0.1; no database needed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { addressRefusal, parseRobots, robotsDecide, safeFetch, sniffMediaType, vetUrl } from '../src/engine/net.ts';
import type { FetchPolicy } from '../src/engine/net.ts';
import { canonicalUrl, extractLeads, shingleSketch, sketchSimilarity } from '../src/engine/parse.ts';
import { PDF, STAFF_PAGE, startFixture, startInternal } from './engine-helpers.ts';

const policy = (over: Partial<FetchPolicy> = {}): FetchPolicy => ({ userAgent: 'PamTestBot/1.0', allowedPrivateHosts: [], allowedPorts: [80, 443], maxRedirects: 3, maxBytes: 200_000, maxDecompressedBytes: 1_000_000, timeoutMs: 500, ...over });

test('address classification refuses every non-public range', () => {
  const refused = ['0.0.0.0', '10.1.2.3', '127.0.0.1', '127.255.255.254', '100.64.0.1', '100.100.100.200', '169.254.169.254', '169.254.0.1', '172.16.0.1', '172.31.255.255', '192.168.1.1', '192.0.0.8', '192.0.2.1', '198.18.0.1', '198.51.100.7', '203.0.113.9',
    '224.0.0.1', '239.255.255.250', '240.0.0.1', '255.255.255.255', '::', '::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:8.8.8.8', '::127.0.0.1', '64:ff9b::7f00:1', 'fc00::1', 'fd00:ec2::254', 'fe80::1', 'fec0::1', 'ff02::1', '2001:db8::1', '2001::1', '2002:7f00:1::1', '100::1', '3ffe::1%eth0', 'not-an-ip'];
  for (const ip of refused) assert.notEqual(addressRefusal(ip), null, ip);
  for (const ip of ['8.8.8.8', '93.184.216.34', '172.32.0.1', '100.63.255.255', '2606:4700:4700::1111', '2a00:1450:4001:81b::200e']) assert.equal(addressRefusal(ip), null, ip);
  assert.equal(addressRefusal('::ffff:8.8.8.8'), 'ipv4_mapped'); assert.equal(addressRefusal('169.254.169.254'), 'link_local_or_metadata'); assert.equal(addressRefusal('100.64.0.1'), 'cgnat');
});

test('URL vetting: schemes, credentials, ports', () => {
  const p = policy();
  for (const bad of ['file:///etc/passwd', 'ftp://example.org/a', 'gopher://example.org/', 'javascript:alert(1)', 'data:text/plain,hi', 'http://user:pw@example.org/', 'http://user@example.org/', 'https://example.org:8443/', 'http://example.org:22/', 'http://example.org:6379/', 'not a url', ''])
    assert.throws(() => vetUrl(bad, p), (e: unknown) => (e as { code: string }).code === 'blocked_url', bad);
  assert.equal(vetUrl('HTTPS://Example.ORG/a#frag', p).url.href, 'https://example.org/a');
  assert.equal(vetUrl('http://127.0.0.1:8080/x', policy({ allowedPrivateHosts: ['127.0.0.1:8080'] })).privateAllowed, true);
  assert.equal(vetUrl('http://2130706433/', p).hostname, '127.0.0.1', 'decimal host forms are normalised before the address check');
  assert.equal(vetUrl('http://0x7f.1/', p).hostname, '127.0.0.1'); assert.equal(vetUrl('http://[::1]/', p).hostname, '::1');
});

test('SSRF matrix against live loopback listeners: refused without the explicit allowlist', async () => {
  const fx = await startFixture(); const internal = await startInternal(); fx.state.otherPort = internal.port;
  try {
    const before = fx.times.length;
    // 1. No allowlist: loopback, alternate encodings, IPv6 loopback and mapped forms are all refused before any connection.
    const open = policy({ allowedPorts: [80, 443, fx.port, internal.port] });
    for (const url of [`${fx.base}/docs/one.html`, `http://localhost:${fx.port}/docs/one.html`, `http://2130706433:${fx.port}/`, `http://0x7f.0.0.1:${fx.port}/`, `http://127.1:${fx.port}/`, `http://[::1]:${fx.port}/`, `http://[::ffff:127.0.0.1]:${fx.port}/`, `http://0.0.0.0:${fx.port}/`,
      'http://169.254.169.254/latest/meta-data/', 'http://10.0.0.5/', 'http://192.168.0.1/', 'http://100.64.1.1/', 'http://[fd00:ec2::254]/', 'http://224.0.0.1/']) {
      const r = await safeFetch({ url }, open);
      assert.equal(r.ok, false, url); assert.equal(r.code, 'blocked_address', url); assert.equal(r.bytes, null); assert.equal(r.status, null);
    }
    assert.equal(fx.times.length, before, 'no connection reached the fixture'); assert.equal(internal.hits(), 0);
    // default port allowlist alone also refuses a high port
    assert.equal((await safeFetch({ url: `${fx.base}/docs/one.html` }, policy())).code, 'blocked_url');
    // 2. DNS answers: a name resolving to a private address, a mixed answer set, and a failing resolver.
    const named = (answers: string[]) => policy({ allowedPorts: [80, fx.port], resolver: async () => answers.map((address) => ({ address, family: address.includes(':') ? 6 : 4 })) });
    assert.equal((await safeFetch({ url: `http://internal.example.test:${fx.port}/` }, named(['127.0.0.1']))).code, 'blocked_address');
    assert.equal((await safeFetch({ url: `http://mixed.example.test:${fx.port}/` }, named(['93.184.216.34', '10.0.0.1']))).code, 'blocked_address', 'one private answer poisons the whole set');
    assert.equal((await safeFetch({ url: `http://mapped.example.test:${fx.port}/` }, named(['::ffff:127.0.0.1']))).code, 'blocked_address');
    assert.equal((await safeFetch({ url: 'http://nx.example.test/' }, policy({ resolver: async () => { throw new Error('ENOTFOUND'); } }))).code, 'dns_failed');
    assert.equal((await safeFetch({ url: 'http://empty.example.test/' }, policy({ resolver: async () => [] }))).code, 'dns_failed');
    assert.equal(fx.times.length, before);
    // 3. DNS rebinding: the name is resolved once, vetted, and the connection is pinned to that answer; a second, different answer is never used.
    let lookups = 0;
    const rebinding = policy({ allowedPrivateHosts: [`rebind.example.test:${fx.port}`], resolver: async () => { lookups++; return [{ address: lookups === 1 ? '127.0.0.1' : '10.9.9.9', family: 4 }]; } });
    const pinned = await safeFetch({ url: `http://rebind.example.test:${fx.port}/files/report.pdf` }, rebinding);
    assert.equal(pinned.code, 'ok'); assert.equal(pinned.resolvedIp, '127.0.0.1'); assert.equal(lookups, 1, 'exactly one resolution per hop'); assert.deepEqual(Buffer.from(pinned.bytes!), PDF);
    // Without the allowlist entry the same rebinding name is refused outright.
    lookups = 0; assert.equal((await safeFetch({ url: `http://rebind.example.test:${fx.port}/` }, policy({ allowedPorts: [fx.port], resolver: rebinding.resolver! }))).code, 'blocked_address');
    // 4. Redirects are re-vetted on every hop, even when the first hop is allowlisted.
    const allowed = policy({ allowedPrivateHosts: [fx.hostPort], allowedPorts: [80, 443, internal.port] });
    const toPrivate = await safeFetch({ url: `${fx.base}/docs/to-private` }, allowed);
    assert.equal(toPrivate.code, 'blocked_address'); assert.equal(toPrivate.redirects.length, 1); assert.equal(toPrivate.bytes, null); assert.equal(internal.hits(), 0, 'the internal listener was never contacted');
    assert.equal((await safeFetch({ url: `${fx.base}/docs/to-metadata` }, allowed)).code, 'blocked_address');
    assert.equal((await safeFetch({ url: `${fx.base}/docs/loop-a` }, allowed)).code, 'redirect_loop');
    const many = await safeFetch({ url: `${fx.base}/docs/hops` }, allowed); assert.equal(many.code, 'too_many_redirects'); assert.equal(many.redirects.length, 4);
    const moved = await safeFetch({ url: `${fx.base}/docs/moved.html` }, allowed); assert.equal(moved.code, 'ok'); assert.equal(moved.finalUrl, `${fx.base}/docs/two.html`); assert.deepEqual(moved.redirects.map((r) => r.status), [301]); assert.equal(moved.mediaType, 'text/html');
    // 5. Size, time and expansion limits abort the stream.
    assert.equal((await safeFetch({ url: `${fx.base}/docs/big.bin` }, allowed)).code, 'too_large');
    const bomb = await safeFetch({ url: `${fx.base}/docs/bomb.html` }, allowed); assert.equal(bomb.code, 'decompression_limit'); assert.equal(bomb.bytes, null);
    const started = Date.now(); const slow = await safeFetch({ url: `${fx.base}/docs/slow.html` }, allowed); assert.equal(slow.code, 'timeout'); assert.ok(Date.now() - started < 2000);
    const ac = new AbortController(); setTimeout(() => ac.abort(), 50); assert.equal((await safeFetch({ url: `${fx.base}/docs/slow.html`, signal: ac.signal }, policy({ ...allowed, timeoutMs: 5000 }))).code, 'cancelled');
    assert.equal((await safeFetch({ url: `http://127.0.0.1:1/` }, policy({ allowedPrivateHosts: ['127.0.0.1:1'] }))).code, 'network_error');
    // 6. Credentials go only to their exact origin; cookies are never sent or kept; errors are plain outcomes.
    const cred = { origin: fx.base, header: 'authorization', value: 'Bearer s3cr3t-token-value' };
    const ok = await safeFetch({ url: `${fx.base}/protected/list`, credential: cred, headers: { cookie: 'a=b' } }, allowed); assert.equal(ok.code, 'ok'); assert.equal(ok.credentialSent, true); assert.equal(ok.headers['set-cookie'], undefined);
    assert.ok(fx.times.every((t) => t.cookie === undefined));
    const other = await safeFetch({ url: `${fx.base}/protected/list`, credential: { ...cred, origin: 'https://elsewhere.example.org' } }, allowed); assert.equal(other.status, 401); assert.equal(other.credentialSent, false); assert.equal(other.headers['www-authenticate'], 'Bearer');
    const nf = await safeFetch({ url: `${fx.base}/docs/missing.html` }, allowed); assert.equal(nf.code, 'http_error'); assert.equal(nf.status, 404);
    assert.equal((await safeFetch({ url: `${fx.base}/docs/one.html`, headers: { 'if-none-match': '"one-v1"' } }, allowed)).code, 'not_modified');
  } finally { await fx.close(); await internal.close(); }
});

test('sniffing, robots rules, canonical URLs, shingles', () => {
  assert.equal(sniffMediaType(PDF, 'text/html'), 'application/pdf'); assert.equal(sniffMediaType(Buffer.from('<!DOCTYPE html><html>'), 'application/pdf'), 'text/html');
  assert.equal(sniffMediaType(Buffer.from('{"a":1}'), 'text/plain'), 'application/json'); assert.equal(sniffMediaType(Buffer.from([0, 1, 2, 3, 0, 9]), 'text/plain'), 'application/octet-stream');
  assert.equal(sniffMediaType(Buffer.from('PK\x03\x04rest'), null), 'application/zip'); assert.equal(sniffMediaType(Buffer.from('<?xml version="1.0"?><rss version="2.0">'), 'text/xml'), 'application/rss+xml');
  const groups = parseRobots('User-agent: *\nDisallow: /private/\nAllow: /private/open/\nCrawl-delay: 2\n\nUser-agent: pamtestbot\nDisallow: /only-for-us$\nDisallow: /*.zip$\n# comment\nUser-agent: other\nDisallow: /');
  assert.equal(robotsDecide(groups, 'OtherBot/2', '/x').allowed, true, 'product token must match the group name');
  assert.equal(robotsDecide(groups, 'other/2', '/x').allowed, false);
  assert.deepEqual(robotsDecide(groups, 'Unknown/1', '/private/a'), { allowed: false, rule: 'disallow: /private/', group: '*', crawlDelaySeconds: 2 });
  assert.equal(robotsDecide(groups, 'Unknown/1', '/private/open/a').allowed, true, 'longest match wins');
  assert.equal(robotsDecide(groups, 'PamTestBot/1.0', '/private/a').allowed, true, 'a specific group replaces the wildcard group');
  assert.equal(robotsDecide(groups, 'PamTestBot/1.0', '/only-for-us').allowed, false); assert.equal(robotsDecide(groups, 'PamTestBot/1.0', '/only-for-us/more').allowed, true); assert.equal(robotsDecide(groups, 'PamTestBot/1.0', '/a/b.zip').allowed, false);
  assert.equal(canonicalUrl('HTTP://Example.org:80/a/%7Euser/?utm_source=x&b=2&a=1&fbclid=z#top'), 'http://example.org/a/~user/?a=1&b=2');
  assert.equal(canonicalUrl('https://example.org:443'), 'https://example.org/'); assert.notEqual(canonicalUrl('https://example.org/a'), canonicalUrl('https://example.org/a/'));
  const text = 'the quick brown fox jumps over the lazy dog near the old harbour wall while the tide comes in and the gulls circle above the fishing boats returning with the morning catch for the market';
  const a = shingleSketch(text)!; const b = shingleSketch(`${text} today`)!; const c = shingleSketch('an entirely different passage about council budgets rate notices planning committees and the long history of the municipal tramway company that once served the northern districts')!;
  assert.ok(sketchSimilarity(a, b) > 0.9); assert.equal(sketchSimilarity(a, c), 0); assert.equal(shingleSketch('too short to compare'), null);
});

test('deterministic contact-lead extractors', () => {
  const leads = extractLeads(STAFF_PAGE, 'https://records.example.org/staff.html');
  const ada = leads.find((l) => l.personName === 'Ada Quill')!; assert.equal(ada.role, 'Head Archivist'); assert.equal(ada.organization, 'Example Records Office'); assert.deepEqual(ada.routes, [{ kind: 'email', value: 'ada.quill@records.example.org' }]); assert.equal(ada.extractor, 'json_ld');
  const ben = leads.find((l) => l.personName === 'Ben Folio')!; assert.equal(ben.extractor, 'staff_listing'); assert.equal(ben.role, 'Reading Room Supervisor');
  const press = leads.find((l) => l.personName === 'Cy Vellum')!; assert.equal(press.extractor, 'mailto'); assert.equal(press.routes[0]!.value, 'press@records.example.org');
  const org = leads.find((l) => l.extractor === 'json_ld' && l.personName === null)!; assert.equal(org.organization, 'Example Records Office'); assert.deepEqual(org.routes.map((r) => r.kind), ['email', 'postal']); assert.match(org.routes[1]!.value, /1 Archive Lane, Port Example, 00001/);
  const contact = leads.find((l) => l.extractor === 'contact_section')!; assert.deepEqual(contact.routes.map((r) => [r.kind, r.value]), [['email', 'enquiries@records.example.org'], ['web_form', 'https://records.example.org/contact/send'], ['postal', 'Example Records Office, 1 Archive Lane, Port Example 00001']]);
  assert.equal(leads.length, 5); assert.deepEqual(extractLeads('<html><body><p>No contacts here, only prose about a@b</p></body></html>', 'https://example.org/'), []);
  assert.deepEqual(extractLeads('<a href="mailto:%00bad">x</a><a href="javascript:alert(1)">y</a><script type="application/ld+json">{not json</script>', 'https://example.org/'), []);
});

test('parsers stay bounded on hostile input', async () => {
  const { parseHtml, htmlListing, feedListing, sitemapListing } = await import('../src/engine/parse.ts');
  const { robotsMatch } = await import('../src/engine/net.ts');
  const n = 200_000;
  const hostile = ['<a ' + 'x=1 '.repeat(n), '<'.repeat(n), '<div>'.repeat(n), '<!--'.repeat(n), '<![CDATA['.repeat(n), '<a href="mailto:a@b.example">'.repeat(n / 5), '<item><title><![CDATA['.repeat(n / 4), '<url><loc>'.repeat(n / 4), '<li class="staff"><b>x</b>'.repeat(n / 10)];
  const started = Date.now();
  for (const input of hostile) { parseHtml(input); extractLeads(input, 'https://example.org/'); htmlListing(input, 'https://example.org/'); feedListing(input, 'https://example.org/'); sitemapListing(input, 'https://example.org/'); }
  assert.equal(robotsMatch(`/${'*a'.repeat(60)}$`, `/${'a'.repeat(20_000)}b`), false);
  assert.ok(Date.now() - started < 30_000, `hostile inputs took ${Date.now() - started} ms`);
  assert.equal(robotsMatch('/a*c$', '/abc'), true); assert.equal(robotsMatch('/a*c$', '/abcd'), false); assert.equal(robotsMatch('/a', '/abc'), true); assert.equal(robotsMatch('/*.pdf', '/x/y.pdf?z'), true); assert.equal(robotsMatch('/b', '/abc'), false);
});
