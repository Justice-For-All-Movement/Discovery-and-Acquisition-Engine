// Deterministic parsers for retrieved (untrusted) content: HTML, sitemaps, feeds, JSON listings, URL canonicalisation,
// text shingling for mirror detection and contact-lead extraction. Nothing here performs I/O.
import { createHash } from 'node:crypto';

// ───────────────────────────── Text decoding ─────────────────────────────
export function decodeText(bytes: Uint8Array, contentType: string | null | undefined, max = 8 * 1024 * 1024): string {
  const slice = bytes.length > max ? bytes.subarray(0, max) : bytes;
  const declared = /charset\s*=\s*"?([A-Za-z0-9._-]+)/i.exec(contentType ?? '')?.[1];
  const meta = declared ?? /<meta[^>]+charset\s*=\s*["']?([A-Za-z0-9._-]+)/i.exec(Buffer.from(slice.subarray(0, 2048)).toString('latin1'))?.[1];
  for (const label of [meta, 'utf-8']) {
    if (label === undefined) continue;
    try { return new TextDecoder(label).decode(slice); } catch { /* unknown label */ }
  }
  return Buffer.from(slice).toString('latin1');
}
const ENT: Readonly<Record<string, string>> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', ndash: '–', mdash: '—', hellip: '…', copy: '©' };
export function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]{1,6}|#[0-9]{1,7}|[a-z]{2,8});/gi, (m, e: string) => {
    if (e[0] === '#') { const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return n > 0 && n <= 0x10ffff && !(n >= 0xd800 && n <= 0xdfff) ? String.fromCodePoint(n) : ' '; }
    return ENT[e.toLowerCase()] ?? m;
  });
}

// ───────────────────────────── Tolerant HTML tree ─────────────────────────────
export type HtmlNode = { tag: string; attrs: Record<string, string>; children: (HtmlNode | string)[]; parent: HtmlNode | null };
const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr']);
const TOKEN = /(\u0000\u0000never)|<![^>]{0,2000}>|<\?[^>]{0,2000}>|<(\/?)([a-zA-Z][a-zA-Z0-9:_-]*)((?:\s+[^\s"'<>\/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'<>]+))?)*)\s*(\/?)>|[^<]+|</g;
const ATTR = /([^\s"'<>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>]+)))?/g;
/** Elements nested deeper than this become siblings, which bounds every recursive walk over the tree. */
const MAX_DEPTH = 200;
export function parseHtml(input: string, maxNodes = 200_000): HtmlNode {
  const root: HtmlNode = { tag: '#root', attrs: {}, children: [], parent: null };
  let cur = root; let count = 0; let depth = 0;
  TOKEN.lastIndex = 0;
  let m: RegExpExecArray | null;
  for (;;) {
    // Comments and CDATA are skipped with indexOf so an unterminated one costs one scan, not one per position.
    const at = TOKEN.lastIndex;
    if (input.startsWith('<!--', at)) { const end = input.indexOf('-->', at + 4); if (end < 0) break; TOKEN.lastIndex = end + 3; continue; }
    if (input.startsWith('<![CDATA[', at)) { const end = input.indexOf(']]>', at + 9); cur.children.push(input.slice(at + 9, end < 0 ? input.length : end)); if (end < 0) break; TOKEN.lastIndex = end + 3; continue; }
    if ((m = TOKEN.exec(input)) === null || count >= maxNodes) break;
    const tok = m[0];
    if (m[3] === undefined) { if (!tok.startsWith('<!') && !tok.startsWith('<?')) cur.children.push(tok === '<' ? '<' : decodeEntities(tok)); continue; }
    const tag = m[3].toLowerCase();
    if (m[2] === '/') {
      let n: HtmlNode | null = cur;
      let up = 1;
      while (n !== null && n.tag !== tag) { n = n.parent; up++; }
      if (n !== null && n.parent !== null) { cur = n.parent; depth -= up; }
      continue;
    }
    const attrs: Record<string, string> = {};
    ATTR.lastIndex = 0;
    let a: RegExpExecArray | null;
    while ((a = ATTR.exec(m[4] ?? '')) !== null) { const k = (a[1] as string).toLowerCase(); if (!Object.hasOwn(attrs, k)) attrs[k] = decodeEntities(a[2] ?? a[3] ?? a[4] ?? ''); }
    if ((tag === 'p' || tag === 'li') && cur.tag === tag && cur.parent !== null) { cur = cur.parent; depth--; }
    const node: HtmlNode = { tag, attrs, children: [], parent: cur };
    cur.children.push(node); count++;
    if (tag === 'script' || tag === 'style') {
      const close = new RegExp(`</${tag}\\s*>`, 'ig'); close.lastIndex = TOKEN.lastIndex;
      const end = close.exec(input);
      node.children.push(input.slice(TOKEN.lastIndex, end === null ? input.length : end.index));
      TOKEN.lastIndex = end === null ? input.length : close.lastIndex;
      continue;
    }
    if (!VOID.has(tag) && m[5] !== '/' && depth < MAX_DEPTH) { cur = node; depth++; }
  }
  return root;
}
export function walk(node: HtmlNode, visit: (n: HtmlNode) => boolean | void): void {
  const stack: HtmlNode[] = [node];
  while (stack.length > 0) {
    const n = stack.pop() as HtmlNode;
    if (n !== node && visit(n) === false) continue;
    for (let i = n.children.length - 1; i >= 0; i--) { const c = n.children[i]; if (typeof c !== 'string' && c !== undefined) stack.push(c); }
  }
}
export function findAll(node: HtmlNode, pred: (n: HtmlNode) => boolean): HtmlNode[] { const out: HtmlNode[] = []; walk(node, (n) => { if (pred(n)) out.push(n); }); return out; }
const SKIP_TEXT = new Set(['script', 'style', 'noscript', 'template', 'svg']);
const BLOCK = new Set(['p', 'div', 'li', 'tr', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'section', 'article', 'td', 'th', 'address', 'dt', 'dd', 'ul', 'ol', 'table', 'header', 'footer', 'nav', 'aside', 'main', 'form', 'blockquote']);
export function textOf(node: HtmlNode | string, skip: ReadonlySet<string> = SKIP_TEXT): string {
  if (typeof node === 'string') return node;
  if (skip.has(node.tag)) return '';
  let out = BLOCK.has(node.tag) ? '\n' : '';
  for (const c of node.children) out += textOf(c, skip);
  return BLOCK.has(node.tag) ? `${out}\n` : out;
}
export const squash = (s: string): string => s.replace(/\s+/g, ' ').trim();
const classHas = (n: HtmlNode, re: RegExp): boolean => re.test(`${n.attrs.class ?? ''} ${n.attrs.id ?? ''} ${n.attrs.itemprop ?? ''}`);

// ───────────────────────────── URLs ─────────────────────────────
const TRACKING = /^(utm_[a-z0-9_]+|fbclid|gclid|mc_cid|mc_eid|igshid)$/i;
/** Canonical form used for dedupe: lower-case scheme/host, default port and fragment removed, tracking parameters dropped, query sorted. */
export function canonicalUrl(raw: string): string {
  let u: URL;
  try { u = new URL(raw); } catch { return raw.trim(); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return raw.trim();
  u.hash = ''; u.username = ''; u.password = '';
  if (u.hostname.endsWith('.')) u.hostname = u.hostname.slice(0, -1);
  const params = [...u.searchParams.entries()].filter(([k]) => !TRACKING.test(k)).sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0) : a[0] < b[0] ? -1 : 1));
  u.search = '';
  for (const [k, v] of params) u.searchParams.append(k, v);
  u.pathname = u.pathname.replace(/%[0-9a-f]{2}/gi, (h) => { const c = String.fromCharCode(parseInt(h.slice(1), 16)); return /[A-Za-z0-9._~-]/.test(c) ? c : h.toUpperCase(); });
  return u.href;
}
export function absoluteUrl(href: string, base: string): string | null {
  try { const u = new URL(href.trim(), base); if (u.protocol !== 'http:' && u.protocol !== 'https:') return null; u.hash = ''; return u.href; } catch { return null; }
}

// ───────────────────────────── Listings ─────────────────────────────
export type ListedItem = { url: string; title: string | null; metadata: Record<string, unknown> };
export type Listing = { items: ListedItem[]; next: string[]; total?: number | null };

export function linkHeaderNext(header: string | undefined, base: string): string | null {
  for (const part of (header ?? '').split(/,(?=\s*<)/)) {
    const m = /<([^>]+)>\s*;(.*)$/.exec(part.trim());
    if (m !== null && /rel\s*=\s*"?[^";]*\bnext\b/i.test(m[2] ?? '')) return absoluteUrl(m[1] as string, base);
  }
  return null;
}
export function htmlListing(html: string, pageUrl: string, options: { itemPattern?: string; linkScope?: 'same_host' | 'any' } = {}): Listing {
  const root = parseHtml(html);
  const baseHref = findAll(root, (n) => n.tag === 'base' && n.attrs.href !== undefined)[0]?.attrs.href;
  const base = (baseHref !== undefined ? absoluteUrl(baseHref, pageUrl) : null) ?? pageUrl;
  const next: string[] = [];
  const pattern = options.itemPattern === undefined ? null : new RegExp(options.itemPattern);
  const host = new URL(pageUrl).host;
  const items = new Map<string, ListedItem>();
  walk(root, (n) => {
    if ((n.tag === 'a' || n.tag === 'link') && n.attrs.href !== undefined) {
      const url = absoluteUrl(n.attrs.href, base);
      if (url === null) return;
      const rel = (n.attrs.rel ?? '').toLowerCase().split(/\s+/);
      if (rel.includes('next')) { if (!next.includes(url)) next.push(url); return; }
      if (n.tag === 'link' || rel.includes('prev') || rel.includes('nofollow')) return;
      if (pattern !== null ? !pattern.test(url) : options.linkScope !== 'any' && new URL(url).host !== host) return;
      if (pattern === null && canonicalUrl(url) === canonicalUrl(pageUrl)) return;
      if (!items.has(url)) items.set(url, { url, title: squash(textOf(n)).slice(0, 500) || null, metadata: {} });
    }
  });
  return { items: [...items.values()], next };
}
/** Linear-time `<tag ...>…</tag>` splitter: an unterminated element ends the scan instead of rescanning from every start. */
function xmlBlocks(xml: string, tag: string, max = 50_000): string[] {
  const out: string[] = []; const lower = xml.toLowerCase(); const open = `<${tag.toLowerCase()}`; const close = `</${tag.toLowerCase()}>`;
  let at = 0;
  while (out.length < max) {
    const start = lower.indexOf(open, at); if (start < 0) break;
    const after = lower.charCodeAt(start + open.length); // next char must end the tag name
    if (!(after === 62 || after === 47 || after === 32 || after === 9 || after === 10 || after === 13)) { at = start + open.length; continue; }
    const gt = lower.indexOf('>', start); if (gt < 0) break;
    const end = lower.indexOf(close, gt); if (end < 0) break;
    out.push(xml.slice(gt + 1, end)); at = end + close.length;
  }
  return out;
}
const xmlText = (raw: string | undefined): string | null => { if (raw === undefined) return null; const s = raw.slice(0, 20_000); const t = squash(decodeEntities(s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').replace(/<[^>]+>/g, ''))); return t === '' ? null : t; };
const xmlTag = (block: string, tag: string): string | null => xmlText(xmlBlocks(block, tag, 1)[0]);
export function sitemapListing(xml: string, pageUrl: string): Listing {
  const out: Listing = { items: [], next: [] };
  const index = /<sitemapindex\b/i.test(xml);
  for (const block of xmlBlocks(xml, index ? 'sitemap' : 'url')) {
    const loc = xmlTag(block, 'loc'); const url = loc === null ? null : absoluteUrl(loc, pageUrl);
    if (url === null) continue;
    if (index) out.next.push(url);
    else { const lastmod = xmlTag(block, 'lastmod'); out.items.push({ url, title: null, metadata: lastmod === null ? {} : { lastmod } }); }
  }
  return out;
}
export function feedListing(xml: string, pageUrl: string): Listing {
  const out: Listing = { items: [], next: [] };
  const atom = /<feed\b/i.test(xml) && !/<rss\b/i.test(xml);
  const linkAttr = (tagText: string, name: string): string | null => { const v = new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)')`, 'i').exec(tagText); return v === null ? null : decodeEntities(v[1] ?? v[2] ?? ''); };
  const firstEntry = xml.search(/<(item|entry)[\s>]/i); const head = (firstEntry < 0 ? xml : xml.slice(0, firstEntry)).slice(0, 200_000);
  for (const m of `${head}${xml.slice(-4000)}`.matchAll(/<(?:atom:)?link\b[^>]{0,4000}>/gi)) {
    if ((linkAttr(m[0], 'rel') ?? '').toLowerCase() === 'next') { const u = absoluteUrl(linkAttr(m[0], 'href') ?? '', pageUrl); if (u !== null && !out.next.includes(u)) out.next.push(u); }
  }
  const total = xmlTag(xml, 'opensearch:totalResults');
  if (total !== null && /^\d+$/.test(total)) out.total = Number(total);
  for (const full of xmlBlocks(xml, atom ? 'entry' : 'item')) {
    const block = full.slice(0, 200_000);
    let link: string | null = null;
    if (atom) {
      const links = [...block.matchAll(/<link\b[^>]{0,4000}>/gi)].map((l) => ({ rel: (linkAttr(l[0], 'rel') ?? 'alternate').toLowerCase(), href: linkAttr(l[0], 'href') }));
      link = (links.find((l) => l.rel === 'alternate') ?? links[0])?.href ?? null;
    } else link = xmlTag(block, 'link') ?? (/isPermaLink\s*=\s*["']false/i.test(block) ? null : xmlTag(block, 'guid'));
    const url = link === null ? null : absoluteUrl(link, pageUrl);
    if (url === null) continue;
    const metadata: Record<string, unknown> = {};
    const published = xmlTag(block, atom ? 'updated' : 'pubDate') ?? xmlTag(block, 'published') ?? xmlTag(block, 'dc:date');
    if (published !== null) metadata.published = published.slice(0, 100);
    const guid = xmlTag(block, atom ? 'id' : 'guid'); if (guid !== null) metadata.guid = guid.slice(0, 500);
    const summary = xmlTag(block, atom ? 'summary' : 'description'); if (summary !== null) metadata.summary = summary.slice(0, 1000);
    const enclosure = /<enclosure\b[^>]{0,4000}>/i.exec(block); const encUrl = enclosure === null ? null : absoluteUrl(linkAttr(enclosure[0], 'url') ?? '', pageUrl);
    if (encUrl !== null) metadata.enclosure = encUrl;
    out.items.push({ url, title: xmlTag(block, 'title')?.slice(0, 500) ?? null, metadata });
  }
  return out;
}
export function jsonPath(value: unknown, path: string | undefined): unknown {
  if (path === undefined || path === '') return value;
  let cur: unknown = value;
  for (const key of path.split('.')) {
    if (cur === null || typeof cur !== 'object') return undefined;
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') return undefined;
    cur = Array.isArray(cur) ? cur[Number(key)] : Object.hasOwn(cur, key) ? (cur as Record<string, unknown>)[key] : undefined;
  }
  return cur;
}
export type JsonListingConfig = {
  itemsPath?: string; urlField?: string; titleField?: string; idField?: string; itemUrlTemplate?: string; metadataFields?: string[]; totalPath?: string;
  pagination?: { type: 'none' } | { type: 'cursor'; cursorPath: string; cursorParam: string } | { type: 'page'; pageParam: string; startPage?: number; totalPagesPath?: string }
    | { type: 'offset'; offsetParam: string; limitParam?: string; limit: number } | { type: 'next_url'; nextPath: string } | { type: 'link_header' };
};
export function jsonListing(text: string, pageUrl: string, config: JsonListingConfig, linkHeader?: string): Listing {
  const doc = JSON.parse(text) as unknown;
  const rows = jsonPath(doc, config.itemsPath);
  const out: Listing = { items: [], next: [] };
  const total = jsonPath(doc, config.totalPath ?? '\u0000'); if (typeof total === 'number') out.total = total;
  if (!Array.isArray(rows)) return out;
  for (const row of rows.slice(0, 5000)) {
    const raw = typeof row === 'string' ? row : jsonPath(row, config.urlField ?? 'url');
    const id = typeof row === 'string' ? undefined : jsonPath(row, config.idField ?? 'id');
    const href = typeof raw === 'string' && raw !== '' ? raw : config.itemUrlTemplate !== undefined && (typeof id === 'string' || typeof id === 'number') ? config.itemUrlTemplate.replaceAll('{id}', encodeURIComponent(String(id))) : null;
    const url = href === null ? null : absoluteUrl(href, pageUrl);
    if (url === null) continue;
    const metadata: Record<string, unknown> = {};
    if (typeof row === 'object' && row !== null) {
      if (typeof id === 'string' || typeof id === 'number') metadata.id = id;
      for (const f of config.metadataFields ?? []) { const v = jsonPath(row, f); if (v !== undefined && JSON.stringify(v).length <= 4000) metadata[f] = v; }
    }
    const title = typeof row === 'string' ? undefined : jsonPath(row, config.titleField ?? 'title');
    out.items.push({ url, title: typeof title === 'string' ? title.slice(0, 500) : null, metadata });
  }
  const p = config.pagination ?? { type: 'none' as const };
  const u = new URL(pageUrl);
  if (p.type === 'cursor') { const c = jsonPath(doc, p.cursorPath); if ((typeof c === 'string' && c !== '') || typeof c === 'number') { u.searchParams.set(p.cursorParam, String(c)); out.next.push(u.href); } }
  else if (p.type === 'next_url') { const n = jsonPath(doc, p.nextPath); const abs = typeof n === 'string' && n !== '' ? absoluteUrl(n, pageUrl) : null; if (abs !== null) out.next.push(abs); }
  else if (p.type === 'link_header') { const n = linkHeaderNext(linkHeader, pageUrl); if (n !== null) out.next.push(n); }
  else if (p.type === 'page' && rows.length > 0) {
    const page = Number(u.searchParams.get(p.pageParam) ?? p.startPage ?? 1); const totalPages = jsonPath(doc, p.totalPagesPath ?? '\u0000');
    if (typeof totalPages !== 'number' || page < totalPages) { u.searchParams.set(p.pageParam, String(page + 1)); out.next.push(u.href); }
  } else if (p.type === 'offset' && rows.length > 0) {
    const offset = Number(u.searchParams.get(p.offsetParam) ?? 0);
    if (rows.length >= p.limit && (out.total === undefined || out.total === null || offset + rows.length < out.total)) { u.searchParams.set(p.offsetParam, String(offset + rows.length)); if (p.limitParam !== undefined) u.searchParams.set(p.limitParam, String(p.limit)); out.next.push(u.href); }
  }
  return out;
}

// ───────────────────────────── Page metadata, access markers ─────────────────────────────
export type PageMetadata = { title: string | null; description: string | null; canonicalLink: string | null; published: string | null; language: string | null; author: string | null };
export function pageMetadata(root: HtmlNode, pageUrl: string): PageMetadata {
  const meta = (names: string[]): string | null => {
    for (const n of findAll(root, (x) => x.tag === 'meta')) { const key = (n.attrs.name ?? n.attrs.property ?? '').toLowerCase(); if (names.includes(key) && (n.attrs.content ?? '') !== '') return squash(n.attrs.content as string).slice(0, 1000); }
    return null;
  };
  const titleNode = findAll(root, (n) => n.tag === 'title')[0];
  const canonical = findAll(root, (n) => n.tag === 'link' && (n.attrs.rel ?? '').toLowerCase().split(/\s+/).includes('canonical'))[0]?.attrs.href;
  return {
    title: (titleNode === undefined ? null : squash(textOf(titleNode)).slice(0, 500) || null) ?? meta(['og:title']),
    description: meta(['description', 'og:description']), canonicalLink: canonical === undefined ? null : absoluteUrl(canonical, pageUrl),
    published: meta(['article:published_time', 'date', 'dc.date']), language: findAll(root, (n) => n.tag === 'html')[0]?.attrs.lang?.slice(0, 35) ?? null, author: meta(['author']),
  };
}
const DEFAULT_CHALLENGE = [/class\s*=\s*["'][^"']*\b(g-recaptcha|h-captcha|cf-turnstile)\b/i, /id\s*=\s*["']challenge-form["']/i, /\/cdn-cgi\/challenge-platform\//i];
/** Detects interactive challenges or operator-configured paywall markers in an otherwise successful page. */
export function accessMarker(text: string, extra: readonly string[] = []): string | null {
  const head = text.slice(0, 400_000);
  for (const re of DEFAULT_CHALLENGE) if (re.test(head)) return 'challenge_page';
  for (const marker of extra) if (marker !== '' && head.toLowerCase().includes(marker.toLowerCase())) return 'configured_marker';
  return null;
}

// ───────────────────────────── Shingles ─────────────────────────────
const CHROME = new Set([...SKIP_TEXT, 'nav', 'header', 'footer', 'aside', 'form', 'button', 'select']);
/** Main readable text of a page: prefers <article>/<main>, drops navigation chrome. */
export function mainText(root: HtmlNode): string {
  const main = findAll(root, (n) => n.tag === 'article')[0] ?? findAll(root, (n) => n.tag === 'main' || n.attrs.role === 'main')[0] ?? findAll(root, (n) => n.tag === 'body')[0] ?? root;
  return squash(textOf(main, CHROME));
}
export function normalizeForShingles(text: string): string[] {
  return text.normalize('NFKC').toLowerCase().replace(/[^\p{L}\p{N}\s]+/gu, ' ').split(/\s+/).filter((w) => w !== '');
}
/** Bottom-k sketch of 5-word shingles as signed 32-bit integers, ascending. Null when the text is too short to compare. */
export function shingleSketch(text: string, k = 192, width = 5): number[] | null {
  const words = normalizeForShingles(text).slice(0, 60_000);
  if (words.length < width + 15) return null;
  const set = new Set<number>();
  for (let i = 0; i + width <= words.length; i++) set.add(createHash('sha1').update(words.slice(i, i + width).join(' ')).digest().readInt32BE(0));
  return [...set].sort((a, b) => a - b).slice(0, k);
}
/** Jaccard estimate from two bottom-k sketches (exact when both sets are smaller than k). */
export function sketchSimilarity(a: readonly number[], b: readonly number[]): number {
  if (a.length === 0 || b.length === 0) return 0;
  const k = Math.min(Math.max(a.length, b.length), 192);
  const union = [...new Set([...a, ...b])].sort((x, y) => x - y).slice(0, k);
  const sa = new Set(a), sb = new Set(b);
  return union.filter((x) => sa.has(x) && sb.has(x)).length / union.length;
}

// ───────────────────────────── Contact leads ─────────────────────────────
export type ExtractedRoute = { kind: 'email' | 'postal' | 'web_form' | 'phone'; value: string };
export type ExtractedLead = { personName: string | null; role: string | null; organization: string | null; routes: ExtractedRoute[]; extractor: 'json_ld' | 'staff_listing' | 'mailto' | 'contact_section'; context: string };
const EMAIL = /[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}\.)+[A-Za-z]{2,24}/g;
const emailOk = (s: string): string | null => { const m = s.trim().match(EMAIL); return m !== null && m[0] === s.trim() ? s.trim().toLowerCase() : null; };
const str = (v: unknown, max = 300): string | null => (typeof v === 'string' && squash(v) !== '' ? squash(v).slice(0, max) : null);
function postal(v: unknown): string | null {
  if (typeof v === 'string') return str(v, 500);
  if (v === null || typeof v !== 'object') return null;
  const o = v as Record<string, unknown>;
  const parts = ['streetAddress', 'postOfficeBoxNumber', 'addressLocality', 'addressRegion', 'postalCode', 'addressCountry'].map((k) => (typeof o[k] === 'object' && o[k] !== null ? str((o[k] as Record<string, unknown>).name) : str(o[k]))).filter((x): x is string => x !== null);
  return parts.length === 0 ? null : parts.join(', ').slice(0, 500);
}
function jsonLdLeads(root: HtmlNode, out: ExtractedLead[]): void {
  for (const script of findAll(root, (n) => n.tag === 'script' && /ld\+json/i.test(n.attrs.type ?? ''))) {
    let doc: unknown;
    try { doc = JSON.parse(script.children.filter((c) => typeof c === 'string').join('').slice(0, 1_000_000)); } catch { continue; }
    const seen = new Set<unknown>(); let budget = 5000;
    const visit = (v: unknown, org: string | null): void => {
      if (v === null || typeof v !== 'object' || seen.has(v) || budget-- <= 0) return;
      seen.add(v);
      if (Array.isArray(v)) { for (const x of v) visit(x, org); return; }
      const o = v as Record<string, unknown>;
      const types = (Array.isArray(o['@type']) ? o['@type'] : [o['@type']]).filter((t): t is string => typeof t === 'string');
      const isPerson = types.includes('Person'); const isOrg = types.some((t) => /Organization|Corporation|NGO|GovernmentOffice|LocalBusiness|Library|Archive/.test(t)); const isPoint = types.includes('ContactPoint');
      const name = str(o.name);
      if (isPerson || isOrg || isPoint) {
        const routes: ExtractedRoute[] = [];
        const email = typeof o.email === 'string' ? emailOk(o.email.replace(/^mailto:/i, '')) : null; if (email !== null) routes.push({ kind: 'email', value: email });
        const address = postal(o.address); if (address !== null) routes.push({ kind: 'postal', value: address });
        const phone = str(o.telephone, 60); if (phone !== null) routes.push({ kind: 'phone', value: phone });
        if (isPoint && typeof o.url === 'string') routes.push({ kind: 'web_form', value: o.url.slice(0, 2000) });
        const works = o.worksFor ?? o.affiliation ?? o.memberOf;
        const worksName = works !== null && typeof works === 'object' ? str((Array.isArray(works) ? works[0] as Record<string, unknown> | undefined : works as Record<string, unknown>)?.name) : str(works);
        if (routes.length > 0) out.push({ personName: isPerson ? name : null, role: str(o.jobTitle) ?? (isPoint ? str(o.contactType) : null), organization: isPerson ? worksName ?? org : isOrg ? name : org, routes, extractor: 'json_ld', context: `schema.org ${types.join('/')}${name === null ? '' : `: ${name}`}` });
      }
      const nextOrg = isOrg ? name : org;
      for (const [k, x] of Object.entries(o)) if (k !== 'address' && typeof x === 'object') visit(x, nextOrg);
    };
    visit(doc, null);
  }
}
const mailtoOf = (n: HtmlNode): string | null => (n.tag === 'a' && /^mailto:/i.test(n.attrs.href ?? '') ? emailOk(decodeURIComponentSafe((n.attrs.href as string).slice(7).split('?')[0] ?? '')) : null);
function decodeURIComponentSafe(s: string): string { try { return decodeURIComponent(s); } catch { return s; } }
const STAFF = /\b(staff|team-member|team_member|person|people|member|vcard|h-card|profile|employee|contact-card|bio)\b/i;
const NAME = /\b(name|fn|p-name)\b/i; const ROLE = /\b(role|title|position|job|p-job-title|p-role)\b/i; const ORG = /\b(org|organization|organisation|p-org|affiliation)\b/i;
/** A page yielding more candidates than this is truncated: extraction cost stays bounded on hostile pages. */
const MAX_LEADS = 1000;
export function extractLeads(html: string, pageUrl: string, options: { contactTerms?: readonly string[] } = {}): ExtractedLead[] {
  const root = parseHtml(html);
  const out: ExtractedLead[] = [];
  jsonLdLeads(root, out);
  const claimed = new Set<HtmlNode>();
  // Staff listings: a card-like element containing exactly one mailto link and a name.
  for (const card of findAll(root, (n) => ['li', 'div', 'tr', 'article', 'section', 'dl'].includes(n.tag) && STAFF.test(n.attrs.class ?? '')).slice(0, MAX_LEADS)) {
    const mails = findAll(card, (n) => mailtoOf(n) !== null);
    if (mails.length !== 1) continue;
    const pick = (re: RegExp): string | null => { const n = findAll(card, (x) => classHas(x, re) && x.tag !== 'a')[0]; return n === undefined ? null : squash(textOf(n)).slice(0, 200) || null; };
    const heading = findAll(card, (n) => /^h[1-6]$/.test(n.tag) || n.tag === 'strong' || n.tag === 'b')[0];
    const name = pick(NAME) ?? (heading === undefined ? null : squash(textOf(heading)).slice(0, 200) || null);
    if (name === null) continue;
    claimed.add(mails[0] as HtmlNode);
    out.push({ personName: name, role: pick(ROLE), organization: pick(ORG), routes: [{ kind: 'email', value: mailtoOf(mails[0] as HtmlNode) as string }], extractor: 'staff_listing', context: squash(textOf(card)).slice(0, 300) });
  }
  // Contact sections: an element marked as contact, or the section following a heading that names a configured term.
  const terms = (options.contactTerms ?? ['contact']).map((t) => t.toLowerCase()).filter((t) => t !== '');
  const isTerm = (s: string): boolean => terms.some((t) => s.toLowerCase().includes(t));
  const sections = new Set<HtmlNode>();
  walk(root, (n) => {
    if (n.tag === 'address' || (['section', 'div', 'footer', 'aside'].includes(n.tag) && isTerm(`${n.attrs.class ?? ''} ${n.attrs.id ?? ''}`))) { sections.add(n); return false; }
    if (/^h[1-6]$/.test(n.tag) && isTerm(textOf(n)) && n.parent !== null && n.parent.tag !== '#root' && n.parent.tag !== 'body') { sections.add(n.parent); }
    return true;
  });
  for (const section of [...sections].slice(0, 200)) {
    const routes: ExtractedRoute[] = [];
    const text = textOf(section);
    for (const a of findAll(section, (n) => mailtoOf(n) !== null)) { if (claimed.has(a)) continue; claimed.add(a); routes.push({ kind: 'email', value: mailtoOf(a) as string }); }
    for (const e of (text.slice(0, 50_000).match(EMAIL) ?? []).slice(0, 50)) routes.push({ kind: 'email', value: e.toLowerCase() });
    for (const form of findAll(section, (n) => n.tag === 'form')) { const u = absoluteUrl(form.attrs.action ?? '', pageUrl) ?? pageUrl; routes.push({ kind: 'web_form', value: u }); }
    const addr = section.tag === 'address' ? section : findAll(section, (n) => n.tag === 'address')[0];
    if (addr !== undefined) { const t = squash(textOf(addr).replace(EMAIL, ' ')).slice(0, 500); if (t.length >= 8) routes.push({ kind: 'postal', value: t }); }
    routes.splice(60);
    const unique = routes.filter((r, i) => routes.findIndex((x) => x.kind === r.kind && x.value === r.value) === i);
    if (unique.length > 0) out.push({ personName: null, role: null, organization: null, routes: unique, extractor: 'contact_section', context: squash(text).slice(0, 300) });
  }
  // Remaining mailto links.
  for (const a of findAll(root, (n) => mailtoOf(n) !== null).slice(0, MAX_LEADS)) {
    if (claimed.has(a)) continue;
    const label = squash(textOf(a)); const email = mailtoOf(a) as string;
    out.push({ personName: label !== '' && emailOk(label) === null && label.length <= 120 && /\p{L}/u.test(label) && label.split(' ').length <= 6 && !isTerm(label) && !/e-?mail/i.test(label) ? label : null, role: null, organization: null, routes: [{ kind: 'email', value: email }], extractor: 'mailto', context: squash(textOf(a.parent ?? a)).slice(0, 300) });
  }
  // Merge leads that share an e-mail route; structured data wins on names.
  const merged: ExtractedLead[] = [];
  for (const lead of out.slice(0, MAX_LEADS)) {
    const emails = lead.routes.filter((r) => r.kind === 'email').map((r) => r.value);
    const prior = merged.find((m) => m.routes.some((r) => r.kind === 'email' && emails.includes(r.value)) && (m.personName === null || lead.personName === null || m.personName === lead.personName));
    if (prior === undefined) { merged.push({ ...lead, routes: [...lead.routes] }); continue; }
    prior.personName ??= lead.personName; prior.role ??= lead.role; prior.organization ??= lead.organization;
    for (const r of lead.routes) if (!prior.routes.some((x) => x.kind === r.kind && x.value === r.value)) prior.routes.push(r);
  }
  return merged.slice(0, 500);
}
