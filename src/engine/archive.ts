// Private research archive import: ZIP, WARC (optionally gzip) or a directory under the configured import root.
// Reuses the bounded WARC/ZIP inventory parsers in ../archive-formats.ts; members are inflated with hard output limits.
import { createHash } from 'node:crypto';
import { lstat, readdir, readFile, realpath } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { crc32, gunzipSync, inflateRawSync } from 'node:zlib';
import { DomainError, invariant } from '../contracts.ts';
import type { Context, Json } from '../contracts.ts';
import { parseWarc, parseZip } from '../archive-formats.ts';
import type { WarcRecord, ZipMember } from '../archive-formats.ts';
import type { Capture, SourcePolicy } from '../index.ts';

export type ArchiveManifestEntry = { path: string; originalUrl?: string; retrievedAt?: string; title?: string; mediaType?: string; sha256?: string; note?: string; history?: Json[] };
export type ArchiveManifest = { collection?: string; collectedBy?: string; description?: string; entries: ArchiveManifestEntry[] };
export type ArchiveEntry = { path: string; bytes: Uint8Array; originalUrl: string | null; retrievedAt: string | null; title: string | null; mediaType: string | null; note: string | null; history: Json[]; listed: boolean; sha256Mismatch: boolean; recordId?: string };
export type ArchiveRead = { sha256: string; entries: ArchiveEntry[]; missing: { path: string; originalUrl: string | null }[]; skipped: Record<string, number>; manifestSummary: Json };

const MAX_ARCHIVE = 25 * 1024 * 1024;
const LIMITS = { maximumEntries: 5000, maximumEntryBytes: 25 * 1024 * 1024, maximumExpandedBytes: 200 * 1024 * 1024, maximumHeaderBytes: 16 * 1024 };
const sha = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex');

function validManifest(value: unknown): ArchiveManifest {
  invariant(value !== null && typeof value === 'object' && !Array.isArray(value) && Array.isArray((value as ArchiveManifest).entries) && (value as ArchiveManifest).entries.length <= 20_000, 'invalid_input', 'Manifest must be an object with an entries list');
  const m = value as ArchiveManifest;
  for (const e of m.entries) {
    invariant(e !== null && typeof e === 'object' && typeof e.path === 'string' && e.path !== '' && e.path.length <= 4000, 'invalid_input', 'Every manifest entry needs a path');
    invariant(e.retrievedAt === undefined || Number.isFinite(Date.parse(e.retrievedAt)), 'invalid_input', `Manifest entry ${e.path} has an invalid retrievedAt`);
    invariant(e.history === undefined || (Array.isArray(e.history) && JSON.stringify(e.history).length <= 20_000), 'invalid_input', `Manifest entry ${e.path} has an invalid history`);
    for (const k of ['originalUrl', 'title', 'mediaType', 'sha256', 'note'] as const) invariant(e[k] === undefined || (typeof e[k] === 'string' && (e[k] as string).length <= 4000), 'invalid_input', `Manifest entry ${e.path} has an invalid ${k}`);
  }
  return m;
}
function synthetic(ctx: Context, bytes: Uint8Array, contentType: string, userAgent: string): { policy: SourcePolicy; capture: Capture } {
  const url = 'https://archive-import.invalid/archive';
  const policy: SourcePolicy = { tenantId: ctx.tenantId, projectId: ctx.projectId, id: 'private-archive-import', allowedHosts: ['archive-import.invalid'], enabled: true, expiresAt: new Date(Date.parse(ctx.now) + 86_400_000).toISOString(), maximumBytes: MAX_ARCHIVE, maximumRedirects: 0, userAgent, accessBasis: 'private archive supplied by the operator' };
  return { policy, capture: { tenantId: ctx.tenantId, projectId: ctx.projectId, sourcePolicyId: policy.id, requestedUrl: url, finalUrl: url, retrievedAt: ctx.now, status: 200, contentType, sha256: sha(bytes), bytes, redirects: [], etag: null, lastModified: null } };
}
const wrap = <T>(fn: () => T): T => { try { return fn(); } catch (e) { if (e instanceof DomainError) throw new DomainError('invalid_input', `Archive rejected (${e.code}): ${e.message}`); throw e; } };

function withManifest(files: { path: string; bytes: Uint8Array; originalUrl?: string | null; retrievedAt?: string | null; mediaType?: string | null; recordId?: string }[], manifest: ArchiveManifest | null, matchUrl: boolean): { entries: ArchiveEntry[]; missing: ArchiveRead['missing'] } {
  const used = new Set<ArchiveManifestEntry>();
  const entries = files.map((f): ArchiveEntry => {
    const m = manifest?.entries.find((e) => !used.has(e) && (e.path === f.path || (matchUrl && e.originalUrl !== undefined && e.originalUrl === f.originalUrl)));
    if (m !== undefined && !matchUrl) used.add(m);
    return {
      path: f.path, bytes: f.bytes, originalUrl: f.originalUrl ?? m?.originalUrl ?? null, retrievedAt: f.retrievedAt ?? (m?.retrievedAt === undefined ? null : new Date(m.retrievedAt).toISOString()),
      title: m?.title ?? null, mediaType: f.mediaType ?? m?.mediaType ?? null, note: m?.note ?? null, history: m?.history ?? [], listed: m !== undefined || matchUrl,
      sha256Mismatch: m?.sha256 !== undefined && m.sha256.toLowerCase() !== sha(f.bytes), ...(f.recordId === undefined ? {} : { recordId: f.recordId }),
    };
  });
  const missing = matchUrl ? [] : (manifest?.entries ?? []).filter((e) => !used.has(e)).map((e) => ({ path: e.path, originalUrl: e.originalUrl ?? null }));
  return { entries, missing };
}

function readZip(ctx: Context, bytes: Uint8Array, supplied: ArchiveManifest | null, userAgent: string): ArchiveRead {
  const { policy, capture } = synthetic(ctx, bytes, 'application/zip', userAgent);
  const inventory = wrap(() => parseZip(ctx, policy, capture, LIMITS));
  const files: { path: string; bytes: Uint8Array }[] = []; let manifest = supplied; let total = 0;
  for (const m of inventory.entries as ZipMember[]) {
    const raw = bytes.subarray(m.dataOffset, m.dataOffset + m.compressedLength);
    let data: Uint8Array;
    try { data = m.method === 0 ? Uint8Array.from(raw) : new Uint8Array(inflateRawSync(raw, { maxOutputLength: Math.max(1, m.uncompressedLength) })); } catch { throw new DomainError('invalid_input', `ZIP member ${m.id} could not be inflated within its declared size`); }
    invariant(data.byteLength === m.uncompressedLength && (crc32(data) >>> 0) === (m.crc32 >>> 0), 'invalid_input', `ZIP member ${m.id} fails its size or CRC check`);
    total += data.byteLength; invariant(total <= LIMITS.maximumExpandedBytes, 'invalid_input', 'ZIP expands beyond the import limit');
    if (m.id === 'manifest.json') { if (manifest === null) { try { manifest = validManifest(JSON.parse(Buffer.from(data).toString('utf8'))); } catch (e) { if (e instanceof DomainError) throw e; throw new DomainError('invalid_input', 'manifest.json inside the archive is not valid JSON'); } } continue; }
    files.push({ path: m.id, bytes: data });
  }
  const r = withManifest(files, manifest, false);
  return { sha256: inventory.archiveSha256, ...r, skipped: {}, manifestSummary: manifest === null ? null : { collection: manifest.collection ?? null, collectedBy: manifest.collectedBy ?? null, description: manifest.description ?? null, entries: manifest.entries.length } };
}

function readWarc(ctx: Context, input: Uint8Array, manifest: ArchiveManifest | null, userAgent: string): ArchiveRead {
  let bytes = input;
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) { try { bytes = new Uint8Array(gunzipSync(bytes, { maxOutputLength: MAX_ARCHIVE })); } catch { throw new DomainError('invalid_input', 'Compressed WARC could not be expanded within the import limit'); } }
  const { policy, capture } = synthetic(ctx, bytes, 'application/warc', userAgent);
  const inventory = wrap(() => parseWarc(ctx, policy, capture, LIMITS));
  const files: Parameters<typeof withManifest>[0] = []; const skipped: Record<string, number> = {}; let cursor = 0;
  for (const rec of inventory.entries as WarcRecord[]) {
    const header = Buffer.from(bytes.subarray(cursor, rec.payloadOffset)).toString('latin1'); cursor = rec.payloadOffset + rec.payloadLength + 4;
    const field = (name: string): string | null => new RegExp(`^${name}:\\s*(.+?)\\s*$`, 'im').exec(header)?.[1] ?? null;
    const target = field('WARC-Target-URI')?.replace(/^<|>$/g, '') ?? null; const date = field('WARC-Date');
    if ((rec.kind !== 'response' && rec.kind !== 'resource') || target === null) { skipped[rec.kind] = (skipped[rec.kind] ?? 0) + 1; continue; }
    let payload = bytes.subarray(rec.payloadOffset, rec.payloadOffset + rec.payloadLength); let mediaType: string | null = rec.contentType.split(';')[0]?.trim().toLowerCase() ?? null;
    if (rec.kind === 'response' && /^application\/http/i.test(rec.contentType)) {
      const split = Buffer.from(payload).indexOf('\r\n\r\n');
      if (split < 0) { skipped.malformed_http = (skipped.malformed_http ?? 0) + 1; continue; }
      const head = Buffer.from(payload.subarray(0, split)).toString('latin1');
      const status = Number(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/.exec(head)?.[1] ?? 0);
      if (status < 200 || status >= 300) { skipped[`http_${status}`] = (skipped[`http_${status}`] ?? 0) + 1; continue; }
      if (/^transfer-encoding:\s*chunked/im.test(head) || /^content-encoding:\s*(?!identity)\S/im.test(head)) { skipped.encoded_http_body = (skipped.encoded_http_body ?? 0) + 1; continue; }
      mediaType = /^content-type:\s*([^;\r\n]+)/im.exec(head)?.[1]?.trim().toLowerCase() ?? null;
      payload = payload.subarray(split + 4);
    }
    files.push({ path: target, bytes: Uint8Array.from(payload), originalUrl: target, retrievedAt: date !== null && Number.isFinite(Date.parse(date)) ? new Date(date).toISOString() : null, mediaType, recordId: rec.id });
  }
  files.sort((a, b) => String(a.retrievedAt ?? '').localeCompare(String(b.retrievedAt ?? '')));
  return { sha256: sha(input), ...withManifest(files, manifest, true), skipped, manifestSummary: manifest === null ? null : { collection: manifest.collection ?? null, collectedBy: manifest.collectedBy ?? null, entries: manifest.entries.length } };
}

async function readDirectory(root: string | undefined, path: string, supplied: ArchiveManifest | null): Promise<ArchiveRead> {
  if (root === undefined) throw new DomainError('unavailable', 'Directory import needs a configured import root (DISCOVERY_IMPORT_ROOT)');
  invariant(typeof path === 'string' && path !== '' && !path.includes('\0'), 'invalid_input', 'Import path is required');
  let base: string; let dir: string;
  try { base = await realpath(resolve(root)); dir = await realpath(resolve(base, path)); } catch { throw new DomainError('invalid_input', 'Import directory does not exist under the import root'); }
  invariant(dir === base || dir.startsWith(base + sep), 'invalid_input', 'Import path escapes the import root');
  const files: { path: string; bytes: Uint8Array }[] = []; const skipped: Record<string, number> = {}; let total = 0; let manifest = supplied;
  const walk = async (d: string, rel: string): Promise<void> => {
    for (const name of (await readdir(d)).sort()) {
      const full = join(d, name); const st = await lstat(full); const p = rel === '' ? name : `${rel}/${name}`;
      if (st.isSymbolicLink()) { skipped.symlink = (skipped.symlink ?? 0) + 1; continue; }
      if (st.isDirectory()) { await walk(full, p); continue; }
      if (!st.isFile()) { skipped.special = (skipped.special ?? 0) + 1; continue; }
      if (st.size > LIMITS.maximumEntryBytes) { skipped.too_large = (skipped.too_large ?? 0) + 1; continue; }
      invariant(files.length < LIMITS.maximumEntries, 'invalid_input', 'Directory holds more files than the import limit');
      total += st.size; invariant(total <= LIMITS.maximumExpandedBytes, 'invalid_input', 'Directory exceeds the import size limit');
      const data = new Uint8Array(await readFile(full));
      if (p === 'manifest.json') { if (manifest === null) { try { manifest = validManifest(JSON.parse(Buffer.from(data).toString('utf8'))); } catch (e) { if (e instanceof DomainError) throw e; throw new DomainError('invalid_input', 'manifest.json is not valid JSON'); } } continue; }
      files.push({ path: p, bytes: data });
    }
  };
  await walk(dir, '');
  const r = withManifest(files, manifest, false);
  return { sha256: createHash('sha256').update(JSON.stringify(files.map((f) => [f.path, sha(f.bytes)]))).digest('hex'), ...r, skipped, manifestSummary: manifest === null ? null : { collection: manifest.collection ?? null, collectedBy: manifest.collectedBy ?? null, description: manifest.description ?? null, entries: manifest.entries.length } };
}

export async function readArchive(ctx: Context, input: { format: 'zip' | 'warc' | 'directory'; bytes?: Uint8Array; path?: string; manifest?: ArchiveManifest; importRoot?: string; userAgent: string }): Promise<ArchiveRead> {
  const manifest = input.manifest === undefined ? null : validManifest(input.manifest);
  if (input.format === 'directory') return readDirectory(input.importRoot, input.path ?? '', manifest);
  invariant(input.format === 'zip' || input.format === 'warc', 'invalid_input', 'format must be zip, warc or directory');
  invariant(input.bytes instanceof Uint8Array && input.bytes.byteLength > 0 && input.bytes.byteLength <= MAX_ARCHIVE, 'invalid_input', `Archive bytes are required and limited to ${MAX_ARCHIVE} bytes`);
  return input.format === 'zip' ? readZip(ctx, input.bytes, manifest, input.userAgent) : readWarc(ctx, input.bytes, manifest, input.userAgent);
}
