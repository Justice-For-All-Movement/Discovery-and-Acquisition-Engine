// Standalone server: reads env, migrates, serves HTTP and runs the job worker loop.
import { readFileSync } from 'node:fs';
import pg from 'pg';
import * as kit from '../service-kit.ts';
import { createEngine, manifest, migrate, routes } from './index.ts';

const env = process.env;
function required(name: string): string { const v = env[name]; if (v === undefined || v === '') { console.error(`${name} is required`); process.exit(2); } return v; }
function publicKeys(): Record<string, string> {
  if (env.IDENTITY_PUBLIC_KEYS !== undefined && env.IDENTITY_PUBLIC_KEYS !== '') return JSON.parse(env.IDENTITY_PUBLIC_KEYS) as Record<string, string>;
  if (env.IDENTITY_JWKS_FILE !== undefined && env.IDENTITY_JWKS_FILE !== '') return JSON.parse(readFileSync(env.IDENTITY_JWKS_FILE, 'utf8')) as Record<string, string>;
  console.error('IDENTITY_PUBLIC_KEYS (JSON map kid→PEM) or IDENTITY_JWKS_FILE is required'); return process.exit(2);
}
const list = (v: string | undefined): string[] => (v ?? '').split(',').map((x) => x.trim()).filter((x) => x !== '');

const pool = new pg.Pool({ connectionString: required('DATABASE_URL'), max: Number(env.PG_POOL_MAX ?? 10) });
const sql = kit.pgSql(pool);
await migrate(sql);
const objects = env.OBJECT_STORE === 'none' ? undefined : kit.objectStoreFromEnv(env, './data/objects');
const engine = createEngine({
  sql, ...(objects === undefined ? {} : { objects }),
  config: {
    userAgent: required('DISCOVERY_USER_AGENT'),
    allowedPrivateHosts: list(env.DISCOVERY_ALLOWED_PRIVATE_HOSTS),
    ...(env.DISCOVERY_ALLOWED_PORTS === undefined ? {} : { allowedPorts: list(env.DISCOVERY_ALLOWED_PORTS).map(Number) }),
    ...(env.DISCOVERY_MAX_BYTES === undefined ? {} : { maxBytes: Number(env.DISCOVERY_MAX_BYTES) }),
    ...(env.DISCOVERY_TIMEOUT_MS === undefined ? {} : { timeoutMs: Number(env.DISCOVERY_TIMEOUT_MS) }),
    ...(env.DISCOVERY_CREDENTIAL_KEY === undefined || env.DISCOVERY_CREDENTIAL_KEY === '' ? {} : { credentialKey: env.DISCOVERY_CREDENTIAL_KEY }),
    ...(env.DISCOVERY_IMPORT_ROOT === undefined || env.DISCOVERY_IMPORT_ROOT === '' ? {} : { importRoot: env.DISCOVERY_IMPORT_ROOT }),
  },
});
const handler = kit.createHttpHandler({
  name: manifest.id, version: manifest.version, routes: routes(engine), health: engine.health,
  verify: kit.createTokenVerifier({ publicKeys: publicKeys(), ...(env.IDENTITY_ISSUER === undefined ? {} : { issuer: env.IDENTITY_ISSUER }) }),
  onError: (error, info) => console.error(JSON.stringify({ level: 'error', ...info, error: error instanceof Error ? error.name : 'error' })),
});
const server = await kit.serve(handler, Number(env.PORT ?? 8104), env.HOST ?? '127.0.0.1');
console.log(JSON.stringify({ level: 'info', msg: 'discovery engine listening', port: (server.address() as { port: number }).port }));

let stopping = false;
const concurrency = Math.max(1, Math.min(8, Number(env.DISCOVERY_WORKERS ?? 2)));
async function loop(): Promise<void> {
  while (!stopping) {
    try { if (await engine.runWorkerOnce() === 0) await new Promise((r) => setTimeout(r, 1000)); }
    catch (error) { console.error(JSON.stringify({ level: 'error', msg: 'worker pass failed', error: error instanceof Error ? error.name : 'error' })); await new Promise((r) => setTimeout(r, 5000)); }
  }
}
const workers = env.DISCOVERY_WORKERS === '0' ? [] : Array.from({ length: concurrency }, loop);
const scheduler = setInterval(() => { void engine.runDueWork().catch(() => console.error(JSON.stringify({ level: 'error', msg: 'scheduler pass failed' }))); }, Number(env.DISCOVERY_SCHEDULER_MS ?? 60_000));
for (const signal of ['SIGINT', 'SIGTERM'] as const) process.on(signal, () => { stopping = true; clearInterval(scheduler); server.close(); void Promise.all(workers).then(() => pool.end()).then(() => process.exit(0)); setTimeout(() => process.exit(0), 5000).unref(); });
