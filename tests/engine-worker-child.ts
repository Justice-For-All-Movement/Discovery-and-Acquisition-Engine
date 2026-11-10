// Child process used by the crash test: runs one worker pass and is killed with SIGKILL part-way through.
import pg from 'pg';
import * as kit from '../src/service-kit.ts';
import { createEngine } from '../src/engine/index.ts';

const pool = new pg.Pool({ connectionString: process.env.E04_CHILD_DB as string, max: 4 });
const engine = createEngine({ sql: kit.pgSql(pool), objects: new kit.FsObjectStore(process.env.E04_CHILD_OBJECTS as string), config: JSON.parse(process.env.E04_CHILD_CONFIG as string) });
while (await engine.runWorkerOnce() === 0) await new Promise((r) => setTimeout(r, 50));
await pool.end();
