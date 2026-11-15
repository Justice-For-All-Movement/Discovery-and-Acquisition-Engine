# Discovery and Acquisition Engine

Reusable country-neutral engine. Initial capabilities and limits are documented in [architecture](docs/ARCHITECTURE.md); the canonical work plan is [registry/prs.json](registry/prs.json).

```sh
npm ci
npm run check
```

All research and jurisdiction configuration belong in downstream deployments. Implementation, local tests, CI, merge and live acceptance are separate.

## Service layer

The engine service (E04, schema `e04_discovery`) is in `src/engine/`; the full surface is documented in
[docs/ENGINE_API.md](docs/ENGINE_API.md).

```sh
# run
DATABASE_URL=postgresql://... IDENTITY_PUBLIC_KEYS='{"kid":"-----BEGIN PUBLIC KEY-----..."}' \
DISCOVERY_USER_AGENT='ExampleResearchBot/1.0 (+https://example.org/bot)' OBJECT_STORE=fs OBJECT_STORE_PATH=./data/objects \
PORT=8104 npm run serve

# test (real PostgreSQL; tests create and drop their own databases and use only a local fixture server)
TEST_DATABASE_URL=postgresql://pam:pam@127.0.0.1:5432/postgres npm run check
```

```ts
import { createEngine, migrate, routes } from '@accountability/discovery-acquisition/engine';
await migrate(sql);
const engine = createEngine({ sql, objects, ports: { evidence }, config: { userAgent: 'ExampleResearchBot/1.0 (+https://example.org/bot)' } });
const source = await engine.createSource(ctx, { name: 'Example archive', kind: 'html_index', baseUrl: 'https://archive.example.org/list', accessTerms: 'Public; citation only', reuse: 'citation_only' });
const run = await engine.startCollection(ctx, { sourceId: source.id, level: 'bytes' });
await engine.runWorkerOnce();                       // normally the serve loop does this
const coverage = await engine.coverage(ctx, { runId: run.id });
```
