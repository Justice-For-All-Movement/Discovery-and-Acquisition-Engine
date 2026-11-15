import test from "node:test";
import assert from "node:assert/strict";
import { capture } from "../src/index.ts";
import type { SourcePolicy, CaptureDependencies } from "../src/index.ts";
import { DomainError, hashBytes } from "../src/contracts.ts";
import type { Context } from "../src/contracts.ts";
const c: Context = {
  tenantId: "alpha",
  projectId: "study",
  actor: { id: "worker", kind: "service", roles: ["researcher"] },
  purpose: "research",
  requestId: "r",
  now: "2026-01-01T00:00:00Z",
};
const p: SourcePolicy = {
  tenantId: "alpha",
  projectId: "study",
  id: "source",
  allowedHosts: ["archive.example"],
  enabled: true,
  expiresAt: "2026-02-01T00:00:00Z",
  maximumBytes: 1000,
  maximumRedirects: 1,
  userAgent: "ResearchAssistant/0.1",
  accessBasis: "Authorized fictional capture",
};
const reply = {
  status: 200,
  headers: { "content-type": "text/plain" },
  bytes: Buffer.from("Fictional source"),
};
test("context policy and dependency functions are captured before caller mutation across DNS waits", async () => {
  const context = structuredClone(c),
    policy = structuredClone(p);
  let complete!: (v: string[]) => void;
  const gate = new Promise<string[]>((r) => {
    complete = r;
  });
  const deps: CaptureDependencies = {
    resolve: () => gate,
    transport: async (u, o) => {
      assert.equal(u.hostname, "archive.example");
      assert.equal(o.maximumBytes, 1000);
      assert.equal(o.userAgent, p.userAgent);
      return reply;
    },
  };
  const pending = capture(
    context,
    "https://archive.example/item",
    policy,
    deps,
  );
  (context as { tenantId: string }).tenantId = "beta";
  policy.id = "changed";
  policy.allowedHosts = ["other.example"];
  policy.maximumBytes = 1;
  deps.transport = async () => {
    throw new Error("modified transport");
  };
  complete(["8.8.8.8"]);
  const result = await pending;
  assert.equal(result.tenantId, "alpha");
  assert.equal(result.sourcePolicyId, "source");
  assert.equal(result.sha256, hashBytes(reply.bytes));
});
test("validated DNS pin and request URL cannot be replaced by dependency-owned mutable objects", async () => {
  let reads = 0;
  const addresses = ["8.8.8.8"];
  Object.defineProperty(addresses, 0, {
    get: () => (++reads === 1 ? "8.8.8.8" : "127.0.0.1"),
  });
  const result = await capture(c, "https://archive.example/item", p, {
    resolve: async () => addresses,
    transport: async (u, o) => {
      assert.equal(o.address, "8.8.8.8");
      u.hostname = "private.example";
      return reply;
    },
  });
  assert.equal(result.finalUrl, "https://archive.example/item");
});
test("returned byte provenance remains stable after the transport buffer is changed", async () => {
  const bytes = Buffer.from("Fictional source");
  const result = await capture(c, "https://archive.example/item", p, {
    resolve: async () => ["8.8.8.8"],
    transport: async () => ({ ...reply, bytes }),
  });
  bytes.fill(0);
  assert.equal(Buffer.from(result.bytes).toString(), "Fictional source");
  assert.equal(hashBytes(result.bytes), result.sha256);
});
test("total deadline bounds unresolved DNS and prevents later resolution from starting transport", async () => {
  let complete!: (v: string[]) => void,
    calls = 0;
  const gate = new Promise<string[]>((r) => {
    complete = r;
  });
  await assert.rejects(
    capture(c, "https://archive.example/item", p, {
      timeoutMs: 10,
      resolve: () => gate,
      transport: async () => {
        calls++;
        return reply;
      },
    }),
    { code: "capture_timeout" },
  );
  complete(["8.8.8.8"]);
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(calls, 0);
});
test("deadline and cancellation bound a noncooperating transport and propagate an aborted signal", async () => {
  let signal: AbortSignal | undefined;
  await assert.rejects(
    capture(c, "https://archive.example/item", p, {
      timeoutMs: 10,
      resolve: async () => ["8.8.8.8"],
      transport: async (_u, o) => {
        signal = o.signal;
        return new Promise(() => {});
      },
    }),
    { code: "capture_timeout" },
  );
  assert.equal(signal?.aborted, true);
  const controller = new AbortController();
  let entered!: () => void;
  const started = new Promise<void>((r) => {
    entered = r;
  });
  const pending = capture(c, "https://archive.example/item", p, {
    signal: controller.signal,
    resolve: async () => ["8.8.8.8"],
    transport: async (_u, o) => {
      signal = o.signal;
      entered();
      return new Promise(() => {});
    },
  });
  await started;
  controller.abort("private cancellation reason");
  await assert.rejects(
    pending,
    (e: any) => e.code === "capture_aborted" && !e.message.includes("private"),
  );
  assert.equal(signal?.aborted, true);
  let calls = 0;
  await assert.rejects(
    capture(c, "https://archive.example/item", p, {
      signal: controller.signal,
      resolve: async () => {
        calls++;
        return [];
      },
    }),
    { code: "capture_aborted" },
  );
  assert.equal(calls, 0);
});
test("runtime limits strict enabled policy and provider failures fail without leaking diagnostics", async () => {
  for (const timeoutMs of [NaN, 0, 30001])
    await assert.rejects(
      capture(c, "https://archive.example/item", p, { timeoutMs }),
      { code: "invalid_deadline" },
    );
  await assert.rejects(
    capture(c, "https://archive.example/item", { ...p, enabled: "yes" as any }),
    { code: "connector_disabled" },
  );
  for (const deps of [
    {
      resolve: async () => {
        throw new DomainError("provider_internal", "secret adapter diagnostic");
      },
    },
    {
      resolve: async () => {
        throw new Error("secret DNS credential");
      },
    },
    {
      resolve: async () => ["8.8.8.8"],
      transport: async () => {
        throw new Error("secret provider credential");
      },
    },
  ])
    await assert.rejects(
      capture(c, "https://archive.example/item", p, deps),
      (e: any) =>
        e.code === "capture_unavailable" && !e.message.includes("secret"),
    );
});

test('late synchronous DNS result cannot start transport after the total deadline', async () => {
  let calls = 0;
  await assert.rejects(capture(c, 'https://archive.example/item', p, {
    timeoutMs: 10,
    resolve: async () => {
      const until = performance.now() + 30;
      while (performance.now() < until) { /* adversarial event-loop blockage */ }
      return ['8.8.8.8'];
    },
    transport: async () => { calls++; return reply; },
  }), { code: 'capture_timeout' });
  assert.equal(calls, 0);
});

test('late synchronous transport result cannot publish bytes before delayed timer callback', async () => {
  let signal: AbortSignal | undefined;
  await assert.rejects(capture(c, 'https://archive.example/item', p, {
    timeoutMs: 10, resolve: async () => ['8.8.8.8'],
    transport: async (_url, options) => {
      signal = options.signal;
      const until = performance.now() + 30;
      while (performance.now() < until) { /* timers cannot preempt synchronous code */ }
      return reply;
    },
  }), { code: 'capture_timeout' });
  assert.equal(signal?.aborted, true);
});

test('late response metadata work cannot publish a capture after dependency await completed', async () => {
  let signal: AbortSignal | undefined;
  const headers = { ...reply.headers } as Record<string, string | undefined>;
  Object.defineProperty(headers, 'last-modified', { get: () => {
    const until = performance.now() + 30;
    while (performance.now() < until) { /* trusted adapter metadata can still consume time */ }
    return 'synthetic timestamp';
  } });
  await assert.rejects(capture(c, 'https://archive.example/item', p, {
    timeoutMs: 10, resolve: async () => ['8.8.8.8'],
    transport: async (_url, options) => { signal = options.signal; return { ...reply, headers }; },
  }), { code: 'capture_timeout' });
  assert.equal(signal?.aborted, true);
});

test('late resolver rejection is classified as timeout without leaking provider diagnostics', async () => {
  await assert.rejects(capture(c, 'https://archive.example/item', p, {
    timeoutMs: 10,
    resolve: async () => {
      const until = performance.now() + 30;
      while (performance.now() < until) { /* delay timer delivery before rejection */ }
      throw new Error('private DNS diagnostics');
    },
  }), (error: unknown) => error instanceof DomainError && error.code === 'capture_timeout' && !error.message.includes('private'));
});
