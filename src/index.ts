import { request } from "node:https";
import { performance } from "node:perf_hooks";
import { resolve4 } from "node:dns/promises";
import { isIP } from "node:net";
import {
  DomainError,
  hashBytes,
  invariant,
  requireScope,
  validTime,
  nonempty,
} from "./contracts.ts";
import type { Context, Scope } from "./contracts.ts";
export interface SourcePolicy extends Scope {
  id: string;
  allowedHosts: readonly string[];
  enabled: boolean;
  expiresAt: string;
  maximumBytes: number;
  maximumRedirects: number;
  userAgent: string;
  accessBasis: string;
}
export interface Capture extends Scope {
  sourcePolicyId: string;
  requestedUrl: string;
  finalUrl: string;
  retrievedAt: string;
  status: 200;
  contentType: string;
  sha256: string;
  bytes: Uint8Array;
  redirects: readonly string[];
  etag: string | null;
  lastModified: string | null;
}
export function allowedUrl(raw: string, policy: SourcePolicy): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error("Invalid source URL");
  }
  invariant(
    u.protocol === "https:" &&
      !u.username &&
      !u.password &&
      !u.hash &&
      (!u.port || u.port === "443"),
    "unsafe_url",
    "Only credential-free HTTPS sources are supported",
  );
  invariant(
    policy.allowedHosts.includes(u.hostname.toLowerCase()) && !isIP(u.hostname),
    "host_denied",
    "Source hostname is not approved",
  );
  return u;
}
export function isPublicIpv4(ip: string): boolean {
  if (isIP(ip) !== 4) return false;
  const p = ip.split(".").map(Number);
  const a = p[0]!,
    b = p[1]!,
    c = p[2]!;
  return !(
    a === 0 ||
    a === 10 ||
    a === 127 ||
    a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 &&
      (b === 168 || b === 0 || b === 2 || (b === 88 && c === 99))) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113)
  );
}
export interface NetworkReply {
  status: number;
  headers: Record<string, string | undefined>;
  bytes: Uint8Array;
}
export type CaptureTransport = (
  url: URL,
  options: {
    address: string;
    maximumBytes: number;
    userAgent: string;
    signal: AbortSignal;
  },
) => Promise<NetworkReply>;
export const pinnedHttpsTransport: CaptureTransport = (url, options) =>
  new Promise((resolve, reject) => {
    const req = request(
      url,
      {
        method: "GET",
        family: 4,
        lookup: (_host, _options, callback) =>
          callback(null, options.address, 4),
        signal: options.signal,
        timeout: 10000,
        headers: {
          "User-Agent": options.userAgent,
          "Accept-Encoding": "identity",
          Accept: "text/plain,text/html,application/json,application/pdf,application/warc,application/zip",
        },
      },
      (res) => {
        const encoding = res.headers["content-encoding"];
        if (encoding && encoding !== "identity") {
          res.destroy();
          reject(new Error("unsupported_encoding"));
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > options.maximumBytes) {
            res.destroy(new Error("capture_too_large"));
            return;
          }
          chunks.push(chunk);
        });
        res.on("error", reject);
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: Object.fromEntries(
              ["content-type", "location", "etag", "last-modified"].map((k) => [
                k,
                typeof res.headers[k] === "string" ? res.headers[k] : undefined,
              ]),
            ),
            bytes: Buffer.concat(chunks),
          }),
        );
      },
    );
    req.on("timeout", () => req.destroy(new Error("capture_timeout")));
    req.on("error", reject);
    req.end();
  });
export type CaptureDependencies = {
  resolve?: (hostname: string) => Promise<string[]>;
  transport?: CaptureTransport;
  timeoutMs?: number;
  signal?: AbortSignal;
};
/** Snapshot admission policy before awaits; one deadline covers DNS, redirects and bytes. */
export async function capture(
  context: Context,
  raw: string,
  sourcePolicy: SourcePolicy,
  deps: CaptureDependencies = {},
): Promise<Capture> {
  const ctx = structuredClone(context),
    policy = structuredClone(sourcePolicy);
  const resolver = deps.resolve ?? resolve4,
    transport = deps.transport ?? pinnedHttpsTransport,
    parentSignal = deps.signal,
    timeoutMs = deps.timeoutMs ?? 30000;
  requireScope(ctx, policy);
  invariant(
    policy.enabled === true && validTime(ctx.now) < validTime(policy.expiresAt),
    "connector_disabled",
    "Source policy unavailable or expired",
  );
  invariant(
    Number.isInteger(policy.maximumBytes) &&
      policy.maximumBytes > 0 &&
      policy.maximumBytes <= 25 * 1024 * 1024 &&
      Number.isInteger(policy.maximumRedirects) &&
      policy.maximumRedirects >= 0 &&
      policy.maximumRedirects <= 5,
    "invalid_policy",
    "Capture limits are invalid",
  );
  invariant(
    Number.isSafeInteger(timeoutMs) && timeoutMs >= 10 && timeoutMs <= 30000,
    "invalid_deadline",
    "Capture deadline must be 10-30000 milliseconds",
  );
  nonempty(policy.accessBasis, "access basis");
  nonempty(policy.userAgent, "user agent", 200);
  invariant(
    !/[\r\n]/.test(policy.userAgent),
    "invalid_policy",
    "Invalid user agent",
  );
  let current = allowedUrl(raw, policy);
  const redirects: string[] = [],
    seen = new Set<string>();
  const controller = new AbortController();
  let timedOut = false;
  const abort = () => controller.abort();
  parentSignal?.addEventListener("abort", abort, { once: true });
  if (parentSignal?.aborted) abort();
  const deadline = performance.now() + timeoutMs;
  const timer = setTimeout(() => {
    timedOut = true;
    abort();
  }, timeoutMs);
  function interrupted(): DomainError {
    return new DomainError(
      timedOut ? "capture_timeout" : "capture_aborted",
      timedOut
        ? "Capture exceeded its total deadline"
        : "Capture was cancelled",
    );
  }
  // Timers cannot preempt synchronous adapter work. Recheck monotonic elapsed time
  // at admission/result boundaries before starting another request or publishing bytes.
  function checkDeadline(): void {
    if (!controller.signal.aborted && performance.now() >= deadline) {
      timedOut = true;
      abort();
    }
    if (controller.signal.aborted) throw interrupted();
  }
  async function bounded<T>(work: () => Promise<T>): Promise<T> {
    checkDeadline();
    return new Promise<T>((resolve, reject) => {
      const cancelled = () => {
        cleanup();
        reject(interrupted());
      };
      const cleanup = () =>
        controller.signal.removeEventListener("abort", cancelled);
      controller.signal.addEventListener("abort", cancelled, { once: true });
      Promise.resolve()
        .then(() => {
          checkDeadline();
          return work();
        })
        .then(
          (value) => {
            cleanup();
            try { checkDeadline(); resolve(value); }
            catch (error) { reject(error); }
          },
          () => {
            cleanup();
            try {
              checkDeadline();
              reject(new DomainError("capture_unavailable",
                "Capture transport or resolution could not complete"));
            } catch (error) { reject(error); }
          },
        );
    });
  }
  try {
    for (;;) {
      invariant(
        !seen.has(current.href),
        "redirect_loop",
        "Source redirect loop",
      );
      seen.add(current.href);
      const addresses = [...(await bounded(() => resolver(current.hostname)))];
      invariant(
        addresses.length > 0 && addresses.every(isPublicIpv4),
        "unsafe_address",
        "Source DNS must resolve only to public IPv4 addresses",
      );
      const response = await bounded(() =>
        transport(new URL(current.href), {
          address: addresses[0]!,
          maximumBytes: policy.maximumBytes,
          userAgent: policy.userAgent,
          signal: controller.signal,
        }),
      );
      const bytes = new Uint8Array(response.bytes);
      invariant(
        bytes.length <= policy.maximumBytes,
        "capture_too_large",
        "Capture exceeds byte budget",
      );
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        invariant(
          redirects.length < policy.maximumRedirects &&
            typeof response.headers.location === "string",
          "redirect_denied",
          "Redirect budget or location missing",
        );
        current = allowedUrl(
          new URL(response.headers.location, current).href,
          policy,
        );
        redirects.push(current.href);
        continue;
      }
      invariant(
        response.status === 200,
        "source_unavailable",
        "Source did not return a complete successful response",
      );
      const contentType = (
        response.headers["content-type"] ?? "application/octet-stream"
      )
        .split(";")[0]!
        .trim()
        .toLowerCase();
      invariant(
        [
          "text/plain",
          "text/html",
          "application/json",
          "application/pdf",
          "application/warc",
          "application/zip",
          "application/x-zip-compressed",
        ].includes(contentType),
        "unsupported_media",
        "Source content type is unsupported",
      );
      const result: Capture = {
        tenantId: ctx.tenantId,
        projectId: ctx.projectId,
        sourcePolicyId: policy.id,
        requestedUrl: raw,
        finalUrl: current.href,
        retrievedAt: ctx.now,
        status: 200,
        contentType,
        sha256: hashBytes(bytes),
        bytes,
        redirects,
        etag: response.headers.etag ?? null,
        lastModified: response.headers["last-modified"] ?? null,
      };
      checkDeadline();
      return result;
    }
  } catch (error) {
    if (error instanceof DomainError) throw error;
    throw new DomainError(
      "capture_unavailable",
      "Capture transport or resolution could not complete",
    );
  } finally {
    clearTimeout(timer);
    parentSignal?.removeEventListener("abort", abort);
  }
}
