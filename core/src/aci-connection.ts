// Verified ACI connection on top of the maintained `@phala/aci-verifier`
// package (clients/verifier-ts). Replaces the former hand-rolled stack:
//   - tls-pinning.ts      → connection.fetch (pinned transport, fail-closed)
//   - aci-client.ts       → connectAci bootstrap (full §9.1 transcript,
//                           including the hardware quote via @phala/dcap-qvl)
//   - attestation-store.ts→ connection.identity (established keyset + expiry)
//
// Posture, unchanged from the old kernel: pinning.enabled (default) fails
// CLOSED — when no verified connection is established, inference traffic to
// the configured origin is blocked rather than downgraded to plain CA-TLS;
// /v1/aci/* bootstrap/audit endpoints stay reachable so a fresh attestation
// can always be fetched. verify.failOpenOnUnpinned opts into running unpinned
// with a footer warning.
//
// Serving enforcement is deliberately off (requireReceipt/requireVerified:
// false): this plugin ships prevention (pinning), not the receipt audit.
// receiptHistorySize: 0 follows from that — we never call verifyReceipt(),
// so recording receipts would only pay for a per-response clone + SHA-256.
// Quote verification against the Phala PCCS is ON — that is what makes the
// pinned SPKI hardware-bound; it adds a runtime network dependency that the
// old binding-only check did not have.

import {
  AciConnectionError,
  type AciConnection,
  type AciFetch,
  connectAci,
} from "@phala/aci-verifier/runtime";
import {
  type AttestationReport,
  type ReportTranscript,
  type WorkloadKeyset,
  verifyService,
} from "@phala/aci-verifier";

import type { AciCloudConfig } from "./config.ts";
import {
  DEFAULT_ATTESTATION_FETCH_TIMEOUT_MS,
  LOG_PREFIX,
  buildReceiptUrl,
  buildSessionUrl,
  getGatewayRoot,
} from "./constants.ts";

export type PinningStatusName = "pinned" | "unpinned" | "blocked" | "disabled";

/** TLS SPKI pin state for the configured base origin, shown in the footer. */
export interface PinningState {
  host: string;
  status: PinningStatusName;
}

/** ACI bootstrap/audit endpoints: always allowed over CA-TLS, even when
 *  inference to the same origin is fail-closed (they are how a pin gets
 *  established in the first place). */
const ACI_PATH_PREFIX = "/v1/aci/";

/** Lowercase hostname of a URL string, or undefined when unparseable. */
function hostOfUrl(url: string): string | undefined {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

function envProxy(): string | undefined {
  return (
    process.env.https_proxy ||
    process.env.HTTPS_PROXY ||
    process.env.http_proxy ||
    process.env.HTTP_PROXY ||
    undefined
  );
}

/** Build a fetch that adds the gateway bearer token (ACI endpoints are
 *  authorized; the verifier's bootstrap fetch is plain otherwise). Defeats
 *  prototype pollution on `init` by cloning with null-prototype maps. */
function authorizedFetch(apiKey: string): AciFetch {
  return (input, init) => {
    const original = new Request(input, init);
    const headers = new Headers(original.headers);
    if (!headers.has("authorization")) headers.set("authorization", `Bearer ${apiKey}`);
    if (!headers.has("accept")) headers.set("accept", "application/json");
    return fetch(new Request(original, { headers }));
  };
}

/**
 * Owns the provider's verified ACI connection and the narrow global-fetch
 * wrapper that routes the configured origin's inference traffic through it.
 * One manager per extension instance; establish() is re-entrant across
 * config/session changes (the previous connection is closed first).
 */
export class AciConnectionManager {
  private connection?: AciConnection;
  private origin?: string;
  private fetchWrapped = false;
  private baseFetch?: typeof globalThis.fetch;
  private lastReceiptId?: string;
  private lastAttestationError?: string;
  /** Monotonic token that invalidates superseded in-flight establish() attempts. */
  private generation = 0;
  /** In-flight establish(), so requests arriving during the fail-closed
   *  attestation window can wait (abortably) instead of failing. */
  private inflight?: Promise<PinningState>;

  /** TLS SPKI pin state for the configured base origin (footer source). */
  state: PinningState = { host: "", status: "disabled" };

  /** Id of the most recent response's receipt (x-receipt-id header). Kept for
   *  the on-request /aci-receipt audit command; no receipt is fetched or
   *  verified in the normal path. */
  recordReceiptId(receiptId: string | undefined): void {
    this.lastReceiptId = receiptId;
  }

  get receiptId(): string | undefined {
    return this.lastReceiptId;
  }

  /** Human-readable reason the last establish() failed, if any. */
  get lastError(): string | undefined {
    return this.lastAttestationError;
  }

  /** The verified connection, when pinning is active. */
  get verifiedConnection(): AciConnection | undefined {
    return this.connection;
  }

  /**
   * Establish (or re-establish) the verified connection for the effective
   * config. Never throws: failures land in `state` as unpinned/blocked per
   * the fail-open setting, and the fetch wrapper keeps the fail-closed gate
   * in the blocked case.
   *
   * Concurrency contract (session_start, settings reload and teardown can
   * overlap, and callers are encouraged to fire-and-forget):
   *  - the fail-closed gate (origin + wrapper) is installed SYNCHRONOUSLY,
   *    before any await, so the async attestation never opens a cleartext
   *    window and no code path uninstalls the gate mid-establish;
   *  - each attempt carries a generation token: a superseded attempt closes
   *    the connection it just built and leaves the newer state untouched.
   */
  async establish(config: AciCloudConfig, apiKey: string): Promise<PinningState> {
    const pending = this.doEstablish(config, apiKey);
    this.inflight = pending;
    try {
      return await pending;
    } finally {
      if (this.inflight === pending) this.inflight = undefined;
    }
  }

  private async doEstablish(config: AciCloudConfig, apiKey: string): Promise<PinningState> {
    const gen = ++this.generation;
    const host = hostOfUrl(config.baseUrl);
    const normalized = host ?? config.baseUrl;

    // The previous connection keeps serving until the new one is verified;
    // close it off the critical path (undici close() waits for in-flight
    // requests and must not delay the state transition).
    const previous = this.connection;
    const closePrevious = () => {
      if (previous) void previous.close().catch(() => {});
    };

    if (!config.pinning.enabled) {
      this.uninstallFetchWrapper();
      this.origin = undefined;
      this.connection = undefined;
      this.state = { host: normalized, status: "disabled" };
      closePrevious();
      return this.state;
    }
    if (!host || !apiKey) {
      this.uninstallFetchWrapper();
      this.origin = undefined;
      this.connection = undefined;
      this.state = { host: normalized, status: "unpinned" };
      closePrevious();
      return this.state;
    }

    // Fail-closed gate FIRST: from here until a verified connection is
    // attached, inference to this origin is blocked rather than downgraded
    // to plain CA-TLS — even though the attestation below is asynchronous.
    this.origin = new URL(config.baseUrl).origin;
    this.installFetchWrapper();
    if (!previous) {
      this.state = { host, status: "blocked" };
    }

    try {
      const connection = await connectAci({
        baseURL: getGatewayRoot(config.baseUrl),
        serving: { requireReceipt: false, requireVerified: false },
        receiptHistorySize: 0,
        timeoutMs: DEFAULT_ATTESTATION_FETCH_TIMEOUT_MS,
        bootstrapFetch: authorizedFetch(apiKey),
        proxy: envProxy(),
      });
      if (gen !== this.generation) {
        // Superseded by a newer establish()/reset(): close the connection
        // this attempt just built and leave the newer state untouched.
        void connection.close().catch(() => {});
        return this.state;
      }
      this.connection = connection;
      this.lastAttestationError = undefined;
      this.state = { host, status: "pinned" };
      closePrevious();
    } catch (error) {
      if (gen !== this.generation) return this.state;
      this.lastAttestationError = error instanceof Error ? error.message : String(error);
      console.error(`${LOG_PREFIX} ACI connection failed:`, error);
      // Fail closed: drop the old connection and keep the gate (installed
      // above) blocking, unless the user opted into fail-open, which tears
      // the gate down and runs unpinned with a console warning.
      this.connection = undefined;
      closePrevious();
      if (config.verify.failOpenOnUnpinned === true) {
        this.uninstallFetchWrapper();
        this.origin = undefined;
        this.state = { host, status: "unpinned" };
      } else {
        this.state = { host, status: "blocked" };
      }
    }
    return this.state;
  }

  /** Tear down the connection and the fetch wrapper (config change / unload). */
  async reset(): Promise<void> {
    // Invalidate any in-flight establish() so its late completion cannot
    // resurrect state or reinstall the wrapper.
    this.generation++;
    this.uninstallFetchWrapper();
    const connection = this.connection;
    this.connection = undefined;
    this.origin = undefined;
    if (connection) {
      try {
        await connection.close();
      } catch {
        // Closing is best-effort; a leaked transport is inert.
      }
    }
  }

  private installFetchWrapper(): void {
    if (this.fetchWrapped) return;
    this.fetchWrapped = true;
    this.baseFetch = globalThis.fetch;
    globalThis.fetch = this.wrappedFetch;
  }

  private uninstallFetchWrapper(): void {
    if (!this.fetchWrapped) return;
    if (globalThis.fetch === this.wrappedFetch) {
      globalThis.fetch = this.baseFetch ?? globalThis.fetch;
    }
    this.fetchWrapped = false;
    this.baseFetch = undefined;
  }

  /** Route the pinned origin's inference traffic through the verified
   *  connection; keep /v1/aci/* on CA-TLS bootstrap; delegate everything
   *  else untouched (pi's own dispatcher and other providers are unaffected). */
  private wrappedFetch = (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = urlOfInput(input);
    if (url && this.origin && url.origin === this.origin) {
      if (url.pathname.startsWith(ACI_PATH_PREFIX)) {
        return this.baseFetch!(input, init);
      }
      if (this.connection) {
        return this.fetchWithAbort(input, init);
      }
      if (this.state.status === "blocked") {
        if (this.inflight) {
          // Attestation is in flight: wait for it (abortably) rather than
          // failing a request that arrived inside the fail-closed window.
          return this.fetchAfterEstablish(this.inflight, input, init);
        }
        return Promise.reject(new Error(blockedMessage(this.state.host || url.hostname)));
      }
    }
    return this.baseFetch!(input, init);
  };

  /**
   * Fetch through the verified connection, but race the caller's abort
   * signal. The verifier's secureFetch can block inline on identity
   * re-verification (attestation + PCCS) WITHOUT honoring the caller's
   * signal — that left Esc/cancel unresponsive for the whole refresh. The
   * original signal still propagates through `init`/the Request to the
   * transport, so once response headers arrive the normal (fast) abort path
   * takes over; this race only covers the pre-response window.
   */
  private fetchWithAbort(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const connection = this.connection;
    if (!connection) {
      return Promise.reject(new Error(`${LOG_PREFIX} no verified ACI connection`));
    }
    const signal = signalOf(input, init);
    if (!signal) return connection.fetch(input, init);
    if (signal.aborted) {
      // Pre-aborted: reject without touching the connection.
      return Promise.reject(abortReason(signal));
    }
    return new Promise<Response>((resolve, reject) => {
      const onAbort = () => reject(abortReason(signal));
      signal.addEventListener("abort", onAbort, { once: true });
      if (signal.aborted) {
        // Aborted between the pre-check and listener attachment.
        signal.removeEventListener("abort", onAbort);
        reject(abortReason(signal));
        return;
      }
      connection.fetch(input, init).then(
        (response) => {
          signal.removeEventListener("abort", onAbort);
          if (signal.aborted) {
            // Abort won while the verifier was busy. Don't hand a live
            // response to a cancelled caller: drain it so no stream (or the
            // verifier's receipt digest clone) leaks behind the abort.
            void response.body?.cancel().catch(() => {});
            reject(abortReason(signal));
            return;
          }
          resolve(response);
        },
        (error) => {
          signal.removeEventListener("abort", onAbort);
          reject(error);
        },
      );
    });
  }

  /** Wait (abortably) for an in-flight establish, then re-dispatch. */
  private async fetchAfterEstablish(
    inflight: Promise<PinningState>,
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> {
    await raceWithSignal(inflight, signalOf(input, init));
    if (this.connection) return this.fetchWithAbort(input, init);
    if (this.state.status === "blocked") {
      throw new Error(blockedMessage(this.state.host));
    }
    // Establish ended unpinned/disabled (fail-open opt-in or pinning off):
    // the wrapper is already uninstalled, so pass through directly.
    return (this.baseFetch ?? globalThis.fetch)(input, init);
  }

  /**
   * Curated attestation display for the /attestation command. Uses the
   * verified connection's identity when available (no re-fetch); otherwise
   * runs a one-off verifyService transcript (quote + binding + compose).
   */
  async describeAttestation(config: AciCloudConfig, apiKey: string): Promise<string[]> {
    if (this.connection) {
      const { report, workloadKeysetDigest, keyset, verifiedAt, expiresAt } =
        this.connection.identity;
      return renderAttestationSummary(report, workloadKeysetDigest, keyset, verifiedAt, expiresAt);
    }
    if (!apiKey) return [];
    const transcript = await verifyService(getGatewayRoot(config.baseUrl), {
      fetchImpl: authorizedFetch(apiKey) as typeof fetch,
    });
    return renderTranscriptSummary(transcript);
  }
}

/** AbortSignal for a fetch call, whether carried by init or a Request input. */
function signalOf(input: RequestInfo | URL, init?: RequestInit): AbortSignal | undefined {
  return init?.signal ?? (input instanceof Request ? input.signal : undefined) ?? undefined;
}

function abortReason(signal: AbortSignal): unknown {
  return signal.reason ?? new DOMException("This operation was aborted", "AbortError");
}

/** Race a promise against an abort signal; every path drops the listener. */
function raceWithSignal<T>(promise: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(abortReason(signal));
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(abortReason(signal));
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) {
      // Aborted between the pre-check and listener attachment.
      signal.removeEventListener("abort", onAbort);
      reject(abortReason(signal));
      return;
    }
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

function blockedMessage(host: string): string {
  return (
    `${LOG_PREFIX} host ${host} requires an attested TLS pin but none is established; ` +
    `blocked to avoid a cleartext downgrade. Check the attestation/tail the logs, or ` +
    `disable pinning in settings to run unpinned.`
  );
}

function urlOfInput(input: RequestInfo | URL): URL | undefined {
  try {
    if (typeof input === "string") return new URL(input);
    if (input instanceof URL) return input;
    return input.url ? new URL(input.url) : undefined;
  } catch {
    return undefined;
  }
}

function renderAttestationSummary(
  report: AttestationReport,
  workloadKeysetDigest: string,
  keyset: WorkloadKeyset | undefined,
  verifiedAt: number,
  expiresAt: number,
): string[] {
  const e2eeKeys = Array.isArray(keyset?.e2ee_public_keys) ? keyset!.e2ee_public_keys : [];
  const receiptKeys = Array.isArray(keyset?.receipt_signing_keys)
    ? keyset!.receipt_signing_keys
    : [];
  const keySummary = (keys: Array<{ key_id?: unknown; algo?: unknown }>) =>
    keys.length === 0
      ? "none"
      : keys.map((k) => `${String(k.key_id)} (${String(k.algo)})`).join(", ");
  return [
    `Aci Cloud attestation`,
    `API version: ${String(report.api_version)}`,
    `Keyset digest: ${workloadKeysetDigest}`,
    `Report binding: verified`,
    `Keyset not_after: ${new Date(expiresAt).toISOString()}`,
    `Verified at: ${new Date(verifiedAt).toISOString()}`,
    `Encryption keys (${e2eeKeys.length}): ${keySummary(e2eeKeys)}`,
    `Receipt signing keys (${receiptKeys.length}): ${keySummary(receiptKeys)}`,
  ];
}

function renderTranscriptSummary(transcript: ReportTranscript): string[] {
  const lines = [`Verdict: ${transcript.verdict.verified ? "VERIFIED" : "FAILED"} — ${transcript.verdict.line}`];
  for (const line of transcript.lines) {
    const mark = line.status === "pass" ? "ok  " : line.status === "fail" ? "FAIL" : line.status;
    lines.push(`${mark} ${line.id} ${line.title}${line.detail ? ` — ${line.detail}` : ""}`);
  }
  return lines;
}

// ---------------------------------------------------------------------------
// On-request audit fetches (raw documents — no verification). These power the
// /aci-receipt and /aci-session commands. They are NOT wired into the chat
// path: prevention is pinning, and receipts/sessions are only shown when the
// user asks.
// ---------------------------------------------------------------------------

async function fetchJson(
  url: string,
  apiKey: string,
  timeoutMs: number,
  label: string,
): Promise<unknown | null> {
  if (!apiKey) return null;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs).unref();
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { Authorization: `Bearer ${apiKey}`, Accept: "application/json" },
    });
    if (!response.ok) {
      console.error(`${LOG_PREFIX} ${label} returned ${response.status} ${response.statusText}`);
      return null;
    }
    const text = await response.text();
    try {
      return JSON.parse(text);
    } catch (parseError) {
      console.error(`${LOG_PREFIX} ${label} JSON parse failed:`, parseError);
      return null;
    }
  } catch (error) {
    console.error(`${LOG_PREFIX} ${label} failed:`, error);
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

const AUDIT_FETCH_TIMEOUT_MS = DEFAULT_ATTESTATION_FETCH_TIMEOUT_MS;

/** Fetch a receipt document by id (raw; no signature verification). */
export async function fetchReceipt(
  apiKey: string,
  receiptId: string,
  options: { baseUrl?: string } = {},
): Promise<Record<string, unknown> | null> {
  return (await fetchJson(
    buildReceiptUrl(receiptId, options.baseUrl),
    apiKey,
    AUDIT_FETCH_TIMEOUT_MS,
    `receipt ${receiptId}`,
  )) as Record<string, unknown> | null;
}

/** Fetch an attested session document by id (raw). */
export async function fetchSession(
  apiKey: string,
  sessionId: string,
  options: { baseUrl?: string } = {},
): Promise<Record<string, unknown> | null> {
  return (await fetchJson(
    buildSessionUrl(sessionId, options.baseUrl),
    apiKey,
    AUDIT_FETCH_TIMEOUT_MS,
    `session ${sessionId}`,
  )) as Record<string, unknown> | null;
}

/** Compact summary of a raw receipt's key fields for the on-request audit
 *  display. Always present: receipt_id, key_id, api_version, served_at, model,
 *  and a one-line rendering of each interesting event_log entry. */
export function summarizeReceipt(receipt: Record<string, unknown>): string[] {
  const lines: string[] = [];
  const push = (label: string, value: unknown): void => {
    lines.push(`${label}: ${value === undefined || value === null ? "(none)" : String(value)}`);
  };
  push("Receipt", receipt.receipt_id);
  push("API version", receipt.api_version);
  push("Signing key", receipt.key_id);
  push("Model", receipt.model);
  push("Endpoint", receipt.endpoint);
  push(
    "Served at",
    receipt.served_at
      ? new Date(Number(receipt.served_at) * 1000).toISOString()
      : receipt.served_at,
  );
  push("Keyset digest", receipt.workload_keyset_digest);
  const events = Array.isArray(receipt.event_log) ? (receipt.event_log as unknown[]) : [];
  lines.push(`events: ${events.length}`);
  const interesting = [
    "upstream.verified",
    "request.received",
    "request.forwarded",
    "response.received",
    "response.returned",
  ];
  for (const ev of events) {
    const e = ev as Record<string, unknown>;
    const type = String(e.type ?? "?");
    if (!interesting.includes(type)) continue;
    const summary = summarizeEvent(e, type);
    if (summary) lines.push(`  ${type} ${summary}`);
  }
  return lines;
}

function summarizeEvent(e: Record<string, unknown>, type: string): string {
  if (type === "upstream.verified") {
    const bits: string[] = [];
    if (e.result !== undefined) bits.push(`result=${String(e.result)}`);
    if (e.required !== undefined) bits.push(`required=${String(e.required)}`);
    if (e.provider !== undefined) bits.push(`provider=${String(e.provider)}`);
    if (e.model_id !== undefined) bits.push(`model=${String(e.model_id)}`);
    if (e.session_id !== undefined) bits.push(`session=${String(e.session_id)}`);
    return bits.length ? bits.join(" ") : "";
  }
  if (e.body_hash !== undefined) return `body_hash=${String(e.body_hash)}`;
  return "";
}

/** Compact summary of a raw attested session's key fields. */
export function summarizeSession(session: Record<string, unknown>): string[] {
  return [
    `Session: ${String(session.session_id ?? session.id ?? "?")}`,
    `API version: ${String(session.api_version ?? "?")}`,
    `Upstream: ${String(session.upstream_name ?? "?")}`,
    `Endpoint: ${String(session.endpoint ?? "(none)")}`,
    `Verifier: ${String(session.verifier_id ?? "?")}`,
    `Established: ${session.established_at ? new Date(Number(session.established_at) * 1000).toISOString() : "?"}`,
    `Expires: ${session.expires_at ? new Date(Number(session.expires_at) * 1000).toISOString() : "?"}`,
  ];
}

export { AciConnectionError };
