// Cloud-console billing/usage client (optional, profile-gated).
//
// The vendor-neutral core only activates this module when the active brand
// profile declares a `billing` block (console URL + env var for the console
// API token). The console management API is a different service from the
// inference gateway: it authenticates with a workspace API token sent as
// `X-API-Key`; the inference (sk-*) key is NOT accepted here.
//
// Endpoints (all GET, X-API-Key auth):
//   /api/v1/redpill/usage/daily  — daily usage + cost aggregates
//   /api/v1/billing/balance      — workspace credit balance
//   /api/v1/workspaces           — workspace list (for the billing URL slug)
//
// Monetary amounts are decimal STRINGS (up to 18 fractional digits, USD).
// They are passed through untouched and only trimmed for display — never
// parsed into floats.
//
// Caching: a single in-flight/last snapshot is cached for 60s, matching the
// server-side Redis cache on the usage endpoint. The settings page fetches
// once per open; there is no polling.

import { profile } from "./profile.ts";

export interface DailyUsageSummary {
  totalRequests: number;
  totalTokens: number;
  /** USD decimal string, as returned by the API. */
  totalCost: string;
}

export interface BillingBalance {
  /** Spendable balance (USD decimal string). Excludes granted credits. */
  balance: string;
  /** Granted (promotional) credits; NOT usable for Private AI inference. */
  grantedBalance?: string;
  isPostPaid?: boolean;
  outstandingAmount?: string;
  tier?: string;
}

export interface BillingSnapshot {
  usage?: DailyUsageSummary;
  balance?: BillingBalance;
  /** Workspace slug for the console billing URL; undefined when unknown. */
  workspaceSlug?: string;
  /** Names of endpoints whose fetch/parse failed (soft-degraded display). */
  failed: string[];
}

export const BILLING_CACHE_TTL_MS = 60_000;
const FETCH_TIMEOUT_MS = 8000;

let snapshotCache: { key: string; at: number; value: BillingSnapshot } | undefined;

/** Drop the cached snapshot (token/config change, tests). */
export function clearBillingCache(): void {
  snapshotCache = undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function num(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function str(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

/** Date parts of `date` in the given IANA timezone. */
function datePartsInZone(
  date: Date,
  timeZone: string,
): { year: number; month: number; day: number } {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(date);
  const get = (type: string): number =>
    Number(parts.find((p) => p.type === type)?.value ?? "0");
  return { year: get("year"), month: get("month"), day: get("day") };
}

/** Offset (local − UTC) in ms of the wall clock in `timeZone` at `date`. */
function zoneOffsetMs(date: Date, timeZone: string): number {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).formatToParts(date);
  const get = (type: string): number =>
    Number(parts.find((p) => p.type === type)?.value ?? "0");
  const wallAsUtc = Date.UTC(
    get("year"),
    get("month") - 1,
    get("day"),
    get("hour"),
    get("minute"),
    get("second"),
  );
  return wallAsUtc - Math.floor(date.getTime() / 1000) * 1000;
}

/** The UTC instant of local midnight (00:00) on the given calendar date in
 *  `timeZone`. Fixed-point offset refinement handles the offset differing
 *  across a DST boundary; when midnight itself is skipped by a transition
 *  (a few zones, a couple of days a year) we nudge forward to the first
 *  instant that lands on the requested date. */
function localMidnightUtc(
  year: number,
  month: number,
  day: number,
  timeZone: string,
): Date {
  const targetWallMs = Date.UTC(year, month - 1, day);
  let guess = targetWallMs;
  for (let i = 0; i < 4; i++) {
    const next = targetWallMs - zoneOffsetMs(new Date(guess), timeZone);
    if (next === guess) break;
    guess = next;
  }
  const onTarget = (ms: number): boolean => {
    const p = datePartsInZone(new Date(ms), timeZone);
    return p.year === year && p.month === month && p.day === day;
  };
  while (!onTarget(guess)) {
    guess += 15 * 60 * 1000;
    if (guess > targetWallMs + 26 * 60 * 60 * 1000) break; // safety
  }
  return new Date(guess);
}

function toIsoSeconds(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

/**
 * "Today" as a [start, end) pair of UTC ISO 8601 timestamps: local midnight
 *  to local midnight in the given IANA timezone.
 *
 * The server parses date-only values ("2026-11-13") as UTC midnight while
 * grouping usage by the `timezone` parameter — mixing the two shifts the
 * window away from the user's local day. Full timestamps are passed through
 * verbatim, so we send the local-day bounds as UTC instants and keep
 * `timezone` for the usage[] grouping. */
export function todayWindow(
  timeZone: string,
  now: Date = new Date(),
): { start: string; end: string } {
  const { year, month, day } = datePartsInZone(now, timeZone);
  // Next calendar day via UTC calendar arithmetic (DST-immune).
  const next = new Date(Date.UTC(year, month - 1, day + 1));
  const start = localMidnightUtc(year, month, day, timeZone);
  const end = localMidnightUtc(
    next.getUTCFullYear(),
    next.getUTCMonth() + 1,
    next.getUTCDate(),
    timeZone,
  );
  return { start: toIsoSeconds(start), end: toIsoSeconds(end) };
}

/**
 * Format a USD decimal string for display without float conversion.
 * Keeps up to `maxDecimals` fractional digits, strips trailing zeros, pads
 * to at least 2. A nonzero value too small to show becomes "<$0.01".
 */
export function formatUsd(raw: string | undefined, maxDecimals = 6): string {
  if (raw === undefined) return "n/a";
  const negative = raw.startsWith("-");
  const body = negative ? raw.slice(1) : raw;
  const dot = body.indexOf(".");
  const intPart = dot === -1 ? body : body.slice(0, dot);
  const fracPart = dot === -1 ? "" : body.slice(dot + 1);
  if (!/^\d+$/.test(intPart) || (fracPart !== "" && !/^\d+$/.test(fracPart))) return raw;
  let frac = fracPart.length > maxDecimals ? fracPart.slice(0, maxDecimals) : fracPart;
  frac = frac.replace(/0+$/, "");
  const intDisplay = intPart.replace(/^0+(?=\d)/, "");
  const sign = negative ? "-" : "";
  if (frac === "") {
    // Distinguish exactly-zero from a nonzero amount truncated away.
    return /[1-9]/.test(fracPart) ? `${sign}<$0.01` : `${sign}$${intDisplay}.00`;
  }
  if (frac.length < 2) frac = frac.padEnd(2, "0");
  return `${sign}$${intDisplay}.${frac}`;
}

/** Grouped thousands for token/request counts. */
export function formatCount(n: number): string {
  return n.toLocaleString("en-US");
}

function parseUsage(raw: unknown): DailyUsageSummary | undefined {
  if (!isRecord(raw)) return undefined;
  const totalRequests = num(raw.total_requests);
  const totalTokens = num(raw.total_tokens);
  const totalCost = str(raw.total_cost);
  if (totalRequests === undefined || totalTokens === undefined || totalCost === undefined) {
    return undefined;
  }
  return { totalRequests, totalTokens, totalCost };
}

function parseBalance(raw: unknown): BillingBalance | undefined {
  if (!isRecord(raw)) return undefined;
  const balance = str(raw.balance);
  if (balance === undefined) return undefined;
  return {
    balance,
    grantedBalance: str(raw.granted_balance),
    isPostPaid: raw.is_post_paid === true,
    outstandingAmount: str(raw.outstanding_amount),
    tier: str(raw.tier),
  };
}

/** `/api/v1/workspaces` is a paginated envelope; with X-API-Key auth `data`
 *  holds at most the token's own workspace. `slug` is nullable — undefined
 *  sends the caller to the console's fallback billing route. */
function parseWorkspaceSlug(raw: unknown): string | undefined {
  if (!isRecord(raw) || !Array.isArray(raw.data)) return undefined;
  for (const workspace of raw.data) {
    if (isRecord(workspace)) {
      const slug = str(workspace.slug);
      if (slug) return slug;
    }
  }
  return undefined;
}

async function fetchJson(url: string, token: string): Promise<unknown> {
  const res = await fetch(url, {
    headers: { "X-API-Key": token, Accept: "application/json" },
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return (await res.json()) as unknown;
}

export interface FetchBillingOptions {
  /** Overrides the profile's console URL (mainly tests). */
  consoleUrl?: string;
  /** IANA timezone for the "today" boundary; defaults to the system zone. */
  timeZone?: string;
  /** Bypass the 60s cache. */
  noCache?: boolean;
}

/** Fetch usage, balance, and workspace slug concurrently; each endpoint
 *  degrades independently so one failure never blanks the whole panel. */
export async function fetchBillingSnapshot(
  token: string,
  options: FetchBillingOptions = {},
): Promise<BillingSnapshot> {
  const consoleUrl = (options.consoleUrl ?? profile().billing?.consoleUrl ?? "").replace(
    /\/+$/,
    "",
  );
  if (!consoleUrl) {
    throw new Error("billing console URL is not configured for this profile");
  }
  const cacheKey = `${consoleUrl}\n${token}`;
  if (!options.noCache && snapshotCache?.key === cacheKey) {
    if (Date.now() - snapshotCache.at < BILLING_CACHE_TTL_MS) return snapshotCache.value;
  }

  const timeZone = options.timeZone ?? Intl.DateTimeFormat().resolvedOptions().timeZone ?? "UTC";
  const { start, end } = todayWindow(timeZone);
  const usageUrl =
    `${consoleUrl}/api/v1/redpill/usage/daily?start_date=${encodeURIComponent(start)}` +
    `&end_date=${encodeURIComponent(end)}&timezone=${encodeURIComponent(timeZone)}`;
  const balanceUrl = `${consoleUrl}/api/v1/billing/balance`;
  const workspacesUrl = `${consoleUrl}/api/v1/workspaces`;

  const [usageRes, balanceRes, workspacesRes] = await Promise.allSettled([
    fetchJson(usageUrl, token),
    fetchJson(balanceUrl, token),
    fetchJson(workspacesUrl, token),
  ]);

  const failed: string[] = [];
  let usage: DailyUsageSummary | undefined;
  if (usageRes.status === "fulfilled") {
    usage = parseUsage(usageRes.value);
    if (!usage) failed.push("usage (unexpected shape)");
  } else {
    failed.push("usage");
  }
  let balance: BillingBalance | undefined;
  if (balanceRes.status === "fulfilled") {
    balance = parseBalance(balanceRes.value);
    if (!balance) failed.push("balance (unexpected shape)");
  } else {
    failed.push("balance");
  }
  // The slug only deep-links the billing menu item; a failure is silent
  // (the item falls back to the console's /cost route).
  const workspaceSlug =
    workspacesRes.status === "fulfilled" ? parseWorkspaceSlug(workspacesRes.value) : undefined;

  const snapshot: BillingSnapshot = { usage, balance, workspaceSlug, failed };
  snapshotCache = { key: cacheKey, at: Date.now(), value: snapshot };
  return snapshot;
}

/** Deep link to the console billing page; `/cost` is the stable fallback
 *  route when the workspace slug is unknown. */
export function billingDashboardUrl(consoleUrl: string, slug?: string): string {
  const base = consoleUrl.replace(/\/+$/, "");
  return slug ? `${base}/${encodeURIComponent(slug)}/billing` : `${base}/cost`;
}
