// Settings UI helpers for the <provider-id>-settings command. Pure formatting
// and theme adapters; the interactive SettingsList wiring lives in index.ts.

import os from "node:os";
import { relative } from "node:path";
import type { Theme } from "@earendil-works/pi-coding-agent";
import type { SettingsListTheme } from "@earendil-works/pi-tui";

import {
  type AciCloudConfig,
  getGlobalAciCloudConfigPath,
  getProjectAciCloudConfigPath,
} from "./config.ts";
import { formatCount, formatUsd } from "./billing.ts";
import { PROVIDER_VERSION } from "./constants.ts";
import { profile } from "./profile.ts";

export type AciConfigScope = "project" | "home";

export const THINKING_FORMAT_VALUES = ["auto", "qwen", "openai", "off"] as const;
export const BOOLEAN_VALUES = ["true", "false"] as const;

export function buildSettingsTheme(theme: Theme): SettingsListTheme {
  return {
    label: (text: string, selected: boolean) => (selected ? theme.fg("accent", text) : text),
    value: (text: string, selected: boolean) =>
      selected ? theme.bold(theme.fg("accent", text)) : theme.fg("muted", text),
    description: (text: string) => theme.fg("dim", text),
    cursor: theme.fg("accent", "> "),
    hint: (text: string) => theme.fg("dim", text),
  };
}

export function homeRelative(filePath: string, home = os.homedir()): string {
  const normalizedHome = home.replace(/[\\/]+$/, "");
  if (filePath === normalizedHome) return "~";
  const slashPrefix = `${normalizedHome}/`;
  if (filePath.startsWith(slashPrefix)) return `~/${filePath.slice(slashPrefix.length)}`;
  const backslashPrefix = `${normalizedHome}\\`;
  if (filePath.startsWith(backslashPrefix)) return `~\\${filePath.slice(backslashPrefix.length)}`;
  return filePath;
}

export function formatScopeDescription(
  scope: AciConfigScope,
  cwd: string,
  home = os.homedir(),
): string {
  const filePath =
    scope === "project" ? getProjectAciCloudConfigPath(cwd) : getGlobalAciCloudConfigPath(home);
  const displayPath = scope === "home" ? homeRelative(filePath, home) : relative(cwd, filePath);
  return `Writes to the ${scope} config file: ${displayPath}`;
}

export function formatBoolean(value: boolean): string {
  return value ? "true" : "false";
}

export function settingsTitle(): string {
  return `${profile().label} settings (provider v${PROVIDER_VERSION})`;
}

export function modelRegistrationSummary(config: AciCloudConfig): string {
  const tee = config.models.isTeeOnly ? "TEE-only" : "all models";
  const allow = config.models.allowlist?.length
    ? `, allowlist: ${config.models.allowlist.length}`
    : "";
  return `Models: ${tee}${allow} | thinking: ${config.models.thinkingFormat}`;
}

export function verifySummary(config: AciCloudConfig): string {
  return `Pin: ${config.pinning.enabled ? "required" : "disabled"}, ` +
    `fail-open-unpinned ${formatBoolean(config.verify.failOpenOnUnpinned)}`;
}

/** Live auth + catalog snapshot shown in the settings summary line. */
export interface CatalogStatus {
  /** A usable API key resolves right now. */
  authenticated: boolean;
  /** Human-readable credential source ("none" when unauthenticated). */
  authSource: string;
  /** Registered chat models. */
  chatCount: number;
  /** Registered classifier (decision) models. */
  classifierCount: number;
  /** True when the profile fallback catalog is shown instead of the live one. */
  fallback: boolean;
}

export function catalogSummary(status: CatalogStatus): string {
  const plural = (n: number) => `model${n === 1 ? "" : "s"}`;
  const catalog = status.fallback
    ? `fallback (${status.chatCount} ${plural(status.chatCount)})`
    : `${status.chatCount} chat ${plural(status.chatCount)}`;
  const decisions =
    status.classifierCount > 0
      ? `${status.classifierCount} decision ${plural(status.classifierCount)}`
      : "no decision models";
  const auth = status.authenticated ? `auth: ${status.authSource}` : `auth: none (${status.authSource})`;
  return `Catalog: ${catalog}, ${decisions} | ${auth}`;
}

/** Live billing/usage snapshot shown in the settings summary. */
export interface BillingLineStatus {
  /** A console API token resolved from config/env. */
  tokenPresent: boolean;
  /** Env var name for the token (used in the not-configured hint). */
  apiKeyEnv: string;
  /** Fetch in flight. */
  loading: boolean;
  usage?: { totalRequests: number; totalTokens: number; totalCost: string };
  balance?: { balance: string; grantedBalance?: string };
  /** Endpoint names that failed (partial data may still be shown). */
  failed: string[];
}

function isZeroDecimal(raw: string | undefined): boolean {
  return raw === undefined || /^-?0+(\.0+)?$/.test(raw);
}

export function billingSummary(status: BillingLineStatus): string {
  if (!status.tokenPresent) {
    return `Billing: set ${status.apiKeyEnv} (console Settings → API Keys) to see usage & balance`;
  }
  if (status.loading) return "Billing: loading usage & balance…";
  const parts: string[] = [];
  if (status.usage) {
    parts.push(
      `today ${formatCount(status.usage.totalRequests)} req, ` +
        `${formatCount(status.usage.totalTokens)} tok, ${formatUsd(status.usage.totalCost)}`,
    );
  }
  if (status.balance) {
    // Granted credits cannot pay for inference; show them as an aside, not
    // summed into the spendable balance.
    const granted = isZeroDecimal(status.balance.grantedBalance)
      ? ""
      : ` (+${formatUsd(status.balance.grantedBalance)} granted)`;
    parts.push(`balance ${formatUsd(status.balance.balance)}${granted}`);
  }
  if (parts.length === 0) {
    return `Billing: unavailable (${status.failed.join(", ") || "request failed"})`;
  }
  const degraded = status.failed.length > 0 ? ` | unavailable: ${status.failed.join(", ")}` : "";
  return `Billing: ${parts.join(" | ")}${degraded}`;
}
