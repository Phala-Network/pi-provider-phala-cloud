/**
 * Private AI Gateway (ACI) provider extension
 *
 * Wires an attested private-ai-gateway into pi as an OpenAI-compatible provider
 * with per-response verifiability and attested TLS (SPKI) pinning. This is the
 * vendor-neutral core; branded distributions (pi-provider-redpill,
 * pi-provider-phala-cloud) call createProvider() with their own profile.
 *
 * Usage:
 *   pi install npm:@phala/pi-provider-aci
 *   # Set ACI_LLM_API_KEY (+ ACI_BASE_URL) then /model aci/<model-id>
 *
 * Source layout:
 *   src/constants.ts     — module-level consts + env-driven endpoints
 *   src/config.ts        — layered config (default/home/project/env/runtime)
 *   src/project-trust.ts — project-scope config trust gate
 *   src/aci-connection.ts— verified ACI connection (@phala/aci-verifier):
 *                          attestation bootstrap, pinned fail-closed fetch
 *   src/models.ts        — /v1/models discovery + thinkingFormat inference
 *   src/settings-ui.ts   — SettingsList helpers for the settings command
 */

import {
  type ExtensionAPI,
  type ExtensionCommandContext,
  type ExtensionFactory,
  readStoredCredential,
} from "@earendil-works/pi-coding-agent";
import { type SettingItem, SettingsList, truncateToWidth } from "@earendil-works/pi-tui";
import os from "node:os";

import {
  type AciCloudConfig,
  type AciCloudConfigPatch,
  loadHomeAciCloudConfig,
  loadAciCloudConfig,
  loadProjectAciCloudConfig,
  saveHomeAciCloudConfig,
  saveProjectAciCloudConfig,
} from "./src/config.ts";
import {
  API_KEY_ENV,
  FOOTER_STATUS_KEY,
  HEADER_RECEIPT_ID,
  LOG_PREFIX,
  PROVIDER_ID,
  PROVIDER_VERSION,
  applyProviderProfile,
} from "./src/constants.ts";
import { profile, type ProviderProfile } from "./src/profile.ts";
import {
  type AciServerModel,
  discoverAciModels,
  fallbackModels,
  mapAciServerModel,
} from "./src/models.ts";
import { isAciProjectConfigApproved } from "./src/project-trust.ts";
import {
  AciConnectionManager,
  type PinningState,
  fetchReceipt,
  fetchSession,
  summarizeReceipt,
  summarizeSession,
} from "./src/aci-connection.ts";
import {
  type AciConfigScope,
  THINKING_FORMAT_VALUES,
  buildSettingsTheme,
  formatScopeDescription,
  modelRegistrationSummary,
  settingsTitle,
  verifySummary,
} from "./src/settings-ui.ts";

/** TLS SPKI pin state for the configured base host, shown in the footer. */
type PinningStatus = PinningState;

interface AciRuntimeState {
  cwd: string;
  config: AciCloudConfig;
  projectTrusted: boolean;
  rawModels: AciServerModel[];
  /** Verified ACI connection + pinning gate (footer status source). */
  connection: AciConnectionManager;
  /** TLS SPKI pin status for the configured base host (attested, per session). */
  pinning?: PinningStatus;
  overrides?: AciCloudConfigPatch;
}

function resolveApiKey(): string {
  // Prefer the credential stored by /login (auth.json) to match pi's own
  // auth resolution; fall back to the env var.
  try {
    const stored = readStoredCredential(PROVIDER_ID);
    if (stored?.type === "oauth") {
      // An expired OAuth token must not be sent to the gateway as a live
      // bearer (it fails as a silent 401 that degrades to UNPINNED).
      if (typeof stored.access === "string" && stored.access) {
        const expires = stored.expires;
        if (typeof expires === "number" && Number.isFinite(expires) && expires <= Date.now()) {
          console.error(`${LOG_PREFIX} stored OAuth credential is expired; run /login ${PROVIDER_ID} again`);
        } else {
          return stored.access;
        }
      }
    } else if (stored?.type === "api_key" && typeof stored.key === "string" && stored.key) {
      return stored.key;
    }
  } catch {
    // auth.json unreadable; fall through to env.
  }
  return process.env[API_KEY_ENV]?.trim() || "";
}

/** Human-facing label of the active brand profile. */
function getLabel(): string {
  return profile().label;
}

function modelsFromState(state: AciRuntimeState): ReturnType<typeof fallbackModels> {
  const mapped = state.rawModels
    .map((m) => mapAciServerModel(m, state.config))
    .filter((m): m is ReturnType<typeof fallbackModels>[number] => m !== null);
  return mapped.length > 0 ? mapped : fallbackModels(state.config);
}

/**
 * Establish the verified ACI connection for the configured base origin.
 * Default posture is fail CLOSED: with `pinning.enabled` (the default) an
 * unattestable session blocks inference with a clear error rather than
 * silently downgrading to CA-TLS. Users can opt into the old fail-open
 * behavior via `verify.failOpenOnUnpinned` (runs unpinned with a footer
 * warning). The manager owns the details (quote-verified attestation,
 * pinned fail-closed fetch, bootstrap exemptions).
 */
async function installAttestedTlsPin(state: AciRuntimeState): Promise<void> {
  state.pinning = await state.connection.establish(state.config, resolveApiKey());
}

function registerAciProvider(pi: ExtensionAPI, state: AciRuntimeState): void {
  const config = state.config;
  const oauth = profile().oauth;
  pi.registerProvider(PROVIDER_ID, {
    baseUrl: config.baseUrl,
    apiKey: `$${API_KEY_ENV}`,
    api: "openai-completions",
    authHeader: true,
    models: modelsFromState(state),
    ...(oauth ? { oauth } : {}),
  });
}

function reloadEffectiveConfig(
  state: AciRuntimeState,
  cwd: string,
  projectTrusted: boolean,
): AciCloudConfig {
  const config = loadAciCloudConfig(
    { cwd, home: os.homedir(), includeProject: projectTrusted },
    state.overrides,
  );
  state.cwd = cwd;
  state.config = config;
  state.projectTrusted = projectTrusted;
  state.pinning = undefined;
  return config;
}

function applyEffectiveConfig(
  pi: ExtensionAPI,
  state: AciRuntimeState,
  cwd: string,
  projectTrusted: boolean,
): void {
  reloadEffectiveConfig(state, cwd, projectTrusted);
  registerAciProvider(pi, state);
}

function updateFooter(
  ctx: { ui: { setStatus: (key: string, text: string | undefined) => void } },
  state: AciRuntimeState,
): void {
  try {
    ctx.ui.setStatus(FOOTER_STATUS_KEY, pinSuffix(state));
  } catch {
    // The session may have been replaced/reloaded between an async update and
    // this render; the captured ctx is stale. Nothing to render to.
  }
}

/** Short footer suffix describing the TLS pin state. */
function pinSuffix(state: AciRuntimeState): string {
  if (!state.config.pinning.enabled) return "";
  switch (state.pinning?.status) {
    case "pinned":
      return " | tls-pinned";
    case "unpinned":
      return " | UNPINNED";
    case "blocked":
      return " | PIN REQUIRED";
    default:
      return " | pin: pending";
  }
}

async function openSettingsMenu(
  pi: ExtensionAPI,
  ctx: ExtensionCommandContext,
  state: AciRuntimeState,
): Promise<void> {
  const projectTrusted = isAciProjectConfigApproved(ctx);
  const homeDraft = loadHomeAciCloudConfig(os.homedir());
  const drafts: Record<AciConfigScope, AciCloudConfig> = {
    project: projectTrusted ? loadProjectAciCloudConfig(ctx.cwd) : homeDraft,
    home: homeDraft,
  };
  let scope: AciConfigScope = projectTrusted ? "project" : "home";
  let dirty = false;

  await ctx.ui.custom<void>((tui, theme, _keybindings, done) => {
    const settingsTheme = buildSettingsTheme(theme);
    let list: SettingsList;

    const refreshValues = () => {
      list.updateValue("scope", scope);
      list.updateValue("isTeeOnly", drafts[scope].models.isTeeOnly ? "true" : "false");
      list.updateValue("thinkingFormat", drafts[scope].models.thinkingFormat);
      list.updateValue("failOpenOnUnpinned", drafts[scope].verify.failOpenOnUnpinned ? "true" : "false");
      list.updateValue("pinning", drafts[scope].pinning.enabled ? "true" : "false");
    };

    const save = () => {
      if (scope === "project" && !projectTrusted) {
        ctx.ui.notify("Project config cannot be saved until the project is trusted.", "warning");
        return;
      }
      try {
        if (scope === "project") saveProjectAciCloudConfig(ctx.cwd, drafts[scope]);
        else saveHomeAciCloudConfig(os.homedir(), drafts[scope]);
        applyEffectiveConfig(pi, state, ctx.cwd, scope === "project" ? true : projectTrusted);
        dirty = true;
      } catch (error: unknown) {
        ctx.ui.notify((error as Error).message, "error");
      }
    };

    const onChange = (id: string, newValue: string) => {
      if (id === "scope") {
        scope = newValue as AciConfigScope;
        refreshValues();
        return;
      }
      if (id === "isTeeOnly") {
        drafts[scope].models.isTeeOnly = newValue === "true";
        list.updateValue(id, newValue);
        save();
        return;
      }
      if (id === "thinkingFormat") {
        drafts[scope].models.thinkingFormat = newValue as AciCloudConfig["models"]["thinkingFormat"];
        list.updateValue(id, newValue);
        save();
        return;
      }
      if (id === "failOpenOnUnpinned") {
        drafts[scope].verify.failOpenOnUnpinned = newValue === "true";
        list.updateValue(id, newValue);
        save();
        return;
      }
      if (id === "pinning") {
        drafts[scope].pinning.enabled = newValue === "true";
        list.updateValue(id, newValue);
        save();
        return;
      }
    };

    const scopeItem: SettingItem = {
      id: "scope",
      label: "Config scope",
      description: projectTrusted
        ? formatScopeDescription(scope, ctx.cwd)
        : "Project config disabled until the project is trusted; editing home config only",
      currentValue: scope,
      values: projectTrusted ? ["project", "home"] : ["home"],
    };

    const items: SettingItem[] = [
      scopeItem,
      {
        id: "isTeeOnly",
        label: "TEE-only models",
        description: "Only register models served confidentially (is_tee === true)",
        currentValue: drafts[scope].models.isTeeOnly ? "true" : "false",
        values: ["true", "false"],
      },
      {
        id: "thinkingFormat",
        label: "Thinking format",
        description: "How pi thinking levels map to provider parameters",
        currentValue: drafts[scope].models.thinkingFormat,
        values: [...THINKING_FORMAT_VALUES],
      },
      {
        id: "failOpenOnUnpinned",
        label: "Fail open when unpinned",
        description: "Off (default): block inference until an attested TLS pin is established. On: run unpinned with a footer warning when the attestation is unreachable.",
        currentValue: drafts[scope].verify.failOpenOnUnpinned ? "true" : "false",
        values: ["true", "false"],
      },
      {
        id: "pinning",
        label: "Attested TLS pinning",
        description: "Require the gateway TLS connection to present the attested SPKI (fails closed on mismatch)",
        currentValue: drafts[scope].pinning.enabled ? "true" : "false",
        values: ["true", "false"],
      },
    ];

    list = new SettingsList(items, items.length, settingsTheme, onChange, () => done(), {
      enableSearch: true,
    });

    return {
      items,
      onChange,
      render(width: number) {
        return [
          truncateToWidth(theme.fg("accent", theme.bold(settingsTitle())), width),
          "",
          truncateToWidth(modelRegistrationSummary(drafts[scope]), width),
          truncateToWidth(verifySummary(drafts[scope]), width),
          "",
          ...list.render(width),
        ];
      },
      handleInput(data: string) {
        list.handleInput?.(data);
        tui.requestRender();
      },
      invalidate() {
        list.invalidate();
      },
    };
  });

  if (dirty) await ctx.reload();
}

/** On-request audit: fetch and show the latest (or a given) receipt. Raw
 *  document display — no signature verification (prevention is pinning). */
async function runReceiptCommand(
  ctx: ExtensionCommandContext,
  state: AciRuntimeState,
  args: string,
): Promise<void> {
  const apiKey = resolveApiKey();
  if (!apiKey) {
    ctx.ui.notify(`${API_KEY_ENV} not set`, "error");
    return;
  }
  const receiptId = args.trim() || state.connection.receiptId;
  if (!receiptId) {
    ctx.ui.notify("No receipt id given and no x-receipt-id seen yet; send a message first or pass an id", "error");
    return;
  }
  const receipt = await fetchReceipt(apiKey, receiptId, { baseUrl: state.config.baseUrl });
  if (!receipt) {
    ctx.ui.notify(`Receipt ${receiptId} not found or fetch failed`, "error");
    return;
  }
  ctx.ui.notify(summarizeReceipt(receipt).join("\n"), "info");
}

/** On-request audit: fetch and show an attested session document (raw). */
async function runSessionCommand(
  ctx: ExtensionCommandContext,
  state: AciRuntimeState,
  args: string,
): Promise<void> {
  const apiKey = resolveApiKey();
  if (!apiKey) {
    ctx.ui.notify(`${API_KEY_ENV} not set`, "error");
    return;
  }
  const sessionId = args.trim();
  if (!sessionId) {
    ctx.ui.notify("Usage: /aci-session <session-id>", "error");
    return;
  }
  const session = await fetchSession(apiKey, sessionId, { baseUrl: state.config.baseUrl });
  if (!session) {
    ctx.ui.notify(`Session ${sessionId} not found or fetch failed`, "error");
    return;
  }
  ctx.ui.notify(summarizeSession(session).join("\n"), "info");
}

async function runAttestationCommand(
  ctx: ExtensionCommandContext,
  state: AciRuntimeState,
): Promise<void> {
  const apiKey = resolveApiKey();
  if (!apiKey) {
    ctx.ui.notify(`${API_KEY_ENV} not set`, "error");
    return;
  }
  try {
    const lines = await state.connection.describeAttestation(state.config, apiKey);
    if (lines.length === 0) {
      ctx.ui.notify(`${API_KEY_ENV} not set`, "error");
      return;
    }
    ctx.ui.notify(lines.join("\n"), "info");
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    ctx.ui.notify(`Attestation validation failed: ${detail}`, "error");
  }
}

/**
 * Create the provider extension for the given brand profile (and optional
 * runtime config patch). The neutral default profile ("aci") is used when no
 * profile is supplied; branded shells pass their own identity.
 */
export function createProvider(
  profileOverride?: Partial<ProviderProfile>,
  overrides?: AciCloudConfigPatch,
): ExtensionFactory {
  applyProviderProfile(profileOverride);
  return async (pi: ExtensionAPI) => {
    const cwd = process.cwd();
    const config = loadAciCloudConfig(
      { cwd, home: os.homedir(), includeProject: false },
      overrides,
    );
    const apiKey = resolveApiKey();
    const discovered = apiKey
      ? await discoverAciModels(apiKey, config)
      : { models: fallbackModels(config), raw: [] };

    const state: AciRuntimeState = {
      cwd,
      config,
      projectTrusted: false,
      rawModels: discovered.raw,
      connection: new AciConnectionManager(),
      overrides,
    };
    registerAciProvider(pi, state);

    pi.on("session_start", async (_event, ctx) => {
      const projectTrusted = isAciProjectConfigApproved(ctx);
      applyEffectiveConfig(pi, state, ctx.cwd, projectTrusted);
      // Resolve the attested SPKI from a fresh report and pin TLS for this
      // session (fail-closed; footer shows "PIN REQUIRED" if it cannot be
      // done, unless the user opted into failOpenOnUnpinned).
      await installAttestedTlsPin(state);
      updateFooter(ctx, state);
    });

    // Cheap header capture ONLY: remember the latest x-receipt-id so the
    // on-request /aci-receipt audit command knows what to fetch. No receipt is
    // downloaded or verified here (prevention is pinning; audit is opt-in).
    pi.on("after_provider_response", (event, ctx) => {
      if (ctx.model?.provider !== PROVIDER_ID) return;
      const lower = Object.fromEntries(
        Object.entries(event.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]),
      );
      state.connection.recordReceiptId(
        lower[HEADER_RECEIPT_ID] ?? lower["x-receipt-id"],
      );
    });

    const settingsCommand = `${PROVIDER_ID}-settings`;
    pi.registerCommand(settingsCommand, {
      description: `Configure ${getLabel()} (models, thinking, TLS pinning, verification)`,
      handler: async (_args, ctx) => {
        if (ctx.mode !== "tui") {
          ctx.ui.notify(`${settingsCommand} requires TUI mode`, "error");
          return;
        }
        await openSettingsMenu(pi, ctx, state);
      },
    });

    pi.registerCommand("attestation", {
      description: "Show the cached/current attestation report status",
      handler: async (_args, ctx) => {
        await runAttestationCommand(ctx, state);
      },
    });

    pi.registerCommand("aci-receipt", {
      description: "Show the latest (or a given) receipt as an audit trail (no verification)",
      handler: async (args, ctx) => {
        await runReceiptCommand(ctx, state, args ?? "");
      },
    });

    pi.registerCommand("aci-session", {
      description: "Show an attested session document (audit trail)",
      handler: async (args, ctx) => {
        await runSessionCommand(ctx, state, args ?? "");
      },
    });
  };
}

export default createProvider();

export { PROVIDER_ID, PROVIDER_VERSION };
export { profile as getProviderProfile } from "./src/profile.ts";
export { loadAciCloudConfig } from "./src/config.ts";
export { discoverAciModels, mapAciServerModel, inferThinkingFormat } from "./src/models.ts";
// Attestation/audit helpers for consumers. The prevention layer (verified
// ACI connection + pinned fetch) lives in src/aci-connection.ts; receipt
// verification is not part of this plugin.
export {
  fetchReceipt,
  fetchSession,
  summarizeReceipt,
  summarizeSession,
} from "./src/aci-connection.ts";
export {
  type AttestationReport,
  type ReportVerification,
  type WorkloadKeyset,
  verifyReportBinding,
} from "@phala/aci-verifier";
