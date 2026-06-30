/**
 * Phala Cloud Provider Extension
 *
 * Wires Phala Cloud Confidential AI into pi as an OpenAI-compatible provider
 * with per-response verifiability and optional E2EE.
 *
 * Usage:
 *   pi -e ~/workshop/pi-provider-phala-cloud
 *   # Set PHALA_LLM_API_KEY=..., then /model phala-cloud/<model-id>
 *
 * Source layout:
 *   src/constants.ts     — module-level consts + env-driven endpoints
 *   src/config.ts        — layered config (default/home/project/env/runtime)
 *   src/project-trust.ts — project-scope config trust gate
 *   src/canonical.ts     — JCS (RFC 8785 subset) for receipt/attestation digests
 *   src/crypto.ts        — secp256k1 ECDH + HKDF + AES-GCM + signature recovery
 *   src/e2ee.ts          — E2EE field selection + AAD construction (request side)
 *   src/headers.ts       — request header builder + E2EE header injection
 *   src/models.ts        — /v1/models discovery + thinkingFormat inference
 *   src/verify.ts        — receipt/attestation/session fetch + full verification
 *   src/receipt-store.ts — last-response receipt cache + footer status source
 *   src/settings-ui.ts   — SettingsList helpers for /phala-cloud-settings
 */

import {
  type ExtensionAPI,
  type ExtensionCommandContext,
  type ExtensionFactory,
} from "@earendil-works/pi-coding-agent";
import {
  type Api,
  type AssistantMessageEventStream,
  type Context,
  type Model,
  type SimpleStreamOptions,
  streamSimpleOpenAICompletions,
} from "@earendil-works/pi-ai";
import { type SettingItem, SettingsList, truncateToWidth } from "@earendil-works/pi-tui";
import os from "node:os";

import {
  type PhalaCloudConfig,
  type PhalaCloudConfigPatch,
  loadHomePhalaCloudConfig,
  loadPhalaCloudConfig,
  loadProjectPhalaCloudConfig,
  saveHomePhalaCloudConfig,
  saveProjectPhalaCloudConfig,
} from "./src/config.ts";
import {
  API_KEY_ENV,
  FOOTER_STATUS_KEY,
  PROVIDER_ID,
  PROVIDER_VERSION,
} from "./src/constants.ts";
import { buildPhalaHeaders, generateE2eeMaterial } from "./src/headers.ts";
import {
  type PhalaServerModel,
  FALLBACK_MODELS,
  discoverPhalaModels,
  mapPhalaServerModel,
} from "./src/models.ts";
import { isPhalaProjectConfigApproved } from "./src/project-trust.ts";
import { footerText, PhalaReceiptStore } from "./src/receipt-store.ts";
import {
  type PhalaConfigScope,
  THINKING_FORMAT_VALUES,
  buildSettingsTheme,
  formatScopeDescription,
  modelRegistrationSummary,
  settingsTitle,
  verifySummary,
} from "./src/settings-ui.ts";
import { encryptRequestPayload } from "./src/e2ee.ts";

interface PhalaRuntimeState {
  cwd: string;
  config: PhalaCloudConfig;
  projectTrusted: boolean;
  rawModels: PhalaServerModel[];
  store: PhalaReceiptStore;
  /** Gateway E2EE public key resolved from a verified attestation, cached. */
  e2eeModelPublicKeyHex?: string;
  overrides?: PhalaCloudConfigPatch;
}

function resolveApiKey(): string {
  return process.env[API_KEY_ENV]?.trim() || "";
}

function modelsFromState(state: PhalaRuntimeState): typeof FALLBACK_MODELS {
  const mapped = state.rawModels
    .map((m) => mapPhalaServerModel(m, state.config))
    .filter((m): m is (typeof FALLBACK_MODELS)[number] => m !== null);
  return mapped.length > 0 ? mapped : FALLBACK_MODELS;
}

/** Resolve the gateway E2EE public key from a fresh attestation, cached. */
async function resolveE2eeKey(
  state: PhalaRuntimeState,
  apiKey: string,
): Promise<string | undefined> {
  if (state.e2eeModelPublicKeyHex) return state.e2eeModelPublicKeyHex;
  const attested = await state.store.getAttestation(apiKey, state.config);
  if (!attested) return undefined;
  const keyset = attested.report.attestation?.workload_keyset;
  const e2eeKeys = Array.isArray(keyset?.e2ee_public_keys)
    ? (keyset!.e2ee_public_keys as Array<{ key_id?: unknown; public_key?: unknown }>)
    : [];
  const key = e2eeKeys.find(
    (k) => k.key_id === "dstack-kms-e2ee-v1" && typeof k.public_key === "string",
  );
  if (key && typeof key.public_key === "string") {
    state.e2eeModelPublicKeyHex = key.public_key;
    return key.public_key;
  }
  return undefined;
}

function registerPhalaProvider(pi: ExtensionAPI, state: PhalaRuntimeState): void {
  const config = state.config;
  const providerConfig: Parameters<ExtensionAPI["registerProvider"]>[1] = {
    baseUrl: config.baseUrl,
    apiKey: `$${API_KEY_ENV}`,
    api: "openai-completions",
    authHeader: true,
    models: modelsFromState(state),
  };

  if (config.e2ee.enabled) {
    // E2EE path: inject headers per request and encrypt payload fields in the
    // onPayload hook. The built-in openai-completions handler still builds the
    // OpenAI request and parses the SSE stream; we only transform the body and
    // add headers.
    providerConfig.streamSimple = (
      model: Model<Api>,
      context: Context,
      options?: SimpleStreamOptions,
    ): AssistantMessageEventStream => {
      const apiKey = resolveApiKey();
      const baseHeaders: Record<string, string> = { ...(options?.headers) };
      const originalOnPayload = options?.onPayload;

      const patchedOptions: SimpleStreamOptions = {
        ...options,
        headers: baseHeaders,
        onPayload: async (payload: unknown, modelData: unknown) => {
          let nextPayload = payload;
          if (nextPayload && typeof nextPayload === "object") {
            const obj = nextPayload as Record<string, unknown>;
            const modelId = typeof obj.model === "string" ? obj.model : model?.id ?? "";
            try {
              const modelPub = await resolveE2eeKey(state, apiKey);
              if (modelPub) {
                const material = generateE2eeMaterial(modelPub);
                const e2eeHeaders = buildPhalaHeaders(config, material);
                Object.assign(baseHeaders, e2eeHeaders);
                encryptRequestPayload(obj, {
                  modelPublicKeyHex: material.modelPublicKeyHex,
                  nonce: material.nonce,
                  timestamp: material.timestamp,
                  algo: "secp256k1-aes-256-gcm-hkdf-sha256",
                  model: modelId,
                });
                state.store.setLastRequestBody(new TextEncoder().encode(JSON.stringify(obj)));
              }
            } catch (error) {
              console.error("[phala-cloud] E2EE encrypt failed:", error);
            }
          }
          if (originalOnPayload) {
            const res = await originalOnPayload(nextPayload, modelData as Model<Api>);
            if (res !== undefined) nextPayload = res;
          }
          return nextPayload;
        },
      };

      return streamSimpleOpenAICompletions(
        model as Model<"openai-completions">,
        context,
        patchedOptions,
      );
    };
  } else {
    providerConfig.headers = buildPhalaHeaders(config);
  }

  pi.registerProvider(PROVIDER_ID, providerConfig);
}

// streamSimpleOpenAICompletions is imported statically from @earendil-works/pi-ai.

function reloadEffectiveConfig(
  state: PhalaRuntimeState,
  cwd: string,
  projectTrusted: boolean,
): PhalaCloudConfig {
  const config = loadPhalaCloudConfig(
    { cwd, home: os.homedir(), includeProject: projectTrusted },
    state.overrides,
  );
  state.cwd = cwd;
  state.config = config;
  state.projectTrusted = projectTrusted;
  state.e2eeModelPublicKeyHex = undefined;
  return config;
}

function applyEffectiveConfig(
  pi: ExtensionAPI,
  state: PhalaRuntimeState,
  cwd: string,
  projectTrusted: boolean,
): void {
  reloadEffectiveConfig(state, cwd, projectTrusted);
  registerPhalaProvider(pi, state);
}

function updateFooter(
  ctx: { ui: { setStatus: (key: string, text: string | undefined) => void } },
  state: PhalaRuntimeState,
): void {
  ctx.ui.setStatus(FOOTER_STATUS_KEY, footerText(state.store));
}

async function openSettingsMenu(
  pi: ExtensionAPI,
  ctx: ExtensionCommandContext,
  state: PhalaRuntimeState,
): Promise<void> {
  const projectTrusted = await isPhalaProjectConfigApproved(ctx, ctx.cwd);
  const homeDraft = loadHomePhalaCloudConfig(os.homedir());
  const drafts: Record<PhalaConfigScope, PhalaCloudConfig> = {
    project: projectTrusted ? loadProjectPhalaCloudConfig(ctx.cwd) : homeDraft,
    home: homeDraft,
  };
  let scope: PhalaConfigScope = projectTrusted ? "project" : "home";
  let dirty = false;

  await ctx.ui.custom<void>((tui, theme, _keybindings, done) => {
    const settingsTheme = buildSettingsTheme(theme);
    let list: SettingsList;

    const refreshValues = () => {
      list.updateValue("scope", scope);
      list.updateValue("isTeeOnly", drafts[scope].models.isTeeOnly ? "true" : "false");
      list.updateValue("thinkingFormat", drafts[scope].models.thinkingFormat);
      list.updateValue("autoFetchReceipt", drafts[scope].verify.autoFetchReceipt ? "true" : "false");
      list.updateValue("e2ee", drafts[scope].e2ee.enabled ? "true" : "false");
    };

    const save = () => {
      if (scope === "project" && !projectTrusted) {
        ctx.ui.notify("Project config cannot be saved until the project is trusted.", "warning");
        return;
      }
      try {
        if (scope === "project") saveProjectPhalaCloudConfig(ctx.cwd, drafts[scope]);
        else saveHomePhalaCloudConfig(os.homedir(), drafts[scope]);
        applyEffectiveConfig(pi, state, ctx.cwd, scope === "project" ? true : projectTrusted);
        dirty = true;
      } catch (error: unknown) {
        ctx.ui.notify((error as Error).message, "error");
      }
    };

    const onChange = (id: string, newValue: string) => {
      if (id === "scope") {
        scope = newValue as PhalaConfigScope;
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
        drafts[scope].models.thinkingFormat = newValue as PhalaCloudConfig["models"]["thinkingFormat"];
        list.updateValue(id, newValue);
        save();
        return;
      }
      if (id === "autoFetchReceipt") {
        drafts[scope].verify.autoFetchReceipt = newValue === "true";
        list.updateValue(id, newValue);
        save();
        return;
      }
      if (id === "e2ee") {
        drafts[scope].e2ee.enabled = newValue === "true";
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
        id: "autoFetchReceipt",
        label: "Auto-verify receipts",
        description: "Fetch the receipt + attestation after each response",
        currentValue: drafts[scope].verify.autoFetchReceipt ? "true" : "false",
        values: ["true", "false"],
      },
      {
        id: "e2ee",
        label: "End-to-end encryption",
        description: "Encrypt request fields to the attested gateway E2EE key (E2EE v2)",
        currentValue: drafts[scope].e2ee.enabled ? "true" : "false",
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

async function runAttestationCommand(
  ctx: ExtensionCommandContext,
  state: PhalaRuntimeState,
): Promise<void> {
  const apiKey = resolveApiKey();
  if (!apiKey) {
    ctx.ui.notify("PHALA_LLM_API_KEY not set", "error");
    return;
  }
  const attested = await state.store.getAttestation(apiKey, state.config);
  if (!attested) {
    const error = state.store.lastAttestationError ?? "unknown error";
    ctx.ui.notify(`Attestation validation failed: ${error}`, "error");
    return;
  }
  const report = attested.report;
  const binding = attested.binding;
  const keyset = report.attestation?.workload_keyset;
  const e2eeKeys = Array.isArray(keyset?.e2ee_public_keys)
    ? (keyset!.e2ee_public_keys as Array<{ key_id?: unknown; algo?: unknown; public_key?: unknown }>)
    : [];
  const receiptKeys = Array.isArray(keyset?.receipt_signing_keys)
    ? (keyset!.receipt_signing_keys as Array<{ key_id?: unknown; algo?: unknown; public_key?: unknown }>)
    : [];
  const freshness = report.attestation?.freshness ?? {};
  const keySummary = (keys: Array<{ key_id?: unknown; algo?: unknown }>) =>
    keys.length === 0
      ? "none"
      : keys.map((k) => `${String(k.key_id)} (${String(k.algo)})`).join(", ");
  const lines = [
    `Phala Cloud attestation`,
    `API version: ${String(report.api_version)}`,
    `Workload ID: ${binding.workloadId}`,
    `Keyset digest: ${binding.workloadKeysetDigest}`,
    `Report data: verified`,
    `Keyset endorsement: verified`,
    `Freshness: fetched_at=${String(freshness.fetched_at)} stale_after=${String(freshness.stale_after)}`,
    `E2EE keys (${e2eeKeys.length}): ${keySummary(e2eeKeys)}`,
    `Receipt signing keys (${receiptKeys.length}): ${keySummary(receiptKeys)}`,
    `Last receipt: ${state.store.snapshot().receiptId ?? "none"}`,
  ];
  ctx.ui.notify(lines.join("\n"), "info");
}

export function PhalaCloud(overrides?: PhalaCloudConfigPatch): ExtensionFactory {
  return async (pi: ExtensionAPI) => {
    const cwd = process.cwd();
    const config = loadPhalaCloudConfig(
      { cwd, home: os.homedir(), includeProject: false },
      overrides,
    );
    const apiKey = resolveApiKey();
    const discovered = apiKey
      ? await discoverPhalaModels(apiKey, config)
      : { models: FALLBACK_MODELS, raw: [] };

    const state: PhalaRuntimeState = {
      cwd,
      config,
      projectTrusted: false,
      rawModels: discovered.raw,
      store: new PhalaReceiptStore(),
      overrides,
    };
    registerPhalaProvider(pi, state);

    pi.on("session_start", async (_event, ctx) => {
      const projectTrusted = await isPhalaProjectConfigApproved(ctx, ctx.cwd);
      applyEffectiveConfig(pi, state, ctx.cwd, projectTrusted);
    });

    pi.on("after_provider_response", (event, ctx) => {
      if (ctx.model?.provider !== PROVIDER_ID) return;
      state.store.recordResponseHeaders(event.headers);
      updateFooter(ctx, state);
    });

    pi.on("message_end", (event, ctx) => {
      if (ctx.model?.provider !== PROVIDER_ID) return;
      if (event.message.role !== "assistant") return;
      const key = resolveApiKey();
      if (!key || !state.config.verify.autoFetchReceipt) return;
      void (async () => {
        try {
          await state.store.classifyLastResponse(key, state.config);
        } catch (error) {
          console.error("[phala-cloud] receipt classification failed:", error);
        }
        updateFooter(ctx, state);
      })();
    });

    pi.registerCommand("phala-cloud-settings", {
      description: "Configure Phala Cloud (models, thinking, verification, E2EE)",
      handler: async (_args, ctx) => {
        if (ctx.mode !== "tui") {
          ctx.ui.notify("/phala-cloud-settings requires TUI mode", "error");
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
  };
}

export default PhalaCloud();

export { PROVIDER_ID, PROVIDER_VERSION };
export { loadPhalaCloudConfig } from "./src/config.ts";
export { discoverPhalaModels, mapPhalaServerModel, inferThinkingFormat } from "./src/models.ts";
export {
  canonicalBytesForSigning,
  classifyReceipt,
  validateAciReportBinding,
  verifyReceipt,
} from "./src/verify.ts";
export { encryptForPublicKey, verifyReceiptSignature } from "./src/crypto.ts";
export { encryptRequestPayload } from "./src/e2ee.ts";
