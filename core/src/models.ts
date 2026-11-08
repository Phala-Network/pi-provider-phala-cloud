// Model discovery and mapping. Pulls /v1/models from the Aci gateway and
// converts each entry into a pi ProviderModelConfig. Responsible for:
//   - is_tee filtering (config.models.isTeeOnly)
//   - allowlist filtering (config.models.allowlist)
//   - non-chat routing by output_modalities: "decisions" entries become pi
//     classifier models (System One API, POST /v1/systemone); embeddings,
//     transcription and image-generation entries are excluded (pi has no
//     matching API surface for them behind this gateway)
//   - thinkingFormat inference (config.models.thinkingFormat, "auto" by id)
//   - pricing conversion (per-token -> per-million-token)
//   - compat settings so the built-in openai-completions handler sends the
//     right max-tokens field and thinking parameter for each model family
//   - per-model compat overrides for known upstream quirks
//     (BUILTIN_MODEL_COMPAT_OVERRIDES + config.models.overrides)
//
// Thinking works without a custom streamSimple because pi's built-in
// openai-completions handler:
//   - sends `enable_thinking: boolean` when compat.thinkingFormat === "qwen"
//     and model.reasoning === true
//   - sends `reasoning_effort` when thinkingFormat === "openai"
//   - parses streaming `reasoning_content` / `reasoning` / `reasoning_text`
//     deltas into pi thinking blocks regardless of the request format

import type { Api, Model, ThinkingLevelMap } from "@earendil-works/pi-ai";
import type { ProviderModelConfig } from "@earendil-works/pi-coding-agent";

import { type AciCloudConfig } from "./config.ts";
import { DEFAULT_DISCOVERY_TIMEOUT_MS, LOG_PREFIX, buildModelsUrl } from "./constants.ts";
import { profile } from "./profile.ts";

/**
 * Per-model compatibility overrides applied on top of the shared catalog
 * mapping. Upstreams differ in which OpenAI-compatible surface they accept;
 * the catalog contract does not declare these, so known quirks are recorded
 * here and users can patch them via `models.overrides` in the provider
 * config. Every field falls back to the shared default when unset.
 */
export interface ModelCompatOverride {
  /** Rewrite the system prompt to a `system` (instead of `developer`) message. */
  supportsDeveloperRole?: boolean;
  /** Map pi thinking levels to this model's reasoning-effort vocabulary. */
  thinkingLevelMap?: ThinkingLevelMap;
  /** Cap the advertised max output tokens (e.g. catalog metadata exceeds the upstream limit). */
  maxTokens?: number;
}

/**
 * Known upstream quirks, keyed by catalog model id. These are properties of
 * the model served behind the gateway, not of a brand, so the vendor-neutral
 * core carries them; deployments can still override per model via config.
 *
 * Originally recorded in private-ai-gateway commit b7257816 (2026-09);
 * re-verified live against inference.phala.com on backport (2026-11):
 * the qwen upstreams now accept every reasoning_effort value and
 * deepseek-v3.2 accepts none/minimal/xhigh/max, so their thinking-level
 * remaps were dropped; only the developer-role rejections and the gpt-oss
 * Harmony vocabulary remain.
 */
export const BUILTIN_MODEL_COMPAT_OVERRIDES: Record<string, ModelCompatOverride> = {
  // These upstreams reject the `developer` message role with a 400
  // ("Unexpected message role" / "request rejected"); they accept `system`.
  "qwen/qwen3.8-27b": { supportsDeveloperRole: false },
  "qwen/qwen3.5-27b": { supportsDeveloperRole: false },
  "qwen/qwen3.5-397b-a17b": { supportsDeveloperRole: false },
  "qwen/qwen3.6-27b": { supportsDeveloperRole: false },
  "phala/qwen3.8-27b-uncensored": { supportsDeveloperRole: false },
  // gpt-oss-120b (Harmony) rejects reasoning_effort 'none'/'minimal' and
  // 'xhigh'/'max'; it accepts only low/medium/high. pi clamps "off" to
  // "minimal", so minimal maps to low; xhigh/max map to high.
  "openai/gpt-oss-120b": {
    thinkingLevelMap: { off: null, minimal: "low", xhigh: "high", max: "high" },
  },
};

/** Effective override for a catalog model: config patch over the builtin table. */
export function resolveModelCompatOverride(
  config: Pick<AciCloudConfig, "models">,
  modelId: string,
): ModelCompatOverride | undefined {
  const builtin = BUILTIN_MODEL_COMPAT_OVERRIDES[modelId];
  const patch = config.models.overrides?.[modelId];
  if (!builtin) return patch;
  if (!patch) return builtin;
  return {
    ...builtin,
    ...patch,
    // Merge the thinking-level map key-by-key so a config patch can adjust a
    // single level without discarding the builtin mappings.
    ...(builtin.thinkingLevelMap || patch.thinkingLevelMap
      ? { thinkingLevelMap: { ...builtin.thinkingLevelMap, ...patch.thinkingLevelMap } }
      : {}),
  };
}

export interface AciServerModel {
  id?: unknown;
  name?: unknown;
  is_tee?: unknown;
  context_length?: unknown;
  max_output_length?: unknown;
  pricing?: unknown;
  providers?: unknown;
  input_modalities?: unknown;
  output_modalities?: unknown;
  supported_features?: unknown;
  supported_parameters?: unknown;
  description?: unknown;
}

interface InferredThinking {
  reasoning: boolean;
  format: "qwen" | "openai" | "off";
  maxTokensField: "max_tokens" | "max_completion_tokens";
  supportsReasoningEffort: boolean;
}

// Pure inference. Exposed for tests so the model-family mapping can be
// verified without hitting the network.
export function inferThinkingFormat(modelId: string): InferredThinking {
  const id = modelId.toLowerCase();

  if (id.includes("qwen")) {
    // Qwen3 accepts top-level enable_thinking: boolean and streams
    // reasoning_content. This is the primary thinking path for Aci.
    return {
      reasoning: true,
      format: "qwen",
      maxTokensField: "max_tokens",
      supportsReasoningEffort: false,
    };
  }

  if (id.includes("gpt-oss")) {
    // OpenAI reasoning models use reasoning_effort and max_completion_tokens.
    return {
      reasoning: true,
      format: "openai",
      maxTokensField: "max_completion_tokens",
      supportsReasoningEffort: true,
    };
  }

  if ((id.includes("deepseek") && id.includes("r1")) || id.includes("reasoner")) {
    // Conservative: treat as OpenAI-style reasoning. If the upstream rejects
    // reasoning_effort, the user can set thinkingFormat: "off".
    return {
      reasoning: true,
      format: "openai",
      maxTokensField: "max_tokens",
      supportsReasoningEffort: true,
    };
  }

  // Non-reasoning models. The handler still surfaces any reasoning_content the
  // model happens to stream, but no thinking parameter is sent.
  return {
    reasoning: false,
    format: "off",
    maxTokensField: "max_tokens",
    supportsReasoningEffort: false,
  };
}

function resolveThinking(
  model: AciServerModel,
  config: AciCloudConfig,
): InferredThinking {
  const modelId = typeof model.id === "string" ? model.id : "";
  const configured = config.models.thinkingFormat;
  if (configured === "off") {
    return {
      reasoning: false,
      format: "off",
      maxTokensField: "max_tokens",
      supportsReasoningEffort: false,
    };
  }
  if (configured === "qwen") {
    return {
      reasoning: true,
      format: "qwen",
      maxTokensField: "max_tokens",
      supportsReasoningEffort: false,
    };
  }
  if (configured === "openai") {
    return {
      reasoning: true,
      format: "openai",
      maxTokensField: "max_completion_tokens",
      supportsReasoningEffort: true,
    };
  }
  const inferred = inferThinkingFormat(modelId);
  // "auto": prefer the server's declared supported_features when the catalog
  // provides them (a non-empty list is authoritative for reasoning support).
  // Id-based inference is only the fallback for entries without metadata —
  // it misses reasoning models like deepseek-v3.2, kimi-k3 or glm-5.x and
  // would over-claim reasoning for entries the server says lack it.
  const features = Array.isArray(model.supported_features)
    ? model.supported_features
    : undefined;
  if (features && features.length > 0) {
    const reasoning = features.includes("reasoning");
    if (reasoning && inferred.format === "off") {
      // Reasoning model from a family the id heuristics don't know. The
      // gateway upstreams accept OpenAI-style reasoning_effort (verified
      // live against inference.phala.com), so use it rather than disabling
      // thinking entirely.
      return {
        reasoning: true,
        format: "openai",
        maxTokensField: "max_tokens",
        supportsReasoningEffort: true,
      };
    }
    return { ...inferred, reasoning };
  }
  return inferred;
}

function parsePerTokenPrice(value: unknown): number {
  if (typeof value !== "string" && typeof value !== "number") return 0;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) return 0;
  // Aci returns per-token pricing; pi expects per-million-token.
  return parsed * 1_000_000;
}

function mapInputModalities(raw: unknown): ("text" | "image")[] {
  if (!Array.isArray(raw)) return ["text"];
  const hasImage = raw.some((m) => m === "image");
  return hasImage ? ["text", "image"] : ["text"];
}

type AciModelKind = "chat" | "classifier" | null;

/**
 * Route a catalog entry by its declared output modalities. The gateway also
 * hosts non-chat models that must not be registered as chat completions:
 *   - ["decisions"]     -> pi classifier model (System One protocol, served
 *     at POST {baseUrl}/systemone; verified live with jaredpalmer/kev-4b)
 *   - ["embeddings"]    -> excluded; pi extensions have no embedding surface
 *   - ["transcription"] -> excluded; pi has no audio API
 *   - ["image"]         -> excluded; pi's only image API is openrouter-images
 * Entries without output_modalities metadata are assumed to be chat.
 */
function modelKind(model: AciServerModel): AciModelKind {
  const output = model.output_modalities;
  if (!Array.isArray(output) || output.length === 0) return "chat";
  if (output.includes("text")) return "chat";
  if (output.length === 1 && output[0] === "decisions") return "classifier";
  return null;
}


// Pure mapping. Exposed for tests.
export function mapAciServerModel(
  model: AciServerModel,
  config: AciCloudConfig,
): ProviderModelConfig | null {
  if (typeof model.id !== "string" || model.id.length === 0) return null;
  const kind = modelKind(model);
  if (kind === null) return null;

  if (config.models.isTeeOnly && model.is_tee !== true) return null;

  if (config.models.allowlist && config.models.allowlist.length > 0) {
    if (!config.models.allowlist.includes(model.id)) return null;
  }

  const contextWindow =
    typeof model.context_length === "number" && model.context_length > 0
      ? model.context_length
      : 32768;

  const pricing =
    model.pricing && typeof model.pricing === "object"
      ? (model.pricing as { prompt?: unknown; completion?: unknown })
      : {};
  const cost = {
    input: parsePerTokenPrice(pricing.prompt),
    output: parsePerTokenPrice(pricing.completion),
    cacheRead: 0,
    cacheWrite: 0,
  };
  const name = typeof model.name === "string" && model.name ? model.name : model.id;

  if (kind === "classifier") {
    // Decision model: served via the TypeSafe System One protocol at
    // POST {baseUrl}/systemone (pi-ai's "typesafe-system-one" classifier
    // API). No compat/thinking handling — classifiers don't stream chat.
    return {
      id: model.id,
      name,
      type: "classifier",
      api: "typesafe-system-one",
      input: mapInputModalities(model.input_modalities),
      cost,
      contextWindow,
    };
  }

  const maxTokens =
    typeof model.max_output_length === "number" && model.max_output_length > 0
      ? model.max_output_length
      : Math.min(contextWindow, 8192);

  const thinking = resolveThinking(model, config);
  const compatOverride = resolveModelCompatOverride(config, model.id);

  // pi 1.5 splits ProviderModelConfig into a discriminated union; compat
  // lives on the chat variant.
  const compat: NonNullable<Extract<ProviderModelConfig, { reasoning: boolean }>["compat"]> = {
    thinkingFormat: thinking.format === "off" ? "openai" : thinking.format,
    maxTokensField: thinking.maxTokensField,
    supportsReasoningEffort: thinking.supportsReasoningEffort,
    // Default true mirrors pi's auto-detection for OpenAI-compatible hosts;
    // per-model overrides record the upstreams that reject `developer`.
    supportsDeveloperRole: compatOverride?.supportsDeveloperRole ?? true,
    supportsStrictMode: false,
    supportsUsageInStreaming: true,
  };

  return {
    id: model.id,
    name,
    reasoning: thinking.reasoning,
    input: mapInputModalities(model.input_modalities),
    cost,
    contextWindow,
    maxTokens: compatOverride?.maxTokens ?? maxTokens,
    ...(compatOverride?.thinkingLevelMap
      ? { thinkingLevelMap: compatOverride.thinkingLevelMap }
      : {}),
    compat,
  };
}

export interface DiscoverAciModelsOptions {
  timeoutMs?: number;
  baseUrl?: string;
}

export interface DiscoverAciModelsResult {
  models: ProviderModelConfig[];
  raw: AciServerModel[];
}

export async function discoverAciModels(
  apiKey: string,
  config: AciCloudConfig,
  options: DiscoverAciModelsOptions = {},
): Promise<DiscoverAciModelsResult> {
  if (!apiKey) return { models: [], raw: [] };

  const timeoutMs = options.timeoutMs ?? DEFAULT_DISCOVERY_TIMEOUT_MS;
  const controller = new AbortController();
  const timeout =
    timeoutMs > 0 ? setTimeout(() => controller.abort(), timeoutMs).unref() : undefined;

  try {
    const response = await fetch(buildModelsUrl(options.baseUrl), {
      signal: controller.signal,
      headers: {
        Authorization: `Bearer ${apiKey}`,
        Accept: "application/json",
      },
    });
    if (!response.ok) {
      console.error(
        `${LOG_PREFIX} /v1/models returned ${response.status} ${response.statusText}`,
      );
      return { models: [], raw: [] };
    }
    const json = (await response.json()) as { data?: unknown };
    const list = Array.isArray(json.data)
      ? (json.data as AciServerModel[]).filter((m) => m && typeof m === "object")
      : [];
    const models = list
      .map((m) => mapAciServerModel(m, config))
      .filter((m): m is ProviderModelConfig => m !== null);
    return { models, raw: list };
  } catch (error) {
    console.error(`${LOG_PREFIX} model discovery failed:`, error);
    return { models: [], raw: [] };
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

/** Fallback model list used when discovery has no API key or fails. Drawn from
 *  the active provider profile (branded shells supply their own catalog); the
 *  live /v1/models catalog is authoritative. */
export function fallbackModels(
  config?: Pick<AciCloudConfig, "models">,
): ProviderModelConfig[] {
  return profile().fallbackModels.map((m) => {
    const thinking = inferThinkingFormat(m.id);
    const compatOverride = config ? resolveModelCompatOverride(config, m.id) : undefined;
    return {
      ...m,
      maxTokens: compatOverride?.maxTokens ?? m.maxTokens,
      ...(compatOverride?.thinkingLevelMap
        ? { thinkingLevelMap: compatOverride.thinkingLevelMap }
        : {}),
      compat: {
        thinkingFormat: thinking.format === "off" ? "openai" : thinking.format,
        maxTokensField: thinking.maxTokensField,
        supportsReasoningEffort: thinking.supportsReasoningEffort,
        supportsDeveloperRole: compatOverride?.supportsDeveloperRole ?? true,
        supportsStrictMode: false,
        supportsUsageInStreaming: true,
      },
    } as ProviderModelConfig;
  });
}

// Re-exported type alias so index.ts can name the Model<Api> shape without an
// extra import site.
export type AnyModel = Model<Api>;
