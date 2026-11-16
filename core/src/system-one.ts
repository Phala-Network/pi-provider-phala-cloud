// System One classifier transport (`typesafe-system-one`).
//
// Decision models in the gateway catalog (`output_modalities: ["decisions"]`)
// answer at POST {baseUrl}/systemone using TypeSafe's System One protocol,
// which pi exposes as the `typesafe-system-one` classifier API.
//
// pi-ai ships an implementation at
// `@earendil-works/pi-ai/api/typesafe-system-one.lazy`, but extensions cannot
// import it: pi resolves only a fixed set of pi-ai entry points for extensions
// (root/compat, /models, /oauth, /providers/all), so a deep `api/*` specifier
// fails to load inside an installed package with "Cannot find module". This
// module therefore carries the transport itself — ported from pi-ai 1.5.2
// (`api/system-one-shared.ts` and `api/typesafe-system-one.ts`) — and borrows
// only pi-ai's types.
//
// Wire notes carried over from upstream:
//   - public `bool` questions are sent as TypeSafe's wire-level `noul`
//   - images go as `assets` by default; OpenRouter-style endpoints take them
//     as `image_url` state parts, and the asset form needs an opt-in header
//   - usage is parsed before answers, so a malformed (but billed) response
//     still reports token usage

import type {
  ClassifierAnswer,
  ClassifierApi,
  ClassifierContext,
  ClassifierModel,
  ClassifierOptions,
  ClassifierQuestion,
  ClassifierResult,
  ImageContent,
  ProviderClassifier,
  Usage,
} from "@earendil-works/pi-ai";

const API = "typesafe-system-one";
const LABEL = "System One API";
const DEFAULT_MAX_RETRIES = 2;
const RETRY_BASE_DELAY_MS = 250;
const ERROR_BODY_LIMIT = 500;

/** TypeSafe's opt-in header for its experimental image input. */
const IMAGE_OPT_IN_HEADERS = { "TypeSafe-Danger-Zone-Images": "true" };
/** Clef accepts at most this many images per request. */
const MAX_DATA_URL_IMAGES = 4;
const DATA_URL_TYPES = new Set(["image/png", "image/jpeg", "image/webp"]);
const ASSET_FORMATS: Record<string, string> = { "image/png": "png", "image/jpeg": "jpeg" };
/** Statuses that are worth retrying; everything else fails on the first attempt. */
const RETRYABLE_STATUSES = new Set([408, 409, 425, 429, 500, 502, 503, 504]);

/** Classifier implementation registered for the `typesafe-system-one` API. */
export function typesafeSystemOneClassifier(): ProviderClassifier {
  return { classify: classifyTypesafeSystemOne };
}

/**
 * Runs one System One classification. Transport and payload failures come back
 * as an error result (the classifier contract) instead of throwing, so the
 * caller still sees usage and a readable message.
 */
async function classifyTypesafeSystemOne(
  model: ClassifierModel<ClassifierApi>,
  context: ClassifierContext,
  options?: ClassifierOptions,
): Promise<ClassifierResult> {
  const result: ClassifierResult = {
    api: model.api,
    provider: model.provider,
    model: model.id,
    answers: {},
    stopReason: "stop",
    timestamp: Date.now(),
  };

  try {
    if (model.api !== API) throw new Error(`Unsupported classifier API: ${model.api}`);

    const request = wireRequest(context);
    let requestOptions = options;
    if (context.images?.length) {
      if (!model.input.includes("image")) {
        throw new Error(`${LABEL} does not support image input for ${model.id}`);
      }
      const detected = detectCompat(model);
      const imageInput = model.compat?.imageInput ?? detected.imageInput;
      addImages(model, imageInput, context.images, request);
      if (model.compat?.sendImageOptInHeader ?? detected.sendImageOptInHeader) {
        requestOptions = { ...options, headers: { ...IMAGE_OPT_IN_HEADERS, ...options?.headers } };
      }
    }

    const body = await postClassifierRequest(model, request, requestOptions);
    // Set before parsing answers: a request with malformed answers was still billed.
    const usage = parseUsage(body.usage, model);
    if (usage) result.usage = usage;
    result.answers = parseAnswers(body.answers, context);
    return result;
  } catch (error) {
    result.stopReason = options?.signal?.aborted ? "aborted" : "error";
    result.errorMessage = `${LABEL} error: ${describeError(error)}`;
    return result;
  }
}

/**
 * Image transport for a model: OpenRouter by provider id (survives baseUrl
 * overrides) or by host (covers regional endpoints); assets otherwise.
 */
function detectCompat(model: ClassifierModel<ClassifierApi>): {
  imageInput: "assets" | "images" | "state-image-urls";
  sendImageOptInHeader: boolean;
} {
  return model.provider === "openrouter" || model.baseUrl.includes("openrouter.ai")
    ? { imageInput: "state-image-urls", sendImageOptInHeader: false }
    : { imageInput: "assets", sendImageOptInHeader: true };
}

/** Maps public `bool` questions to TypeSafe's wire-level `noul` type. */
function wireRequest(context: ClassifierContext): Record<string, unknown> {
  const questions: Record<string, unknown> = {};
  for (const [id, question] of Object.entries(context.questions)) {
    questions[id] = question.type === "bool" ? { ...question, type: "noul" } : question;
  }
  return { state: context.state, questions };
}

/** Adds the context images to `request` in the service's form. */
function addImages(
  model: ClassifierModel<ClassifierApi>,
  input: "assets" | "images" | "state-image-urls",
  images: ImageContent[],
  request: Record<string, unknown>,
): void {
  if (input === "images") {
    if (images.length > MAX_DATA_URL_IMAGES) {
      throw new Error(
        `${LABEL} accepts at most ${MAX_DATA_URL_IMAGES} images for ${model.id}, got ${images.length}`,
      );
    }
    request.images = images.map((image) => {
      if (!DATA_URL_TYPES.has(image.mimeType)) {
        throw new Error(
          `${LABEL} accepts PNG, JPEG, and WebP images for ${model.id}, got ${image.mimeType}`,
        );
      }
      return `data:${image.mimeType};base64,${image.data}`;
    });
    return;
  }

  if (input === "state-image-urls") {
    const parts = images.map((image) => ({
      type: "image_url",
      image_url: { url: `data:${image.mimeType};base64,${image.data}` },
    }));
    request.state = [...parts, request.state];
    return;
  }

  const assets: Record<string, unknown> = {};
  images.forEach((image, index) => {
    const format = ASSET_FORMATS[image.mimeType];
    if (!format) {
      throw new Error(`${LABEL} accepts PNG and JPEG images for ${model.id}, got ${image.mimeType}`);
    }
    assets[`<image-${index + 1}>`] = { type: "image", format, data_base64: image.data };
  });
  request.assets = assets;
  // Every asset must be referenced from the request, before the state body.
  request.state = [...Object.keys(assets), request.state];
}

/** Parses the service's answers, mapping wire-level `noul` back to `bool`. */
function parseAnswers(
  value: unknown,
  context: ClassifierContext,
): Record<string, ClassifierAnswer> {
  if (!isRecord(value)) throw new Error(`${LABEL} returned an unexpected response`);

  const answers: Record<string, ClassifierAnswer> = {};
  for (const [id, question] of Object.entries(context.questions)) {
    const answer = value[id];
    if (!isRecord(answer)) throw new Error(`${LABEL} did not return an answer for ${id}`);
    answers[id] = parseAnswer(id, question, answer);
  }
  return answers;
}

function parseAnswer(
  id: string,
  question: ClassifierQuestion,
  answer: Record<string, unknown>,
): ClassifierAnswer {
  if (question.type === "choice") {
    if (answer.type !== "choice" || typeof answer.choice !== "string") {
      throw new Error(`${LABEL} did not return a choice answer for ${id}`);
    }
    return {
      type: "choice",
      choice: answer.choice,
      probabilities: probabilities(answer.probabilities, id),
      confidence: requiredNumber(answer.confidence, `confidence for ${id}`),
    };
  }
  if (question.type === "score") {
    if (answer.type !== "score") throw new Error(`${LABEL} did not return a score answer for ${id}`);
    return {
      type: "score",
      score: requiredNumber(answer.score, `score for ${id}`),
      confidence: requiredNumber(answer.confidence, `confidence for ${id}`),
    };
  }
  if (answer.type !== "noul") throw new Error(`${LABEL} did not return a bool answer for ${id}`);
  return { type: "bool", probability: requiredNumber(answer.noul, `probability for ${id}`) };
}

function probabilities(value: unknown, id: string): Record<string, number> {
  if (!isRecord(value)) throw new Error(`${LABEL} returned invalid probabilities for ${id}`);
  const out: Record<string, number> = {};
  for (const [key, probability] of Object.entries(value)) {
    out[key] = requiredNumber(probability, `probability for ${id}.${key}`);
  }
  return out;
}

/**
 * Usage from a `{ input_tokens, output_tokens }` object, priced from the model
 * catalog. A missing or malformed usage object leaves the result without usage
 * instead of failing it.
 */
function parseUsage(value: unknown, model: ClassifierModel<ClassifierApi>): Usage | undefined {
  if (!isRecord(value)) return undefined;
  if (value.input_tokens === undefined && value.output_tokens === undefined) return undefined;

  const input = tokenCount(value.input_tokens);
  const output = tokenCount(value.output_tokens);
  const usage: Usage = {
    input,
    output,
    cacheRead: 0,
    cacheWrite: 0,
    totalTokens: input + output,
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
  };
  applyCatalogCost(usage, model);
  return usage;
}

/** Catalog pricing (per million tokens), mirroring pi-ai's `calculateCost`. */
function applyCatalogCost(usage: Usage, model: ClassifierModel<ClassifierApi>): void {
  const inputTokens = usage.input + usage.cacheRead + usage.cacheWrite;
  let rates = model.cost;
  let matchedThreshold = -1;
  for (const tier of model.cost.tiers ?? []) {
    if (inputTokens > tier.inputTokensAbove && tier.inputTokensAbove > matchedThreshold) {
      rates = tier;
      matchedThreshold = tier.inputTokensAbove;
    }
  }
  usage.cost.input = (rates.input / 1_000_000) * usage.input;
  usage.cost.output = (rates.output / 1_000_000) * usage.output;
  usage.cost.cacheRead = (rates.cacheRead / 1_000_000) * usage.cacheRead;
  usage.cost.cacheWrite = (rates.cacheWrite / 1_000_000) * usage.cacheWrite;
  usage.cost.total =
    usage.cost.input + usage.cost.output + usage.cost.cacheRead + usage.cost.cacheWrite;
}

function endpoint(model: ClassifierModel<ClassifierApi>): URL {
  return new URL("systemone", `${model.baseUrl.replace(/\/+$/u, "")}/`);
}

/**
 * Posts one classifier request with bearer auth, `onPayload`/`onResponse`
 * hooks, a fresh timeout per attempt, and bounded retries on transient
 * failures. Returns the parsed response body; throws on failure.
 */
async function postClassifierRequest(
  model: ClassifierModel<ClassifierApi>,
  payload: Record<string, unknown>,
  options?: ClassifierOptions,
): Promise<Record<string, unknown>> {
  const apiKey = options?.apiKey;
  if (!apiKey) throw new Error(`No API key for provider: ${model.provider}`);

  const fetchImpl = options?.fetch ?? globalThis.fetch;
  const headers = requestHeaders(model, apiKey, options?.headers);
  const transformed = await options?.onPayload?.(payload, model);
  const body = transformed !== undefined ? transformed : payload;
  const url = endpoint(model);
  const attempts = Math.max(0, options?.maxRetries ?? DEFAULT_MAX_RETRIES) + 1;

  for (let attempt = 1; ; attempt += 1) {
    throwIfAborted(options?.signal);
    const timeoutSignal =
      options?.timeoutMs === undefined ? undefined : AbortSignal.timeout(options.timeoutMs);
    const signal =
      options?.signal && timeoutSignal
        ? AbortSignal.any([options.signal, timeoutSignal])
        : (options?.signal ?? timeoutSignal);

    try {
      const response = await fetchImpl(url, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal,
      });
      if (!response.ok) {
        const detail = (await response.text()).slice(0, ERROR_BODY_LIMIT);
        throw new HttpStatusError(
          `${LABEL} returned ${response.status}${detail ? `: ${detail}` : ""}`,
          response.status,
        );
      }
      await options?.onResponse?.(
        { status: response.status, headers: headersToRecord(response.headers) },
        model,
      );
      const json: unknown = await response.json();
      if (!isRecord(json)) throw new Error(`${LABEL} returned an unexpected response`);
      return json;
    } catch (error) {
      const timedOut = timeoutSignal?.aborted === true && options?.signal?.aborted !== true;
      if (timedOut) throw new Error(`Request timed out after ${options?.timeoutMs}ms`);
      if (attempt >= attempts || !isRetryable(error)) throw error;
      await delay(RETRY_BASE_DELAY_MS * 2 ** (attempt - 1), options?.signal);
    }
  }
}

class HttpStatusError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "HttpStatusError";
    this.status = status;
  }
}

/** Retries transient statuses and network failures; aborts are final. */
function isRetryable(error: unknown): boolean {
  if (error instanceof HttpStatusError) return RETRYABLE_STATUSES.has(error.status);
  if (error instanceof Error && error.name === "AbortError") return false;
  if (error instanceof Error && error.name === "TimeoutError") return false;
  return error instanceof TypeError;
}

function requestHeaders(
  model: ClassifierModel<ClassifierApi>,
  apiKey: string,
  optionHeaders: ClassifierOptions["headers"],
): Record<string, string> {
  const headers: Record<string, string> = {
    ...model.headers,
    authorization: `Bearer ${apiKey}`,
    "content-type": "application/json",
  };
  for (const [name, value] of Object.entries(optionHeaders ?? {})) {
    if (value === null) delete headers[name];
    else headers[name] = value;
  }
  return headers;
}

function headersToRecord(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, name) => {
    out[name] = value;
  });
  return out;
}

function describeError(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requiredNumber(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`${LABEL} returned an invalid ${field}`);
  }
  return value;
}

function tokenCount(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : 0;
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw signal.reason ?? new Error("Request aborted");
}

function delay(ms: number, signal: AbortSignal | undefined): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason ?? new Error("Request aborted"));
      return;
    }
    const cleanup = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    };
    const onAbort = () => {
      cleanup();
      reject(signal?.reason ?? new Error("Request aborted"));
    };
    const timer = setTimeout(() => {
      cleanup();
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}
