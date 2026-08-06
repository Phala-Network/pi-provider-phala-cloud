// ACI E2EE v2 (spec §7) request encryption and response decryption.
//
// Field coverage (§7.2): every content-bearing field is encrypted in place;
// each ciphertext is bound to its field path through the AAD. The AAD (§7.3)
// is the JCS canonicalization of a purpose-tagged object — no bespoke
// escaping:
//   request:  {"purpose":"aci.e2ee.request.v2","algo","model","field","nonce","ts"}
//   response: {"purpose":"aci.e2ee.response.v2","algo","model","id","field","nonce","ts"}
//
// Wire format and key schedule live in src/crypto.ts (secp256k1 suite,
// matching the gateway's src/aci/e2ee.rs). Field selection and AAD mirror the
// gateway's src/aggregator/service/e2ee_crypto.rs and the reference client
// clients/verifier-ts/src/e2ee-channel.ts.

import { canonicalize } from "./canonical.ts";
import { decryptWithSecretKey, encryptForPublicKey } from "./crypto.ts";

export type Json = unknown;

const CHAT_COMPLETIONS_PATH = "/v1/chat/completions";
const COMPLETIONS_PATH = "/v1/completions";
const EMBEDDINGS_PATH = "/v1/embeddings";

export interface E2eeRequestParams {
  /** Gateway E2EE public key hex (uncompressed secp256k1). */
  modelPublicKeyHex: string;
  /** Per-request replay nonce: 32 random bytes, hex-encoded as 64 chars (§7.5). */
  nonce: string;
  /** Unix seconds; the service rejects |now − ts| > 300 (§7.5). */
  timestamp: number;
  /** Algorithm string from the attestation keyset (secp256k1-aes-256-gcm-hkdf-sha256). */
  algo: string;
  /** Model id from the request payload's `model` field (byte-exact). */
  model: string;
}

function assertValidNonce(nonce: string): void {
  if (nonce.length !== 64 || !/^[0-9a-fA-F]+$/.test(nonce)) {
    throw new Error("invalid E2EE nonce: must be 64 hex characters (§7.5)");
  }
}

/** Request AAD bytes (§7.3), tag `aci.e2ee.request.v2`. */
function requestAad(params: E2eeRequestParams, field: string): Uint8Array {
  return canonicalize({
    purpose: "aci.e2ee.request.v2",
    algo: params.algo,
    model: params.model,
    field,
    nonce: params.nonce,
    ts: params.timestamp,
  });
}

/** Response AAD bytes (§7.3), tag `aci.e2ee.response.v2`; `id` is the response id ("" when absent). */
function responseAad(params: E2eeRequestParams, id: string, field: string): Uint8Array {
  return canonicalize({
    purpose: "aci.e2ee.response.v2",
    algo: params.algo,
    model: params.model,
    id,
    field,
    nonce: params.nonce,
    ts: params.timestamp,
  });
}

function inferEndpointPath(obj: Record<string, unknown>): string {
  if (Array.isArray(obj.messages)) return CHAT_COMPLETIONS_PATH;
  if (obj.prompt !== undefined) return COMPLETIONS_PATH;
  if (obj.input !== undefined) return EMBEDDINGS_PATH;
  // Default to chat completions for safety.
  return CHAT_COMPLETIONS_PATH;
}

/**
 * Encrypt the E2EE-protected fields of an OpenAI-compatible request payload,
 * in place (§7.2). Chat message content is encrypted as ONE ciphertext per
 * message at `messages.{i}.content` — a plain string, or a structured content
 * array serialized to JSON.
 */
export function encryptRequestPayload(
  payload: Json,
  params: E2eeRequestParams,
  endpointPath?: string,
): void {
  assertValidNonce(params.nonce);

  const obj = payload as Record<string, unknown>;
  if (!obj || typeof obj !== "object") {
    throw new Error("E2EE payload must be an object");
  }

  const seal = (text: string, field: string): string =>
    encryptForPublicKey(
      params.modelPublicKeyHex,
      new TextEncoder().encode(text),
      requestAad(params, field),
    );

  const path = endpointPath ?? inferEndpointPath(obj);
  if (path === COMPLETIONS_PATH) {
    sealStringOrArray(obj, "prompt", seal);
    return;
  }
  if (path === EMBEDDINGS_PATH) {
    sealStringOrArray(obj, "input", seal);
    return;
  }

  const messages = obj.messages;
  if (!Array.isArray(messages)) {
    throw new Error("E2EE chat payload missing messages array");
  }
  for (let i = 0; i < messages.length; i++) {
    const message = messages[i] as Record<string, unknown> | undefined;
    if (!message || typeof message !== "object" || message.content == null) continue;
    const text =
      typeof message.content === "string" ? message.content : JSON.stringify(message.content);
    message.content = seal(text, `messages.${i}.content`);
  }
}

/** Encrypt a string member, or each string element of an array at `name.{i}` (§7.2). */
function sealStringOrArray(
  obj: Record<string, unknown>,
  name: string,
  seal: (text: string, field: string) => string,
): void {
  const value = obj[name];
  if (typeof value === "string") {
    obj[name] = seal(value, name);
  } else if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      if (typeof value[i] === "string") value[i] = seal(value[i] as string, `${name}.${i}`);
    }
  }
}

// ----------------------------------------------------------------------------
// Response decryption
// ----------------------------------------------------------------------------

export interface E2eeResponseDecryptor {
  /** Decrypt a buffered (non-stream) response body. */
  openResponse(body: Json): Json;
  /** Decrypt one streamed SSE chunk (chat.completion.chunk / completion chunk). */
  openChunk(chunk: Json): Json;
}

/**
 * Build a response decryptor bound to this request's context (§7.3).
 * `clientSecret` is the private half of the ephemeral client keypair whose
 * public key was sent as X-Client-Pub-Key.
 */
export function createResponseDecryptor(
  clientSecret: Uint8Array,
  params: E2eeRequestParams,
): E2eeResponseDecryptor {
  const decField = (blobHex: string, field: string, id: string): string =>
    new TextDecoder().decode(
      decryptWithSecretKey(clientSecret, blobHex, responseAad(params, id, field)),
    );

  /** Decrypt string member `key` of `obj` at `field`; leave non-strings untouched. */
  const openStr = (obj: Record<string, unknown>, key: string, field: string, id: string): void => {
    if (typeof obj[key] === "string") obj[key] = decField(obj[key] as string, field, id);
  };

  /** `choices`/`data` index is the entry's `index` member, else its array position (§7.2). */
  const indexOf = (entry: Record<string, unknown>, position: number): number =>
    typeof entry.index === "number" ? entry.index : position;

  return {
    openResponse(body) {
      const obj = body as Record<string, unknown>;
      if (!obj || typeof obj !== "object") return body;
      const id = typeof obj.id === "string" ? obj.id : "";
      const out: Record<string, unknown> = { ...obj };
      if (Array.isArray(obj.choices)) {
        out.choices = obj.choices.map((choice, pos) => {
          const c = { ...(choice as Record<string, unknown>) };
          const i = indexOf(c, pos);
          if (c.message && typeof c.message === "object") {
            const m = { ...(c.message as Record<string, unknown>) };
            openStr(m, "content", `choices.${i}.message.content`, id);
            openStr(m, "reasoning_content", `choices.${i}.message.reasoning_content`, id);
            if (m.audio && typeof m.audio === "object") {
              const a = { ...(m.audio as Record<string, unknown>) };
              openStr(a, "data", `choices.${i}.message.audio.data`, id);
              m.audio = a;
            }
            c.message = m;
          } else {
            openStr(c, "text", `choices.${i}.text`, id); // completions
          }
          return c;
        });
      }
      if (Array.isArray(obj.data)) {
        // Embeddings: the value is serialized compactly then encrypted (§7.2).
        out.data = obj.data.map((entry, pos) => {
          const d = { ...(entry as Record<string, unknown>) };
          const i = indexOf(d, pos);
          if (typeof d.embedding === "string") {
            d.embedding = JSON.parse(decField(d.embedding, `data.${i}.embedding`, id));
          }
          return d;
        });
      }
      return out;
    },

    openChunk(chunk) {
      const obj = chunk as Record<string, unknown>;
      if (!obj || typeof obj !== "object") return chunk;
      const id = typeof obj.id === "string" ? obj.id : "";
      const out: Record<string, unknown> = { ...obj };
      if (Array.isArray(obj.choices)) {
        out.choices = obj.choices.map((choice, pos) => {
          const c = { ...(choice as Record<string, unknown>) };
          const i = indexOf(c, pos);
          if (c.delta && typeof c.delta === "object") {
            const d = { ...(c.delta as Record<string, unknown>) };
            openStr(d, "content", `choices.${i}.delta.content`, id);
            openStr(d, "reasoning_content", `choices.${i}.delta.reasoning_content`, id);
            c.delta = d;
          } else {
            openStr(c, "text", `choices.${i}.text`, id); // completions stream
          }
          return c;
        });
      }
      return out;
    },
  };
}

// ----------------------------------------------------------------------------
// Response-level wrapper (fetch seam)
// ----------------------------------------------------------------------------

/**
 * Decrypt an E2EE response produced for this request. SSE bodies are
 * transformed chunk-by-chunk; buffered JSON bodies are decrypted whole.
 * Non-ok responses and non-JSON bodies pass through unchanged (gateway
 * generated error envelopes carry no encrypted fields).
 */
export async function decryptE2eeResponse(
  res: Response,
  decryptor: E2eeResponseDecryptor,
): Promise<Response> {
  if (!res.ok || !res.body) return res;
  const contentType = res.headers.get("content-type") ?? "";
  if (contentType.includes("text/event-stream")) {
    return new Response(decryptSseStream(res.body, decryptor), {
      status: res.status,
      statusText: res.statusText,
      headers: withoutContentLength(res.headers),
    });
  }
  if (contentType.includes("application/json")) {
    const body = await res.json();
    return new Response(JSON.stringify(decryptor.openResponse(body)), {
      status: res.status,
      statusText: res.statusText,
      headers: withoutContentLength(res.headers),
    });
  }
  return res;
}

function withoutContentLength(headers: Headers): Headers {
  const out = new Headers(headers);
  out.delete("content-length");
  return out;
}

/** Transform an SSE byte stream, decrypting each `data:` JSON payload. */
function decryptSseStream(
  body: ReadableStream<Uint8Array>,
  decryptor: E2eeResponseDecryptor,
): ReadableStream<Uint8Array> {
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  let buffer = "";

  const transformLine = (line: string): string => {
    const cr = line.endsWith("\r") ? "\r" : "";
    const bare = cr ? line.slice(0, -1) : line;
    if (!bare.startsWith("data:")) return line;
    const data = bare.slice(5).replace(/^ /, "");
    if (data === "[DONE]") return line;
    try {
      const opened = decryptor.openChunk(JSON.parse(data));
      return `data: ${JSON.stringify(opened)}${cr}`;
    } catch {
      // Not a JSON chunk we understand; forward untouched.
      return line;
    }
  };

  return new ReadableStream<Uint8Array>({
    async start(controller) {
      const reader = body.getReader();
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          let newline: number;
          while ((newline = buffer.indexOf("\n")) !== -1) {
            const line = buffer.slice(0, newline);
            buffer = buffer.slice(newline + 1);
            controller.enqueue(encoder.encode(`${transformLine(line)}\n`));
          }
        }
        buffer += decoder.decode();
        if (buffer.length > 0) controller.enqueue(encoder.encode(transformLine(buffer)));
      } finally {
        reader.releaseLock();
        controller.close();
      }
    },
  });
}
