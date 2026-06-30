// E2EE field selection and AAD construction, mirroring the gateway's
// `src/aci/e2ee_crypto.rs`. The gateway encrypts/decrypts specific fields of
// the OpenAI request/response JSON; the AAD binds each ciphertext to its
// protocol position so a swapped field fails to decrypt.
//
// This module is the request-side encryptor (client -> gateway). Response
// decryption is not needed in this provider: pi consumes the cleartext stream
// that the gateway returns, and E2EE only protects the provider-facing hop.
// (The gateway decrypts inside its TEE, forwards to the upstream over a bound
// channel, then returns cleartext to the client.) We verify confidentiality of
// the upstream hop via the receipt's `upstream.verified` event, not by
// decrypting the response ourselves.

import { encryptForPublicKey } from "./crypto.ts";

// Legacy completions endpoint. Chat completions fall through to encryptChatMessages.
const COMPLETIONS_PATH = "/v1/completions";
const EMBEDDINGS_PATH = "/v1/embeddings";

export type Json = unknown;

function aadComponentIsAmbiguous(value: string): boolean {
  return value.includes("|") || value.includes("\r") || value.includes("\n");
}

// Request AAD for chat completions messages[].content.
//   v2|req|algo={algo}|model={model}|m={msg_idx}|c={content_idx or -}|n={nonce}|ts={ts}
function requestAad(
  algo: string,
  model: string,
  messageIndex: number,
  contentIndex: number | null,
  nonce: string,
  timestamp: number,
): string {
  const c = contentIndex === null ? "-" : String(contentIndex);
  return `v2|req|algo=${algo}|model=${model}|m=${messageIndex}|c=${c}|n=${nonce}|ts=${timestamp}`;
}

// Request AAD for completions `prompt` / embeddings `input` fields.
//   v2|req|algo={algo}|model={model}|field={name}|n={nonce}|ts={ts}
function completionRequestAad(
  algo: string,
  model: string,
  fieldName: string,
  nonce: string,
  timestamp: number,
): string {
  return `v2|req|algo=${algo}|model=${model}|field=${fieldName}|n=${nonce}|ts=${timestamp}`;
}

export interface E2eeRequestParams {
  /** Gateway E2EE public key hex (uncompressed secp256k1). */
  modelPublicKeyHex: string;
  /** Per-request nonce (unique, non-ambiguous). */
  nonce: string;
  /** Unix seconds, close to gateway time. */
  timestamp: number;
  /** Algorithm string from attestation keyset (secp256k1-aes-256-gcm-hkdf-sha256). */
  algo: string;
  /** Model id from the request payload's `model` field. */
  model: string;
}

function assertValidNonce(nonce: string): void {
  if (nonce.length === 0 || aadComponentIsAmbiguous(nonce)) {
    throw new Error("invalid E2EE nonce");
  }
}

function assertValidModel(model: string): void {
  if (aadComponentIsAmbiguous(model)) {
    throw new Error("ambiguous model id in E2EE AAD");
  }
}

/**
 * Encrypt the E2EE-protected fields of an OpenAI-compatible request payload,
 * in place. Returns the same payload object with selected string fields
 * replaced by ciphertext hex.
 *
 * Chat completions: messages[].content (string or [{type:"text",text:...}]).
 * Legacy completions: prompt (string or string[]).
 * Embeddings: input (string or string[]).
 */
function inferEndpointPath(obj: Record<string, unknown>): string {
  if (Array.isArray(obj.messages)) return CHAT_COMPLETIONS_PATH;
  if (obj.prompt !== undefined) return COMPLETIONS_PATH;
  if (obj.input !== undefined) return EMBEDDINGS_PATH;
  // Default to chat completions for safety.
  return CHAT_COMPLETIONS_PATH;
}

export function encryptRequestPayload(
  payload: Json,
  params: E2eeRequestParams,
  endpointPath?: string,
): void {
  assertValidNonce(params.nonce);
  assertValidModel(params.model);

  const obj = payload as Record<string, unknown>;
  if (!obj || typeof obj !== "object") {
    throw new Error("E2EE payload must be an object");
  }

  const path = endpointPath ?? inferEndpointPath(obj);
  if (path === COMPLETIONS_PATH) {
    encryptCompletionContent(obj, params);
    return;
  }
  if (path === EMBEDDINGS_PATH) {
    encryptEmbeddingInput(obj, params);
    return;
  }
  encryptChatMessages(obj, params);
}

function encryptChatMessages(obj: Record<string, unknown>, params: E2eeRequestParams): void {
  const messages = obj.messages;
  if (!Array.isArray(messages)) {
    throw new Error("E2EE chat payload missing messages array");
  }
  for (let i = 0; i < messages.length; i++) {
    const message = messages[i] as Record<string, unknown> | undefined;
    if (!message || typeof message !== "object") continue;
    const content = message.content;
    if (typeof content === "string") {
      const aad = requestAad(
        params.algo,
        params.model,
        i,
        null,
        params.nonce,
        params.timestamp,
      );
      message.content = encryptForPublicKey(
        params.modelPublicKeyHex,
        new TextEncoder().encode(content),
        new TextEncoder().encode(aad),
      );
    } else if (Array.isArray(content)) {
      for (let j = 0; j < content.length; j++) {
        const part = content[j] as Record<string, unknown> | undefined;
        if (!part || part.type !== "text" || typeof part.text !== "string") continue;
        const aad = requestAad(
          params.algo,
          params.model,
          i,
          j,
          params.nonce,
          params.timestamp,
        );
        part.text = encryptForPublicKey(
          params.modelPublicKeyHex,
          new TextEncoder().encode(part.text),
          new TextEncoder().encode(aad),
        );
      }
    }
  }
}

function encryptCompletionContent(obj: Record<string, unknown>, params: E2eeRequestParams): void {
  const prompt = obj.prompt;
  if (typeof prompt === "string") {
    const aad = completionRequestAad(params.algo, params.model, "prompt", params.nonce, params.timestamp);
    obj.prompt = encryptForPublicKey(
      params.modelPublicKeyHex,
      new TextEncoder().encode(prompt),
      new TextEncoder().encode(aad),
    );
  } else if (Array.isArray(prompt)) {
    for (let i = 0; i < prompt.length; i++) {
      if (typeof prompt[i] !== "string") continue;
      const aad = completionRequestAad(
        params.algo,
        params.model,
        `prompt.${i}`,
        params.nonce,
        params.timestamp,
      );
      prompt[i] = encryptForPublicKey(
        params.modelPublicKeyHex,
        new TextEncoder().encode(prompt[i] as string),
        new TextEncoder().encode(aad),
      );
    }
  }
}

function encryptEmbeddingInput(obj: Record<string, unknown>, params: E2eeRequestParams): void {
  const input = obj.input;
  if (typeof input === "string") {
    const aad = completionRequestAad(params.algo, params.model, "input", params.nonce, params.timestamp);
    obj.input = encryptForPublicKey(
      params.modelPublicKeyHex,
      new TextEncoder().encode(input),
      new TextEncoder().encode(aad),
    );
  } else if (Array.isArray(input)) {
    for (let i = 0; i < input.length; i++) {
      if (typeof input[i] !== "string") continue;
      const aad = completionRequestAad(
        params.algo,
        params.model,
        `input.${i}`,
        params.nonce,
        params.timestamp,
      );
      input[i] = encryptForPublicKey(
        params.modelPublicKeyHex,
        new TextEncoder().encode(input[i] as string),
        new TextEncoder().encode(aad),
      );
    }
  }
}

const CHAT_COMPLETIONS_PATH = "/v1/chat/completions";

export { COMPLETIONS_PATH, EMBEDDINGS_PATH, CHAT_COMPLETIONS_PATH };
