import assert from "node:assert/strict";
import { test } from "node:test";

import { getPublicKey } from "@noble/secp256k1";
import { bytesToHex } from "@noble/hashes/utils.js";

import { encryptRequestPayload } from "../src/e2ee.ts";
import { decryptWithSecretKey } from "../src/crypto.ts";

function randomSecret(): Uint8Array {
  const out = new Uint8Array(32);
  crypto.getRandomValues(out);
  return out;
}

test("encryptRequestPayload: encrypts chat messages[].content strings", () => {
  const secret = randomSecret();
  const pubHex = bytesToHex(getPublicKey(secret, false));
  const payload = {
    model: "phala/qwen3.5-27b",
    messages: [
      { role: "system", content: "You are helpful" },
      { role: "user", content: "Hello" },
    ],
  };
  encryptRequestPayload(payload, {
    modelPublicKeyHex: pubHex,
    nonce: "00112233445566778899aabbccddeeff",
    timestamp: 1700000000,
    algo: "secp256k1-aes-256-gcm-hkdf-sha256",
    model: "phala/qwen3.5-27b",
  }, "/v1/chat/completions");

  const system = (payload.messages[0] as { content: string }).content;
  const user = (payload.messages[1] as { content: string }).content;
  assert.match(system, /^[0-9a-f]+$/);
  assert.match(user, /^[0-9a-f]+$/);

  const aad =
    "v2|req|algo=secp256k1-aes-256-gcm-hkdf-sha256|model=phala/qwen3.5-27b|m=0|c=-|n=00112233445566778899aabbccddeeff|ts=1700000000";
  assert.equal(
    new TextDecoder().decode(decryptWithSecretKey(secret, system, new TextEncoder().encode(aad))),
    "You are helpful",
  );

  const aad1 =
    "v2|req|algo=secp256k1-aes-256-gcm-hkdf-sha256|model=phala/qwen3.5-27b|m=1|c=-|n=00112233445566778899aabbccddeeff|ts=1700000000";
  assert.equal(
    new TextDecoder().decode(decryptWithSecretKey(secret, user, new TextEncoder().encode(aad1))),
    "Hello",
  );
});

test("encryptRequestPayload: encrypts array content text parts", () => {
  const secret = randomSecret();
  const pubHex = bytesToHex(getPublicKey(secret, false));
  const payload = {
    model: "phala/qwen3-vl-30b",
    messages: [
      {
        role: "user",
        content: [{ type: "text", text: "describe image" }, { type: "image_url", image_url: "..." }],
      },
    ],
  };
  encryptRequestPayload(payload, {
    modelPublicKeyHex: pubHex,
    nonce: "aabbccddeeff00112233445566778899",
    timestamp: 1700000001,
    algo: "secp256k1-aes-256-gcm-hkdf-sha256",
    model: "phala/qwen3-vl-30b",
  }, "/v1/chat/completions");

  const part = (payload.messages[0] as { content: Array<{ type: string; text?: string }> }).content[0];
  assert.equal(part.type, "text");
  assert.match(part.text ?? "", /^[0-9a-f]+$/);

  const aad =
    "v2|req|algo=secp256k1-aes-256-gcm-hkdf-sha256|model=phala/qwen3-vl-30b|m=0|c=0|n=aabbccddeeff00112233445566778899|ts=1700000001";
  assert.equal(
    new TextDecoder().decode(
      decryptWithSecretKey(secret, part.text!, new TextEncoder().encode(aad)),
    ),
    "describe image",
  );
});

test("encryptRequestPayload: rejects ambiguous nonce", () => {
  const payload = { model: "x", messages: [] };
  assert.throws(() => {
    encryptRequestPayload(
      payload,
      {
        modelPublicKeyHex: "04".padEnd(130, "0"),
        nonce: "bad|nonce",
        timestamp: 1,
        algo: "secp256k1-aes-256-gcm-hkdf-sha256",
        model: "x",
      },
      "/v1/chat/completions",
    );
  });
});
