import assert from "node:assert/strict";
import { test } from "node:test";

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { getPublicKey, sign } from "@noble/secp256k1";

import {
  encryptForPublicKey,
  decryptWithSecretKey,
  normalizeSecp256k1PublicKeyHex,
  sha256Hex,
  verifyReceiptSignature,
} from "../src/crypto.ts";

function randomSecret(): Uint8Array {
  const out = new Uint8Array(32);
  crypto.getRandomValues(out);
  return out;
}

function publicKeyHex(secret: Uint8Array): string {
  return bytesToHex(getPublicKey(secret, false));
}

test("normalizeSecp256k1PublicKeyHex: accepts 65-byte uncompressed", () => {
  const secret = randomSecret();
  const pub = publicKeyHex(secret);
  assert.equal(normalizeSecp256k1PublicKeyHex(pub), pub);
});

test("normalizeSecp256k1PublicKeyHex: converts 64-byte bare to 65-byte", () => {
  const secret = randomSecret();
  const pub = publicKeyHex(secret);
  const bare = pub.slice(2);
  assert.equal(normalizeSecp256k1PublicKeyHex(bare), pub);
});

test("encryptForPublicKey / decryptWithSecretKey round-trip", () => {
  const secret = randomSecret();
  const pub = publicKeyHex(secret);
  const plaintext = new TextEncoder().encode("sensitive prompt content");
  const aad = new TextEncoder().encode("v2|req|algo=...|model=...|m=0|c=-|n=...|ts=...");
  const ciphertextHex = encryptForPublicKey(pub, plaintext, aad);
  const decrypted = decryptWithSecretKey(secret, ciphertextHex, aad);
  assert.deepEqual(decrypted, plaintext);
});

test("decrypt fails with wrong AAD", () => {
  const secret = randomSecret();
  const pub = publicKeyHex(secret);
  const plaintext = new TextEncoder().encode("hello");
  const aad = new TextEncoder().encode("correct-aad");
  const ciphertextHex = encryptForPublicKey(pub, plaintext, aad);
  assert.throws(() => {
    decryptWithSecretKey(secret, ciphertextHex, new TextEncoder().encode("wrong-aad"));
  });
});

test("sha256Hex matches gateway format", () => {
  const payload = new TextEncoder().encode("hello");
  const expected = `sha256:${bytesToHex(sha256(payload))}`;
  assert.equal(sha256Hex(payload), expected);
});

test("verifyReceiptSignature: accepts valid recoverable secp256k1 signature", () => {
  const secret = randomSecret();
  const pubHex = publicKeyHex(secret);
  const canonicalBytes = new TextEncoder().encode('{"receipt_id":"r1"}');
  // noble outputs recovered signatures as v || r || s; the gateway uses r || s || v.
  const nobleSig = sign(canonicalBytes, secret, { format: "recovered" }) as Uint8Array;
  assert.equal(nobleSig.length, 65);
  const gatewaySig = new Uint8Array(65);
  gatewaySig.set(nobleSig.subarray(1), 0);
  gatewaySig[64] = nobleSig[0];
  assert.equal(verifyReceiptSignature(pubHex, canonicalBytes, gatewaySig), true);
});

test("verifyReceiptSignature: rejects signature over different bytes", () => {
  const secret = randomSecret();
  const pubHex = publicKeyHex(secret);
  const nobleSig = sign(new TextEncoder().encode("original"), secret, { format: "recovered" }) as Uint8Array;
  const gatewaySig = new Uint8Array(65);
  gatewaySig.set(nobleSig.subarray(1), 0);
  gatewaySig[64] = nobleSig[0];
  const different = new TextEncoder().encode("tampered");
  assert.equal(verifyReceiptSignature(pubHex, different, gatewaySig), false);
});

test("verifyReceiptSignature: rejects wrong-length signature", () => {
  const secret = randomSecret();
  const pubHex = publicKeyHex(secret);
  const sig = new Uint8Array(64);
  assert.equal(verifyReceiptSignature(pubHex, new TextEncoder().encode("x"), sig), false);
});
