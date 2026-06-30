// E2EE cryptography + receipt signature verification, mirroring the gateway's
// `src/aci/e2ee.rs` and `src/aci/keys.rs`.
//
// E2EE wire ciphertext (lowercase hex):
//   ephemeral_uncompressed_secp256k1_public_key(65B) || aes_gcm_nonce(12B) || ciphertext_tag
//
// Key derivation:
//   shared = ECDH(ephemeral_secret, recipient_public)
//   key    = HKDF-SHA256(salt=none, ikm=shared, info="aci.e2ee.v2.secp256k1", len=32)
//   cipher = AES-256-GCM(key)
//
// Receipt signature (ecdsa-secp256k1, ACI §9.4):
//   65 bytes r||s||v; v in 0..=3 (or 27..=30, normalized by subtracting 27).
//   Verified by RECOVERING the public key from sha256(canonical_bytes) and
//   comparing to the attested receipt_signing_keys entry. NOT a standard
//   verify() — the recoverable form is mandated.

import { createCipheriv, createDecipheriv, createHmac } from "node:crypto";
import { hashes, getPublicKey, getSharedSecret, recoverPublicKey, Point } from "@noble/secp256k1";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { hexToBytes, bytesToHex, concatBytes } from "@noble/hashes/utils.js";

// noble/secp256k1 v3 expects synchronous hash/HMAC providers on the `hashes`
// object. Wire them once at module load.
if (!hashes.sha256) {
  hashes.sha256 = nobleSha256 as never;
}
if (!hashes.hmacSha256) {
  hashes.hmacSha256 = (key: Uint8Array, ...messages: Uint8Array[]) =>
    hmac(nobleSha256, key, concatBytes(...messages)) as never;
}

// ----------------------------------------------------------------------------
// secp256k1 public key handling
// ----------------------------------------------------------------------------

const PUBLIC_KEY_LEN = 65;
const NONCE_LEN = 12;
const TAG_LEN = 16;

/** Normalize a secp256k1 public key to 65-byte uncompressed hex (0x04 || X || Y). */
export function normalizeSecp256k1PublicKeyHex(value: string): string {
  const stripped = value.startsWith("0x") ? value.slice(2) : value;
  const bytes = hexToBytes(stripped);
  let encoded: Uint8Array;
  if (bytes.length === 65 && bytes[0] === 0x04) {
    encoded = bytes;
  } else if (bytes.length === 64) {
    // Bare X||Y: prepend 0x04.
    encoded = new Uint8Array(65);
    encoded[0] = 0x04;
    encoded.set(bytes, 1);
  } else if (bytes.length === 33 && (bytes[0] === 0x02 || bytes[0] === 0x03)) {
    // Compressed: decompress via noble Point.
    encoded = Point.fromHex(stripped).toBytes(false);
  } else {
    throw new Error(
      `secp256k1 public key must be 64, 65, or 33 bytes, got ${bytes.length}`,
    );
  }
  // Validate the point is on the curve.
  Point.fromHex(bytesToHex(encoded));
  return bytesToHex(encoded);
}

// ----------------------------------------------------------------------------
// E2EE encrypt / decrypt
// ----------------------------------------------------------------------------

const HKDF_INFO = new TextEncoder().encode("aci.e2ee.v2.secp256k1");

function hkdfSha256(ikm: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  // HKDF-Extract: PRK = HMAC-SHA256(salt="", ikm). Empty salt -> key of 0x00*32.
  const prk = createHmac("sha256", new Uint8Array(32)).update(ikm).digest();
  // HKDF-Expand: T(i) = HMAC-SHA256(PRK, T(i-1) || info || counter).
  const out = new Uint8Array(length);
  let prev = new Uint8Array(0);
  let offset = 0;
  let counter = 1;
  while (offset < length) {
    const input = new Uint8Array(prev.length + info.length + 1);
    input.set(prev, 0);
    input.set(info, prev.length);
    input[input.length - 1] = counter;
    prev = createHmac("sha256", prk).update(input).digest();
    const take = Math.min(prev.length, length - offset);
    out.set(prev.subarray(0, take), offset);
    offset += take;
    counter++;
  }
  return out;
}

function aesGcmEncrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
  const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return new Uint8Array(Buffer.concat([enc, tag]));
}

function aesGcmDecrypt(key: Uint8Array, nonce: Uint8Array, ciphertextWithTag: Uint8Array, aad: Uint8Array): Uint8Array {
  if (ciphertextWithTag.length < TAG_LEN) {
    throw new Error("E2EE ciphertext too short");
  }
  const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - TAG_LEN);
  const ciphertext = ciphertextWithTag.subarray(0, ciphertextWithTag.length - TAG_LEN);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return new Uint8Array(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
}

/** Derive an ephemeral keypair and return { secret, publicUncompressedHex }. */
function ephemeralKeyPair(): { secret: Uint8Array; publicHex: string } {
  // noble's getPublicKey accepts a 32-byte private key; use crypto.randomBytes
  // for the secret to stay in Node's CSPRNG.
  const secret = new Uint8Array(32);
  crypto.getRandomValues(secret);
  // Ensure scalar is in valid range [1, n-1]; noble handles clamping internally
  // for getSharedSecret, but getPublicKey rejects zero scalar only.
  const pub = getPublicKey(secret, false); // uncompressed -> 65 bytes
  return { secret, publicHex: bytesToHex(pub) };
}

/**
 * Encrypt `plaintext` to `recipientPublicKeyHex` (uncompressed secp256k1 hex)
 * with the given AAD. Returns lowercase hex of
 *   ephemeral_pub || nonce || ciphertext_tag
 */
export function encryptForPublicKey(
  recipientPublicKeyHex: string,
  plaintext: Uint8Array,
  aad: Uint8Array,
): string {
  const recipient = normalizeSecp256k1PublicKeyHex(recipientPublicKeyHex);
  const { secret, publicHex } = ephemeralKeyPair();
  const shared = getSharedSecret(secret, hexToBytes(recipient), false); // 65-byte uncompressed shared point
  // noble returns the shared X coordinate as the last 32 bytes of the 65-byte
  // uncompressed point. ECDH shared secret is the X coordinate.
  const sharedX = shared.subarray(1, 33);
  const key = hkdfSha256(sharedX, HKDF_INFO, 32);
  const nonce = new Uint8Array(NONCE_LEN);
  crypto.getRandomValues(nonce);
  const ciphertext = aesGcmEncrypt(key, nonce, plaintext, aad);
  const blob = new Uint8Array(PUBLIC_KEY_LEN + NONCE_LEN + ciphertext.length);
  blob.set(hexToBytes(publicHex), 0);
  blob.set(nonce, PUBLIC_KEY_LEN);
  blob.set(ciphertext, PUBLIC_KEY_LEN + NONCE_LEN);
  return bytesToHex(blob);
}

/**
 * Decrypt an E2EE field using the recipient's private key.
 * `recipientSecret` is the 32-byte secp256k1 private key.
 */
export function decryptWithSecretKey(
  recipientSecret: Uint8Array,
  ciphertextHex: string,
  aad: Uint8Array,
): Uint8Array {
  const stripped = ciphertextHex.startsWith("0x") ? ciphertextHex.slice(2) : ciphertextHex;
  const blob = hexToBytes(stripped);
  if (blob.length < PUBLIC_KEY_LEN + NONCE_LEN + TAG_LEN) {
    throw new Error(`E2EE ciphertext too short: got ${blob.length} bytes`);
  }
  const ephPub = blob.subarray(0, PUBLIC_KEY_LEN);
  const nonce = blob.subarray(PUBLIC_KEY_LEN, PUBLIC_KEY_LEN + NONCE_LEN);
  const ciphertext = blob.subarray(PUBLIC_KEY_LEN + NONCE_LEN);
  const shared = getSharedSecret(recipientSecret, ephPub, false);
  const sharedX = shared.subarray(1, 33);
  const key = hkdfSha256(sharedX, HKDF_INFO, 32);
  return aesGcmDecrypt(key, nonce, ciphertext, aad);
}

// ----------------------------------------------------------------------------
// Receipt signature verification (ecdsa-secp256k1 recovery)
// ----------------------------------------------------------------------------

/**
 * Verify an ACI receipt signature per §9.4.
 * @param receiptPublicKeyHex 65-byte uncompressed secp256k1 public key hex
 *   from attestation.workload_keyset.receipt_signing_keys[].public_key
 * @param canonicalBytes JCS bytes of the receipt with signature.value omitted
 * @param signature 65-byte r||s||v
 */
export function verifyReceiptSignature(
  receiptPublicKeyHex: string,
  canonicalBytes: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (signature.length !== 65) return false;
  const expectedPub = normalizeSecp256k1PublicKeyHex(receiptPublicKeyHex);
  let v = signature[64];
  if (v >= 27 && v <= 30) v -= 27;
  if (v > 3) return false;
  const r = signature.subarray(0, 32);
  const s = signature.subarray(32, 64);
  const prehash = nobleSha256(canonicalBytes);
  // Convert gateway r||s||v into noble's recovered signature format v||r||s.
  const recoveredSig = new Uint8Array(65);
  recoveredSig[0] = v;
  recoveredSig.set(r, 1);
  recoveredSig.set(s, 33);
  let recovered: Uint8Array | null = null;
  try {
    // Gateway signs sha256(canonical_bytes); tell noble the message is already hashed.
    recovered = recoverPublicKey(recoveredSig, prehash, { prehash: false } as never);
  } catch {
    return false;
  }
  // noble returns a compressed 33-byte point by default; normalize to 65-byte uncompressed.
  const recoveredFull = Point.fromBytes(recovered).toBytes(false);
  return bytesToHex(recoveredFull) === expectedPub;
}

// ----------------------------------------------------------------------------
// Hash helpers
// ----------------------------------------------------------------------------

/** `"sha256:" + hex(sha256(payload))`. Matches gateway `sha256_hex`. */
export function sha256Hex(payload: Uint8Array): string {
  return `sha256:${bytesToHex(nobleSha256(payload))}`;
}
