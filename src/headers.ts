// Request header builder and E2EE header injection. When E2EE is enabled,
// this emits the X-E2EE-* / X-Client-Pub-Key / X-Model-Pub-Key headers the
// gateway requires, and the request payload is field-encrypted by the
// onPayload hook in index.ts (see src/e2ee.ts encryptRequestPayload).
//
// Header set (ACI E2EE v2):
//   X-E2EE-Version: 2
//   X-Client-Pub-Key: <client secp256k1 public key, hex>
//   X-Model-Pub-Key:  <gateway E2EE public key, hex, from attestation keyset>
//   X-E2EE-Nonce:     <unique per-request nonce>
//   X-E2EE-Timestamp: <unix seconds, close to gateway time>
// Do NOT send X-Signing-Algo (that selects the legacy signature path).

import { randomBytes } from "node:crypto";
import { getPublicKey } from "@noble/secp256k1";
import { bytesToHex } from "@noble/hashes/utils.js";

import type { PhalaCloudConfig } from "./config.ts";

export interface E2eeHeaderMaterial {
  clientSecret: Uint8Array;
  clientPublicKeyHex: string;
  modelPublicKeyHex: string;
  nonce: string;
  timestamp: number;
}

/**
 * Build the E2EE request headers. Returns an empty record when E2EE is
 * disabled. The client keypair is ephemeral per request; the private half
 * (E2eeHeaderMaterial.clientSecret) decrypts the response fields the gateway
 * encrypts to X-Client-Pub-Key.
 */
export function buildPhalaHeaders(
  config: PhalaCloudConfig,
  e2ee?: E2eeHeaderMaterial,
): Record<string, string> {
  if (!config.e2ee.enabled || !e2ee) return {};
  return {
    "X-E2EE-Version": "2",
    "X-Client-Pub-Key": e2ee.clientPublicKeyHex,
    "X-Model-Pub-Key": e2ee.modelPublicKeyHex,
    "X-E2EE-Nonce": e2ee.nonce,
    "X-E2EE-Timestamp": String(e2ee.timestamp),
  };
}

/** Generate ephemeral E2EE material for one request. */
export function generateE2eeMaterial(modelPublicKeyHex: string): E2eeHeaderMaterial {
  const clientSecret = randomBytes(32);
  const clientPublicKeyHex = bytesToHex(getPublicKey(clientSecret, false));
  // ACI v2 (spec §7.5): 32 random bytes, hex-encoded as 64 characters.
  const nonce = randomBytes(32).toString("hex");
  const timestamp = Math.floor(Date.now() / 1000);
  return { clientSecret, clientPublicKeyHex, modelPublicKeyHex, nonce, timestamp };
}
