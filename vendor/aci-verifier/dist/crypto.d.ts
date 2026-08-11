/**
 * Cryptographic primitives, all via the Web Crypto API (`globalThis.crypto`) so
 * the same code runs in browsers and in Node 20+ with no dependencies. ACI's
 * only signature algorithm is Ed25519 and its only hash is SHA-256 (spec
 * Appendix B) — both are in Web Crypto, so nothing needs injecting.
 */
/** Lowercase-hex encode bytes. */
export declare function toHex(bytes: Uint8Array): string;
/** Decode hex (optionally `0x`-prefixed) to bytes. */
export declare function fromHex(hex: string): Uint8Array;
/** Encode bytes as standard base64 (RFC 4648 §4, with padding) — the `_b64` field form (Appendix A). */
export declare function toBase64(bytes: Uint8Array): string;
/** Decode standard base64 to the exact underlying bytes. */
export declare function fromBase64(b64: string): Uint8Array;
/** SHA-256 of the given bytes. */
/**
 * JCS (RFC 8785) bytes of a parsed JSON value under the ACI artifact
 * constraints (ASCII member names, integer numbers): compact serialization
 * with sorted member names (§7.2, §8).
 */
export declare function jcsBytes(value: unknown): Uint8Array;
export declare function sha256(bytes: Uint8Array): Promise<Uint8Array>;
/** SHA-384 of the given bytes — the dstack RTMR replay hash (§9.1 policy). */
export declare function sha384(bytes: Uint8Array): Promise<Uint8Array>;
/** Lowercase-hex SHA-256 of the given bytes. */
export declare function sha256Hex(bytes: Uint8Array): Promise<string>;
/**
 * `sha256:<lowercase-hex>` digest string of the given bytes — the ACI digest
 * form (Appendix A) used for keyset digests, body hashes, and session ids.
 */
export declare function sha256Prefixed(bytes: Uint8Array): Promise<string>;
/**
 * Verify an Ed25519 signature (RFC 8032) over `message`. `publicKeyRaw` is the
 * 32-byte raw key; `signature` the 64-byte value. Returns false on a bad
 * signature or malformed key — never throws for those.
 */
export declare function verifyEd25519(publicKeyRaw: Uint8Array, signature: Uint8Array, message: Uint8Array): Promise<boolean>;
//# sourceMappingURL=crypto.d.ts.map