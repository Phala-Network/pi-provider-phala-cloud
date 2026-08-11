/**
 * Receipt verification (§7, §9.3). A receipt is one JSON document; its
 * `signature` is Ed25519 over JCS(document minus `signature`) under a key
 * the established keyset lists. "Established" means a keyset whose digest
 * the caller verified — through {@link verifyReportBinding}, or published
 * by a party the client trusts (§9.3).
 */
import type { ReceiptEnvelope, ReceiptEvent, ReceiptPayload, ReceiptVerification, WorkloadKeyset } from './types.js';
/**
 * §9.3 checks 1–2: the `signature` member verifies over JCS(document minus
 * `signature`) under the keyset entry `key_id` names, and the document's
 * `workload_keyset_digest` equals the established digest. Documents whose
 * `api_version` is not `aci/1` are rejected (Appendix B).
 *
 * Returns per-check results plus the document for the body-hash checks; a
 * failed check is `ok: false`, never thrown.
 */
export declare function verifyReceipt(document: ReceiptEnvelope, keyset: WorkloadKeyset, establishedDigest: string): Promise<ReceiptVerification>;
/** Find the first event of a given type in a receipt payload's event log. */
export declare function findEvent(payload: ReceiptPayload, type: string): ReceiptEvent | undefined;
/**
 * `sha256:<hex>` of raw body bytes — the form ACI body hashes use (Appendix A). Accepts
 * a string (UTF-8 encoded) or raw bytes.
 */
export declare function hashBody(body: Uint8Array | string): Promise<string>;
/**
 * §9.3 check 3: `request.received.body_hash` matches the request bytes this
 * client sent — the wire body for plaintext, the original body it sealed for
 * E2EE (§7.4). Returns false when the event or its hash is absent.
 */
export declare function checkRequestBodyHash(payload: ReceiptPayload, requestBody: Uint8Array | string): Promise<boolean>;
/**
 * §9.3 check 4: `response.returned.body_hash` matches the response bytes this
 * client received off the wire — the in-order raw SSE bytes for a stream, the
 * sealed envelope bytes for E2EE (§7.4). Returns false when the event or its
 * hash is absent.
 */
export declare function checkResponseBodyHash(payload: ReceiptPayload, responseBody: Uint8Array | string): Promise<boolean>;
//# sourceMappingURL=receipt.d.ts.map