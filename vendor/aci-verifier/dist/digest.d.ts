/**
 * The ACI digest constructions (Appendix A, §3.1, §3.2). Artifacts the service builds
 * are hashed as the exact served bytes; the attestation statement is the one
 * report payload a verifier constructs itself, as a fixed byte template whose
 * inputs are restricted so no JSON escaping is ever needed.
 */
/** `workload_keyset_digest` (§3.1): sha256 over the keyset's JCS form. */
export declare function computeKeysetDigest(keyset: unknown): Promise<string>;
/**
 * The exact attestation-statement bytes (§3.2) for a keyset digest and the
 * nonce the client sent — `null`/`undefined` when the query parameter was
 * omitted, which puts the JSON literal `null` in the template. Inputs outside
 * the spec-pinned formats throw {@link AciFormatError}.
 */
export declare function attestationStatement(keysetDigest: string, nonce: string | null | undefined): Uint8Array;
/**
 * `report_data` (§3.2): SHA-256 of the attestation statement, as bare lowercase
 * hex (it fills a report-data slot, not an ACI digest string). The TEE places
 * these 32 bytes zero-padded to 64 in the quote's report-data field.
 */
export declare function computeReportData(keysetDigest: string, nonce: string | null | undefined): Promise<string>;
//# sourceMappingURL=digest.d.ts.map