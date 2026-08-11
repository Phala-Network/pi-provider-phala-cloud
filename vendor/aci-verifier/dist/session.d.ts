/**
 * Attested-session helpers (§8, §9.3). A session is content-addressed: its id
 * is the SHA-256 of the exact served document bytes, and the signed receipt
 * commits to that id — there is no session signature.
 */
import type { SessionRecord, SessionEvidence } from './types.js';
/** `session_id` (§8): bare 64-hex sha256 of the JCS form of the parsed document. */
export declare function computeSessionId(record: unknown): Promise<string>;
/** Appendix B: reject session documents whose `api_version` is not `aci/1`. */
export declare function checkSessionApiVersion(record: Pick<SessionRecord, 'api_version'>): boolean;
/**
 * §9.2(2): `evidence.data` decodes and hashes to `evidence.digest`.
 * Returns false when the data URI is absent, malformed, or does not hash.
 */
export declare function checkSessionEvidence(evidence: SessionEvidence): Promise<boolean>;
//# sourceMappingURL=session.d.ts.map