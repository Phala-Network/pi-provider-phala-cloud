/**
 * Report binding checks a verifier can run with pure Web Crypto — §9.1 check 2
 * (binding and freshness: keyset bytes → digest → statement → `report_data`)
 * and check 3 (expiry), plus the aci/1 protocol gate. Check 1 (the hardware
 * quote verifies to the vendor root and binds `report_data`) is done by
 * {@link verifyQuote} via @phala/dcap-qvl; checks 5–6 (custody, channel) stay
 * policy / caller territory.
 */
import type { AttestationReport, Check, ReportVerification } from './types.js';
/** Options for {@link verifyReportBinding}. */
export interface ReportBindingOptions {
    /**
     * Current time in Unix seconds for the expiry check (§9.1 check 3).
     * Defaults to the local clock; pass an explicit value for deterministic tests.
     */
    now?: number;
}
/**
 * Verify the report's cryptographic bindings for `nonce` — the value this
 * client sent to `GET /v1/aci/attestation`, or `null`/`undefined` when it sent
 * none (§3.2). One recomputation establishes that the keyset is exactly what
 * the quote bound and that the quote postdates the challenge (§9.1 check 2).
 *
 * Returns per-check results plus the established keyset (digest, exact bytes,
 * parsed form); a failed check on the served report is `ok: false`, never
 * thrown. The one exception is the caller's own input: a nonce that is not
 * 64 lowercase hex throws {@link AciFormatError} (§3.2).
 */
export declare function verifyReportBinding(report: AttestationReport, nonce: string | null | undefined, options?: ReportBindingOptions): Promise<ReportVerification>;
/**
 * §9.1 check 4 (dstack policy): the booted docker-compose is the one measured
 * into the report's stated RTMR3. Replays `evidence.event_log` to RTMR3 (SHA-384
 * chain over each `imr==3` digest from a 48-byte-zero start), checks it equals
 * the RTMR3 the raw TDX quote states, then checks `sha256(app_compose)` equals
 * the measured `compose-hash`. Proves the compose against the quote's *stated*
 * RTMR3 only — a genuine, TCB-current quote needs a quote verifier (dcap-qvl.js /
 * the `aci` CLI), and whether the compose is acceptable is caller policy. Throws
 * {@link AciFormatError} only for malformed evidence, never for a failed check.
 */
export declare function verifyComposeMeasurement(report: AttestationReport): Promise<{
    ok: boolean;
    checks: Check[];
}>;
/**
 * §9.1 check 1 (id-1): verify the TDX quote to the Intel vendor root with
 * @phala/dcap-qvl — it fetches collateral from the default Phala PCCS (override
 * with `pccsUrl`) — then confirm the verified quote's report_data equals the
 * report's `report_data` zero-padded to 64 bytes (§3.2). The platform TCB
 * status is reported, never gated on: §9.1(1) does not require it, and §8.3
 * treats freshness as a claim for policy. A pass here makes the RTMR3 that {@link verifyComposeMeasurement}
 * replays against authentic, so the two together prove genuine TEE + which code.
 * Returns a result, never throws for a failed quote (only the fetch/parse can).
 */
export declare function verifyQuote(report: AttestationReport, pccsUrl?: string): Promise<{
    ok: boolean;
    status?: string;
    detail?: string;
}>;
//# sourceMappingURL=report.d.ts.map