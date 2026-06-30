// In-memory store for the last response's receipt metadata, a cached attestation
// report (with freshness), and the verified classification. The footer status
// is derived from this store.

import { randomBytes } from "node:crypto";

import type { PhalaCloudConfig } from "./config.ts";
import {
  ATTESTATION_FALLBACK_TTL_MS,
  HEADER_ACI_IDENTITY,
  HEADER_ACI_KEYSET_DIGEST,
  HEADER_RECEIPT_ID,
} from "./constants.ts";
import {
  type AttestationReport,
  type Receipt,
  type ReceiptClassification,
  type ReportBindingResult,
  attestationStaleAfter,
  fetchAttestation,
  fetchReceipt,
  validateAciReportBinding,
  verifyReceipt,
} from "./verify.ts";

export interface ResponseHeaderSnapshot {
  receiptId?: string;
  aciIdentity?: string;
  keysetDigest?: string;
}

export class PhalaReceiptStore {
  private lastReceiptId?: string;
  private lastAciIdentity?: string;
  private lastKeysetDigest?: string;
  private lastClassification?: ReceiptClassification;
  private lastNonce?: string;
  private _lastAttestationError?: string;
  private cachedAttestation?: {
    report: AttestationReport;
    binding: ReportBindingResult;
    fetchedAt: number;
  };

  recordResponseHeaders(headers: Record<string, string>): ResponseHeaderSnapshot {
    const lower = lowerHeaders(headers);
    this.lastReceiptId = lower[HEADER_RECEIPT_ID] ?? lower["x-receipt-id"];
    this.lastAciIdentity = lower[HEADER_ACI_IDENTITY] ?? lower["x-aci-identity"];
    this.lastKeysetDigest = lower[HEADER_ACI_KEYSET_DIGEST] ?? lower["x-aci-keyset-digest"];
    this.lastClassification = undefined;
    return this.snapshot();
  }

  snapshot(): ResponseHeaderSnapshot {
    return {
      receiptId: this.lastReceiptId,
      aciIdentity: this.lastAciIdentity,
      keysetDigest: this.lastKeysetDigest,
    };
  }

  get classification(): ReceiptClassification | undefined {
    return this.lastClassification;
  }

  /** Remember the nonce used for the attestation fetch so it can be reused at
   *  binding-validation time (the report_data is nonce-bound). */
  setAttestationNonce(nonce: string): void {
    this.lastNonce = nonce;
  }

  /** Stash the last request body bytes for request.received.body_hash verification. */
  setLastRequestBody(bytes: Uint8Array): void {
    this.lastRequestBody = bytes;
  }
  private lastRequestBody?: Uint8Array;

  get lastAttestationError(): string | undefined {
    return this._lastAttestationError;
  }

  async getAttestation(
    apiKey: string,
    config: PhalaCloudConfig,
  ): Promise<{ report: AttestationReport; binding: ReportBindingResult } | null> {
    const now = Date.now();
    if (this.cachedAttestation && this.isFresh(this.cachedAttestation, now)) {
      return { report: this.cachedAttestation.report, binding: this.cachedAttestation.binding };
    }

    const nonce = randomBytes(16).toString("hex");
    this.lastNonce = nonce;
    const report = await fetchAttestation(apiKey, nonce, { baseUrl: config.baseUrl });
    if (!report) return null;
    try {
      const binding = validateAciReportBinding(report, nonce, Math.floor(now / 1000));
      this._lastAttestationError = undefined;
      this.cachedAttestation = { report, binding, fetchedAt: now };
      return { report, binding };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this._lastAttestationError = message;
      console.error("[phala-cloud] attestation report binding failed:", error);
      return null;
    }
  }

  private isFresh(
    cached: { report: AttestationReport; binding: ReportBindingResult; fetchedAt: number },
    now: number,
  ): boolean {
    const staleAfter = attestationStaleAfter(cached.report);
    if (typeof staleAfter === "bigint") {
      return staleAfter * 1000n > BigInt(now);
    }
    return now - cached.fetchedAt < ATTESTATION_FALLBACK_TTL_MS;
  }

  /** Fetch the receipt for the last response and run full verification against a
   *  cached attestation. Stores the classification for footer rendering. */
  async classifyLastResponse(
    apiKey: string,
    config: PhalaCloudConfig,
    _options: { requestBody?: Uint8Array } = {},
  ): Promise<ReceiptClassification | null> {
    if (!this.lastReceiptId) return null;

    const receipt: Receipt | null = await fetchReceipt(apiKey, this.lastReceiptId, {
      baseUrl: config.baseUrl,
    });
    if (!receipt) return null;

    let classification: ReceiptClassification;
    const attested = await this.getAttestation(apiKey, config);
    if (attested) {
      classification = verifyReceipt(receipt, attested.binding, attested.report, {
        requestBody: this.lastRequestBody,
      });
    } else {
      // No attestation available (network failure, key missing): fall back to
      // semantic classification only, with verification fields unset.
      const basic = classifyBasic(receipt);
      classification = basic;
    }

    this.lastClassification = classification;
    return classification;
  }

  reset(): void {
    this.lastReceiptId = undefined;
    this.lastAciIdentity = undefined;
    this.lastKeysetDigest = undefined;
    this.lastClassification = undefined;
    this.cachedAttestation = undefined;
    this.lastNonce = undefined;
    this._lastAttestationError = undefined;
  }
}

// Re-imported to avoid a circular-feeling top import; classifyReceipt lives in
// verify.ts but we want a basic-only variant here that does not require the
// full verify path.
import { classifyReceipt as classifyBasic } from "./verify.ts";

function lowerHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    out[key.toLowerCase()] = value;
  }
  return out;
}

