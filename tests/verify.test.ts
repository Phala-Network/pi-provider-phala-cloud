import assert from "node:assert/strict";
import { test } from "node:test";

import {
  type Receipt,
  type AttestationReport,
  classifyReceipt,
  verifyReceipt,
  type ReportBindingResult,
} from "../src/verify.ts";

test("classifyReceipt: verified when result=verified and required=true", () => {
  const receipt: Receipt = {
    workload_id: "sha256:aaa",
    workload_keyset_digest: "sha256:bbb",
    event_log: [
      { type: "upstream.verified", result: "verified", required: true, session_id: "as_1", provider: "phala", model_id: "phala/qwen3.5-27b" },
    ],
  };
  const c = classifyReceipt(receipt);
  assert.equal(c.status, "verified");
  assert.equal(c.sessionId, "as_1");
  assert.equal(c.provider, "phala");
  assert.equal(c.required, true);
  assert.equal(c.workloadId, "sha256:aaa");
});

test("classifyReceipt: routed when result=failed and required=false", () => {
  const receipt: Receipt = {
    workload_id: "sha256:aaa",
    workload_keyset_digest: "sha256:bbb",
    event_log: [
      { type: "upstream.verified", result: "failed", required: false, provider: "openai" },
    ],
  };
  const c = classifyReceipt(receipt);
  assert.equal(c.status, "routed");
  assert.equal(c.required, false);
  assert.equal(c.sessionId, undefined);
});

test("classifyReceipt: unknown when upstream.verified event is missing", () => {
  const receipt: Receipt = {
    workload_id: "sha256:aaa",
    workload_keyset_digest: "sha256:bbb",
    event_log: [{ type: "request.received" }, { type: "response.returned" }],
  };
  const c = classifyReceipt(receipt);
  assert.equal(c.status, "unknown");
});

test("classifyReceipt: unknown when result/required do not match either pattern", () => {
  const receipt: Receipt = {
    event_log: [{ type: "upstream.verified", result: "verified", required: false }],
  };
  const c = classifyReceipt(receipt);
  assert.equal(c.status, "unknown");
});

test("verifyReceipt: workload match true when both workload_id and keyset_digest match", () => {
  const receipt: Receipt = {
    workload_id: "sha256:aaa",
    workload_keyset_digest: "sha256:bbb",
    event_log: [],
  };
  const binding: ReportBindingResult = {
    workloadId: "sha256:aaa",
    workloadKeysetDigest: "sha256:bbb",
    reportData: new Uint8Array(32),
  };
  const attestation: AttestationReport = { attestation: { workload_keyset: {} } };
  const result = verifyReceipt(receipt, binding, attestation);
  assert.equal(result.workloadMatched, true);
});

test("verifyReceipt: workload match false when keyset_digest differs", () => {
  const receipt: Receipt = {
    workload_id: "sha256:aaa",
    workload_keyset_digest: "sha256:bbb",
    event_log: [],
  };
  const binding: ReportBindingResult = {
    workloadId: "sha256:aaa",
    workloadKeysetDigest: "sha256:ccc",
    reportData: new Uint8Array(32),
  };
  const attestation: AttestationReport = { attestation: { workload_keyset: {} } };
  const result = verifyReceipt(receipt, binding, attestation);
  assert.equal(result.workloadMatched, false);
});

test("verifyReceipt: workload match false when fields are missing", () => {
  const receipt: Receipt = { event_log: [] };
  const binding: ReportBindingResult = {
    workloadId: "sha256:aaa",
    workloadKeysetDigest: "sha256:bbb",
    reportData: new Uint8Array(32),
  };
  const attestation: AttestationReport = { attestation: { workload_keyset: {} } };
  const result = verifyReceipt(receipt, binding, attestation);
  assert.equal(result.workloadMatched, false);
});
