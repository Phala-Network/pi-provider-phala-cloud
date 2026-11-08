# Spike: migrate the kernel onto `@phala/aci-verifier` (npm, maintained)

Date: 2026-11-08
Branch: `feat/aci-verifier-runtime`
Status: **validated — ready for integration, two product decisions needed**

## Why

`origin/main` is a legacy artifact: it vendors `@phala/aci-verifier@0.1.0`
(ten releases behind) and hand-rolls `core/src/tls-pinning.ts` on a direct
`undici` 8 dependency — the exact code path that sat on 21 advisories until
PR #2 bumped it to 8.12.4. Upstream (`clients/verifier-ts` in
private-ai-gateway) maintains all of this as the public npm package
`@phala/aci-verifier` (0.11.0, ~2.9k lines, deps: `@phala/dcap-qql ^0.7.0`,
`undici 7.30.1` — both outside every advisory range).

## What `connectAci()` already provides

`@phala/aci-verifier/runtime` exports one call:

```ts
connectAci({ baseURL, policy?, serving?, pccsUrl?, bootstrapFetch?, proxy?, ca?, timeoutMs? })
  → AciConnection {
      identity: VerifiedAciIdentity {  // full §9.1 transcript, quote verified
        report, keyset, workloadKeysetDigest, composeHash,
        tlsSpkiPins, verifiedAt, expiresAt, transcript
      },
      fetch,            // pinned inference transport (fail-closed)
      receipts(),       // recorded receipt-bearing exchanges
      verifyReceipt(id?), refresh(), close()
    }
```

This subsumes the artifact's kernel modules:

| artifact module | connectAci equivalent |
| --- | --- |
| `core/src/tls-pinning.ts` (hand-rolled pin map, Agent/ProxyAgent, global fetch wrapper) | `connection.fetch` over an internal pinned transport (SPKI + proxy + CA), fail-closed |
| `core/src/aci-client.ts` (fetch report, `verifyReportBinding`, nonce) | bootstrap fetch + full §9.1 transcript incl. hardware quote via dcap-qvl |
| `core/src/attestation-store.ts` (established keyset, staleness) | `identity.keyset`, `verifiedAt`/`expiresAt`, `refresh()` |
| — (not shipped: receipts) | `receipts()` + `verifyReceipt()` audit trail |

## Spike evidence

1. **Type compat 0.1.0 → 0.11.0 is near-total.** Diff of the vendored vs
   npm `types.d.ts`/`report.d.ts`: only additive optional fields
   (`supported_multipart_constraint_endpoints`, `composeHash`). Everything
   `aci-client.ts` uses (`verifyReportBinding(report, nonce)`, `AciError`,
   `AttestationReport`, `WorkloadKeyset`, `TlsKeyPin`,
   `ReportVerification{ok,checks,workloadKeysetDigest,keyset}`) is unchanged.
2. **Runtime behavior** (local TLS server spike):
   - No CA → clean `AciConnectionError('attestation_fetch')` (TLS-layer
     failure surfaces as a typed code, no unhandled rejections).
   - CA + `bootstrapFetch` → request reaches the server; non-ACI body →
     `AciConnectionError('attestation_verification')` with a readable cause.
   - Exports map resolves `./runtime` correctly under Node 26.
3. **Rotation is handled properly.** `refresh()` re-fetches the attestation,
   builds a *candidate* pinned transport with the new `identity.tlsSpkiPins`,
   and swaps it in only on success — strictly better than the artifact's
   "mutable pin map read per handshake" (which can pin/unpin mid-session
   against a report whose binding was never re-verified).

## Behavior differences the integration MUST decide

1. **Hardware quote verification is new.** The artifact only ran
   `verifyReportBinding` (keyset digest + nonce + expiry) — it never
   verified the TDX quote. `connectAci` always verifies the quote via
   `@phala/dcap-qql` against the Phala PCCS (runtime network dependency +
   latency, fail-closed). This is a security upgrade, but it is a behavior
   change and needs sign-off.
2. **Serving enforcement is new.** `serving` defaults demand
   `provider.aci_verified` on POSTs and receipts on success
   (`requireReceipt: true`). The artifact deliberately ships no receipt
   audit ("removed on request"). To preserve current behavior pass
   `serving: { requireReceipt: false, requireVerified: false }`; to turn on
   the audit, wire `receipts()`/`verifyReceipt()` into the existing
   `/phala-receipt` surface instead.
3. **Fetch injection point.** `connection.fetch` can either (a) back the
   existing `globalThis.fetch` wrapper (smallest diff, keeps pi's global
   dispatcher untouched for other hosts), or (b) be passed via
   `streamSimple`'s `options.fetch` (no global mutation at all — the old
   E2EE kernel's approach). Recommend (b) with (a) as fallback if pi builds
   some requests without going through the provider's stream options.

## Proposed integration shape

- Delete `vendor/aci-verifier/` and `core/src/tls-pinning.ts`,
  `aci-client.ts`, `attestation-store.ts`.
- `core/src/aci-connection.ts` (new): owns one `AciConnection` per session;
  exposes `pinningStatus()` for the footer (`pinned/unpinned/blocked`).
- `core/index.ts`: replace `installAttestedTlsPin` with `connectAci` +
  policy config; map `config.pinning.enabled` and
  `config.verify.failOpenOnUnpinned` onto connection failure posture.
- `undici` direct dependency disappears from package.json (the verifier
  brings its own 7.30.1); PR #2's bump becomes moot but harmless.
- Keep `verifyReportBinding` re-export (now from the npm package) for
  consumers.
