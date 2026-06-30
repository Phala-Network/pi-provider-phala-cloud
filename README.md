# Pi extension for Phala Cloud Confidential AI

[![npm](https://img.shields.io/npm/v/pi-provider-phala-cloud)](https://www.npmjs.com/package/pi-provider-phala-cloud)
[![license](https://img.shields.io/npm/l/pi-provider-phala-cloud)](./LICENSE)

**Use Phala Cloud Confidential AI in Pi, with per-response verifiability in the footer and optional end-to-end encryption on request fields.**

Phala Cloud serves OpenAI-compatible models through an attested gateway at
`https://inference.phala.com/v1`. Every response carries signed ACI headers
(`x-receipt-id`, `x-aci-identity`, `x-aci-keyset-digest`) that let you fetch a
receipt and verify it against the gateway's attestation report. This extension
wires that into Pi: chat works like any OpenAI provider, request fields can be
encrypted to the gateway's attested E2EE key, and the footer updates to
`verified` / `routed` / `attested` / `mismatch` after each response.

## What this package adds

- **OpenAI-compatible provider** registered as `phala-cloud`, with model
discovery from `/v1/models` (no hardcoded catalog).
- **Thinking support.** Qwen3 models get `enable_thinking` via pi's built-in
openai-completions handler; streaming `reasoning_content` is surfaced as pi
thinking blocks. No custom stream handler needed.
- **`is_tee` filtering.** Only confidentially-served models are registered by
default; toggle in `/phala-cloud-settings`.
- **Footer verification.** After each response the footer shows whether the
receipt's `upstream.verified` event was `verified` (confidential upstream) or
`routed` (gateway attested but upstream not). A `verified*` suffix means the
receipt signature checks out but request/response hashes were not verified.
`mismatch` means the workload/keyset does not match the cached attestation.
- **E2EE v2.** Request fields (`messages[].content`, legacy `prompt`,
embeddings `input`) are encrypted to the gateway's secp256k1 E2EE public key
before leaving the client. The gateway decrypts inside its TEE. E2EE is enabled
by default; disable it in `/phala-cloud-settings`.
- **`/phala-cloud-settings`** to configure TEE-only filtering, thinking format,
auto-verification, and E2EE, with home and project config scope.
- **`/attestation`** to inspect the current attestation report: workload id,
keyset digest, freshness window, E2EE keys, receipt signing keys, and
validation status.

## Install

From npm:

```bash
pi install npm:pi-provider-phala-cloud
```

Or load a local checkout:

```bash
pi -e /path/to/pi-provider-phala-cloud
```

### Programmatic usage

```typescript
import { main } from "@earendil-works/pi-coding-agent";
import { PhalaCloud } from "pi-provider-phala-cloud";

main(process.argv.slice(2), {
  extensionFactories: [PhalaCloud()],
});
```

## Sign in

Phala Cloud uses API keys (no OAuth yet). Create a key in the Phala dashboard
under **Confidential AI API**, then set `PHALA_LLM_API_KEY`. This is separate
from the CVM-management credential (`PHALA_CLOUD_API_KEY` in the `@phala/cloud`
SDK); the two are not interchangeable.

```bash
PHALA_LLM_API_KEY=... pi
```

## Model

Select a model inside Pi:

```text
/model phala-cloud/phala/qwen3.5-27b
```

Model ids come from the live `/v1/models` catalog. When discovery has no API
key, a small fallback list is used.

## Thinking

For Qwen3-family models, pi's thinking level maps to `enable_thinking`:

```text
/thinking medium   # enable_thinking: true
/thinking off      # enable_thinking: false
```

Other model families default to no thinking parameter. Set the thinking format
in `/phala-cloud-settings` if you need to force `qwen`, `openai`
(`reasoning_effort`), or `off`.

## Verification and footer

Each response includes ACI headers. The extension captures them and, after the
stream finishes, fetches the receipt and classifies it:

- **verified** — `upstream.verified.result === "verified"` and `required === true`
(confidential upstream, channel-bound), and the receipt signature and workload
match the cached attestation.
- **verified\*** — receipt classified as verified but request/response hashes
were not checked (for example because the response body is not available to the
extension hook).
- **routed** — `result === "failed"`, `required === false` (gateway attested,
upstream not).
- **attested** — headers present, receipt fetch pending or unavailable.
- **mismatch** — receipt workload/keyset does not match the cached attestation.
- **(no receipt)** — no ACI headers on the response.

Disable auto-fetch in `/phala-cloud-settings` if you do not want the extension
to call `/v1/aci/receipts/{id}` after each response.

## Attestation report

Run `/attestation` to view the current attestation report:

```text
Phala Cloud attestation
API version: aci/1
Workload ID: sha256:...
Keyset digest: sha256:...
Report data: verified
Keyset endorsement: verified
Freshness: fetched_at=... stale_after=...
E2EE keys (1): dstack-kms-e2ee-v1 (secp256k1)
Receipt signing keys (1): default (ecdsa-secp256k1)
Last receipt: ...
```

If validation fails, the command prints the failure reason, including
diagnostics such as the computed and reported `workload_keyset_digest`.

## Configure

```text
/phala-cloud-settings
```

Toggle TEE-only model registration, thinking format, auto-verification, and
E2EE. Config is layered: project
(`.pi/providers/phala-cloud/config.json`, gated by project trust) overrides home
(`~/.pi/providers/phala-cloud/config.json`), which overrides defaults.
Environment variables override both:

- `PHALA_CLOUD_API_PREFIX` / `PHALA_BASE_URL` / `PHALA_CLOUD_BASE_URL` — gateway
base URL.
- `PHALA_CLOUD_IS_TEE_ONLY` — `true` / `false`.
- `PHALA_CLOUD_THINKING_FORMAT` — `auto`, `qwen`, `openai`, `off`.
- `PHALA_CLOUD_AUTO_VERIFY` — `true` / `false`.

## License

MIT
