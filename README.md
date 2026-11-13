# pi-provider-phala-cloud

Phala Cloud Confidential AI for Pi — attested TLS (SPKI) pinning (prevention)

This repository is a **release artifact** for [pi](https://pi.dev) (`pi-coding-agent`).
It is generated from the single source of truth (SoT):

**https://github.com/Dstack-TEE/private-ai-gateway**

Security control is **attested TLS (SPKI) pinning** (prevention). There is
no field-level E2EE and no automatic per-response receipt verification.
On-demand `/aci-receipt` / `/aci-session` only fetch/summarize; crypto
audit belongs in SoT `clients/verifier-ts`.

Do not treat this repo as the place to change protocol/kernel/verifier logic.
See [Maintenance](#maintenance) below.

## Install

### One-shot try (from a clone)

```bash
git clone https://github.com/Phala-Network/pi-provider-phala-cloud
cd pi-provider-phala-cloud
npm install --omit=dev --legacy-peer-deps
pi -e .
```

`npm install` is required once so that runtime deps (`@phala/aci-verifier`,
which carries `@phala/dcap-qvl` and its pinned `undici`) are fetched from
npm. The attestation/pinning kernel is the published, maintained
`@phala/aci-verifier` package — it is no longer vendored into this repo.

pi loads the extension with jiti; bare imports resolve through this package's
`node_modules`. Peer packages (`@earendil-works/pi-*`) are provided by pi itself.

### Persistent install

```bash
pi install git:github.com/Phala-Network/pi-provider-phala-cloud
# optional pin:
# pi install git:github.com/Phala-Network/pi-provider-phala-cloud@<tag-or-sha>
```

pi clones this repo and runs `npm install --omit=dev` automatically.

## Use

```bash
# API key (both brands)
export PHALA_LLM_API_KEY=...
# optional base URL override
# export PHALA_BASE_URL=https://...

pi -e .          # from this directory after npm install
# then: /model phala/<model-id>
```

The model catalog is fetched from the gateway at load and re-fetched on
every session start; opening `/phala-settings` also refreshes it. The
settings page shows the credential state, the registered chat/decision
model counts, and whether the live catalog or the fallback is in use.

### Usage & billing in `/phala-settings`

The settings page can show **today's usage** (requests, tokens, spend) and
the **workspace balance**, and includes a **Billing dashboard** menu item
that opens the console billing page in your browser.

These come from the Phala Cloud console API, which does **not** accept the
inference (`sk-...`) key. Create a workspace API token at
[cloud.phala.com](https://cloud.phala.com) → Settings → API Keys, then expose
it either way:

```bash
export PHALA_CLOUD_API_KEY=...
# or in ~/.pi/providers/phala/config.json:
# { "billing": { "apiKey": "..." } }
```

Without the token the panel degrades to a hint line; the Billing dashboard
item still opens `https://cloud.phala.com/cost` (deep link
`/<workspace-slug>/billing` once the token is set). Data is fetched once
when the panel opens and cached for 60s (matching the server-side cache);
granted/promotional credits are shown separately since they cannot pay for
Private AI inference.

## Auth

This brand supports **OAuth device login** via pi's `/login phala`
(in addition to `PHALA_LLM_API_KEY`).

OAuth code lives in this repo's brand `index.ts` (maintained in SoT under
`clients/pi-provider/packages/pi-provider-phala-cloud/`).

## Config

Layered config (`~/.pi/providers/phala/config.json`, project
`.pi/providers/phala/config.json`, env, runtime) supports `baseUrl`,
`models.isTeeOnly`, `models.thinkingFormat`, `models.allowlist`,
`models.defaultModel`, `verify.failOpenOnUnpinned`, `pinning.enabled`
and `billing.apiKey`.

`models.overrides` patches per-model compatibility on top of the builtin
quirk table in `core/src/models.ts` (keyed by catalog model id; merged
key-by-key):

```json
{
  "models": {
    "overrides": {
      "some/model-id": {
        "supportsDeveloperRole": false,
        "maxTokens": 8192,
        "thinkingLevelMap": { "off": null, "minimal": "low", "xhigh": "high", "max": "high" }
      }
    }
  }
}
```

Builtins currently record: five qwen3.x upstreams reject the `developer`
message role, and `openai/gpt-oss-120b` (Harmony) accepts only
low/medium/high `reasoning_effort`. Both verified live against
inference.phala.com (2026-11).

Catalog entries are routed by `output_modalities`: chat models register as
chat, `decisions` models (e.g. `jaredpalmer/kev-4b`) register as pi
classifier models served via the System One protocol (`POST /v1/systemone`),
and embeddings/transcription/image entries are excluded (no matching pi API
behind this gateway).

## Layout

```
index.ts                 brand entry (provider id, defaults, optional OAuth)
core/                    vendor-neutral ACI kernel (attestation + pinned fetch)
package.json             pi.extensions + @phala/aci-verifier npm dependency
SOURCE.json              SoT commit / versions recorded at pack time
```

> Upstream note: private-ai-gateway retired its pi-provider product line in
> favor of `pap`; this repo survives as the maintained Pi extension by
> consuming the still-maintained `@phala/aci-verifier` npm package directly
> (previously vendored from SoT `clients/verifier-ts`).

## Maintenance

| Path in this repo | Owned by | How to change |
|---|---|---|
| `core/**` | this repo (was SoT `clients/pi-provider/packages/pi-provider-aci`, now retired there) | PR here |
| `@phala/aci-verifier` | SoT `clients/verifier-ts`, published to npm | bump the npm dependency |
| `index.ts` (brand skin) | this repo (was SoT brand package, now retired there) | PR here |

`@phala/aci-verifier` **is** published to npm; this repo pins it like any
other dependency (`npm run check` typechecks the kernel against pi ^1.5).

## Version

Artifact version: `0.2.0`  
Kernel / verifier versions are recorded in `SOURCE.json`.

## License

MIT (kernel + brand). Vendored verifier retains its upstream license notice
(Apache-2.0); see SoT `clients/verifier-ts`.
