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

`npm install` is required once so that:

- `file:./vendor/aci-verifier` is linked into `node_modules/@phala/aci-verifier`
- runtime deps (`undici`, `@phala/dcap-qvl`) are fetched from npm

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

## Auth

This brand supports **OAuth device login** via pi's `/login phala`
(in addition to `PHALA_LLM_API_KEY`).

OAuth code lives in this repo's brand `index.ts` (maintained in SoT under
`clients/pi-provider/packages/pi-provider-phala-cloud/`).

## Layout

```
index.ts                 brand entry (provider id, defaults, optional OAuth)
core/                    vendor-neutral ACI kernel (from SoT pi-provider-aci)
vendor/aci-verifier/     built reference verifier (from SoT clients/verifier-ts)
package.json             pi.extensions + file:./vendor/aci-verifier
SOURCE.json              SoT commit / versions recorded at pack time
```

## Maintenance

| Path in this repo | Owned by | How to change |
|---|---|---|
| `core/**` | SoT `clients/pi-provider/packages/pi-provider-aci` | Edit SoT, re-pack, push artifact |
| `vendor/aci-verifier/**` | SoT `clients/verifier-ts` (build output only) | Edit SoT verifier, re-pack, push |
| `index.ts` (brand skin) | SoT `clients/pi-provider/packages/pi-provider-phala-cloud` | Edit SoT brand package, re-pack |
| Brand-only experiments | optional local `brand/` (not generated today) | Fork / PR to SoT if it should ship |

Pack command in SoT:

```bash
# from private-ai-gateway
node clients/pi-provider/scripts/pack-brand.mjs \
  --brand phala-cloud \
  --out /path/to/pi-provider-phala-cloud
```

`@phala/aci-verifier` is **not** published to npm. Consumers only see the
vendored build inside this artifact (or the other brand artifact).

## Version

Artifact version: `0.2.0`  
Kernel / verifier versions are recorded in `SOURCE.json`.

## License

MIT (kernel + brand). Vendored verifier retains its upstream license notice
(Apache-2.0); see SoT `clients/verifier-ts`.
