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

## Auth

This brand supports **OAuth device login** via pi's `/login phala`
(in addition to `PHALA_LLM_API_KEY`).

OAuth code lives in this repo's brand `index.ts` (maintained in SoT under
`clients/pi-provider/packages/pi-provider-phala-cloud/`).

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
