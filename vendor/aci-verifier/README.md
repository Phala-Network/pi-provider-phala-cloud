# @phala/aci-verifier (vendored build)

This directory is a **build artifact** of
[`clients/verifier-ts`](https://github.com/Dstack-TEE/private-ai-gateway/tree/main/clients/verifier-ts)
from the private-ai-gateway monorepo (single source of truth).

- Do not edit here. Changes belong in the SoT repo; re-run the pack script.
- `prepare` / TypeScript sources are intentionally omitted so
  `npm install --omit=dev` (as pi does on git install) does not try to build.
- Runtime dependency: `@phala/dcap-qvl` (resolved from this package's
  `dependencies` into the artifact root `node_modules`).
