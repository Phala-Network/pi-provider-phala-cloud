// Module-level constants and env-driven configuration shared across the
// provider's modules. Anything env-dependent read once at module load lives
// here; per-request evaluation goes in the module that needs it.

export const PROVIDER_ID = "phala-cloud";
export const PROVIDER_VERSION = "0.1.0";

export const DEFAULT_BASE_URL = "https://inference.phala.com/v1";

// API key env var. The provider registers with apiKey "$PHALA_LLM_API_KEY" so pi
// resolves it from the environment; this const is used for direct calls
// (model discovery, receipt/attestation fetch) that bypass pi's provider
// machinery.
//
// Note: Phala Cloud issues separate credentials for CVM management
// (@phala/cloud SDK uses PHALA_CLOUD_API_KEY) and Confidential AI inference.
// This provider only needs the LLM/inference key, hence PHALA_LLM_API_KEY.
export const API_KEY_ENV = "PHALA_LLM_API_KEY";

export function getBaseUrl(): string {
  // @phala/cloud uses PHALA_CLOUD_API_PREFIX for the API base; PHALA_BASE_URL
  // is kept as a secondary alias for convenience.
  const value =
    process.env.PHALA_CLOUD_API_PREFIX ||
    process.env.PHALA_BASE_URL ||
    process.env.PHALA_CLOUD_BASE_URL ||
    DEFAULT_BASE_URL;
  return value.trim() || DEFAULT_BASE_URL;
}

// Build a gateway-root URL (no trailing /v1) for ACI endpoints
// (/aci/receipts, /aci/attestation, /aci/sessions). The inference base URL is
// `https://inference.phala.com/v1`; ACI endpoints hang off the same host.
export function getGatewayRoot(baseUrl: string = getBaseUrl()): string {
  return baseUrl.replace(/\/v\d+\/?$/, "").replace(/\/+$/, "");
}

export function buildModelsUrl(baseUrl: string = getBaseUrl()): string {
  const base = baseUrl.replace(/\/+$/, "");
  return base.endsWith("/v1") ? `${base}/models` : `${base}/v1/models`;
}

export function buildReceiptUrl(receiptId: string, baseUrl: string = getBaseUrl()): string {
  return `${getGatewayRoot(baseUrl)}/v1/aci/receipts/${encodeURIComponent(receiptId)}`;
}

export function buildAttestationUrl(nonce: string, baseUrl: string = getBaseUrl()): string {
  return `${getGatewayRoot(baseUrl)}/v1/aci/attestation?nonce=${encodeURIComponent(nonce)}`;
}

export function buildSessionUrl(sessionId: string, baseUrl: string = getBaseUrl()): string {
  return `${getGatewayRoot(baseUrl)}/v1/aci/sessions/${encodeURIComponent(sessionId)}`;
}

// ACI response headers attached to every inference response.
export const HEADER_RECEIPT_ID = "x-receipt-id";
export const HEADER_ACI_IDENTITY = "x-aci-identity";
export const HEADER_ACI_KEYSET_DIGEST = "x-aci-keyset-digest";

export const DEFAULT_DISCOVERY_TIMEOUT_MS = 5000;
export const DEFAULT_RECEIPT_FETCH_TIMEOUT_MS = 8000;
export const DEFAULT_ATTESTATION_FETCH_TIMEOUT_MS = 8000;

// Attestation freshness: re-fetch when the cached report's stale_after has
// passed, or after this fallback TTL if the report lacked freshness info.
export const ATTESTATION_FALLBACK_TTL_MS = 30 * 60 * 1000;
