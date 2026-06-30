import assert from "node:assert/strict";
import { test } from "node:test";

import {
  DEFAULT_PHALA_CLOUD_CONFIG,
  validatePhalaCloudConfig,
  type PhalaCloudConfig,
} from "../src/config.ts";

test("DEFAULT_PHALA_CLOUD_CONFIG validates against itself", () => {
  const validated = validatePhalaCloudConfig(DEFAULT_PHALA_CLOUD_CONFIG);
  assert.equal(validated.baseUrl, "https://inference.phala.com/v1");
  assert.equal(validated.models.isTeeOnly, true);
  assert.equal(validated.models.thinkingFormat, "auto");
  assert.equal(validated.verify.autoFetchReceipt, true);
  assert.equal(validated.e2ee.enabled, true);
});

test("validatePhalaCloudConfig: rejects invalid thinkingFormat", () => {
  const bad = { ...DEFAULT_PHALA_CLOUD_CONFIG, models: { ...DEFAULT_PHALA_CLOUD_CONFIG.models, thinkingFormat: "bogus" } };
  assert.throws(() => validatePhalaCloudConfig(bad), /expected "auto" \| "qwen" \| "openai" \| "off"/);
});

test("validatePhalaCloudConfig: rejects non-boolean isTeeOnly", () => {
  const bad = { ...DEFAULT_PHALA_CLOUD_CONFIG, models: { ...DEFAULT_PHALA_CLOUD_CONFIG.models, isTeeOnly: "yes" } };
  assert.throws(() => validatePhalaCloudConfig(bad), /expected a boolean/);
});

test("validatePhalaCloudConfig: rejects empty baseUrl", () => {
  const bad = { ...DEFAULT_PHALA_CLOUD_CONFIG, baseUrl: "" };
  assert.throws(() => validatePhalaCloudConfig(bad), /expected a non-empty string/);
});

test("validatePhalaCloudConfig: accepts optional allowlist of non-empty strings", () => {
  const config: PhalaCloudConfig = {
    ...DEFAULT_PHALA_CLOUD_CONFIG,
    models: { ...DEFAULT_PHALA_CLOUD_CONFIG.models, allowlist: ["phala/qwen3.5-27b"] },
  };
  const validated = validatePhalaCloudConfig(config);
  assert.deepEqual(validated.models.allowlist, ["phala/qwen3.5-27b"]);
});

test("validatePhalaCloudConfig: allowlist with empty string is rejected", () => {
  const bad = {
    ...DEFAULT_PHALA_CLOUD_CONFIG,
    models: { ...DEFAULT_PHALA_CLOUD_CONFIG.models, allowlist: [""] },
  };
  assert.throws(() => validatePhalaCloudConfig(bad), /expected a non-empty string/);
});

test("validatePhalaCloudConfig: defaultModel is optional", () => {
  const validated = validatePhalaCloudConfig({
    ...DEFAULT_PHALA_CLOUD_CONFIG,
    defaultModel: "phala/qwen3.5-27b",
  });
  assert.equal(validated.defaultModel, "phala/qwen3.5-27b");
});
