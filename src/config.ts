// Layered configuration for the phala-cloud provider.
//
// Layers, lowest to highest precedence:
//   default  -> home (~/.pi/providers/phala-cloud/config.json)
//            -> project (cwd/.pi/providers/phala-cloud/config.json, gated by
//              project trust)
//            -> env (PHALA_* variables)
//            -> runtime (programmatic override via PhalaCloud(patch))
//
// Each config value records which layer it came from (sources) so the settings
// UI can show provenance. Validation runs after merge so a malformed layer
// never produces a partially-applied config.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { PROVIDER_ID } from "./constants.ts";

export type PhalaConfigSource = "runtime" | "env" | "project" | "home" | "default";

export type ThinkingFormat = "auto" | "qwen" | "openai" | "off";

export interface PhalaModelsConfig {
  /** Only register models whose /v1/models entry has is_tee === true. */
  isTeeOnly: boolean;
  /** How to map pi thinking levels onto provider request parameters. */
  thinkingFormat: ThinkingFormat;
  /** Optional model-id allowlist. When set, only these ids are registered. */
  allowlist?: string[];
}

export interface PhalaVerifyConfig {
  /** Automatically fetch the receipt after each response and update the footer. */
  autoFetchReceipt: boolean;
  /** Require a cached attestation whose workload matches the receipt. */
  requireAttestationMatch: boolean;
}

export interface PhalaE2eeConfig {
  /** Reserved. End-to-end encryption is not implemented yet. */
  enabled: boolean;
}

export interface PhalaCloudConfig {
  baseUrl: string;
  models: PhalaModelsConfig;
  verify: PhalaVerifyConfig;
  e2ee: PhalaE2eeConfig;
  /** Default model id to surface first in /model. */
  defaultModel?: string;
}

export type PhalaCloudConfigPatch = {
  baseUrl?: unknown;
  models?: Partial<{
    isTeeOnly: unknown;
    thinkingFormat: unknown;
    allowlist: unknown;
  }>;
  verify?: Partial<{
    autoFetchReceipt: unknown;
    requireAttestationMatch: unknown;
  }>;
  e2ee?: Partial<{ enabled: unknown }>;
  defaultModel?: unknown;
};

export interface PhalaCloudConfigSources {
  baseUrl: PhalaConfigSource;
  models: {
    isTeeOnly: PhalaConfigSource;
    thinkingFormat: PhalaConfigSource;
    allowlist: PhalaConfigSource;
  };
  verify: {
    autoFetchReceipt: PhalaConfigSource;
    requireAttestationMatch: PhalaConfigSource;
  };
  e2ee: { enabled: PhalaConfigSource };
  defaultModel: PhalaConfigSource;
}

export interface LoadPhalaCloudConfigOptions {
  cwd: string;
  home: string;
  env?: NodeJS.ProcessEnv;
  includeProject?: boolean;
}

export const PI_CONFIG_DIR_NAME = ".pi";

export class ConfigError extends Error {
  public readonly configPath: string;
  public readonly pointer?: string;

  constructor(message: string, configPath: string, pointer?: string) {
    super(pointer ? `${configPath}${pointer}: ${message}` : `${configPath}: ${message}`);
    this.name = "ConfigError";
    this.configPath = configPath;
    this.pointer = pointer;
  }
}

export const DEFAULT_PHALA_CLOUD_CONFIG: PhalaCloudConfig = {
  baseUrl: "https://inference.phala.com/v1",
  models: {
    isTeeOnly: true,
    thinkingFormat: "auto",
  },
  verify: {
    autoFetchReceipt: true,
    requireAttestationMatch: false,
  },
  e2ee: {
    enabled: true,
  },
};

let runtimeOverride: PhalaCloudConfigPatch = {};

export function setRuntimePhalaCloudConfigOverride(patch: PhalaCloudConfigPatch): void {
  runtimeOverride = mergeConfigPatch(runtimeOverride, patch);
}

export function getGlobalPhalaCloudConfigPath(home: string): string {
  return join(home, PI_CONFIG_DIR_NAME, "providers", PROVIDER_ID, "config.json");
}

export function getProjectPhalaCloudConfigPath(cwd: string): string {
  return join(cwd, PI_CONFIG_DIR_NAME, "providers", PROVIDER_ID, "config.json");
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function mergeConfigPatch<T extends Record<string, unknown>>(
  base: T,
  patch: Record<string, unknown>,
): T {
  const result: Record<string, unknown> = { ...base };
  for (const [key, value] of Object.entries(patch)) {
    if (value === undefined) continue;
    const current = result[key];
    if (isRecord(current) && isRecord(value)) {
      result[key] = mergeConfigPatch(current, value);
    } else {
      result[key] = value;
    }
  }
  return result as T;
}

function readConfigFile(path: string): Record<string, unknown> {
  if (!existsSync(path)) return {};
  let contents: string;
  try {
    contents = readFileSync(path, "utf8");
  } catch (error) {
    throw new ConfigError(
      `failed to read config: ${error instanceof Error ? error.message : String(error)}`,
      path,
    );
  }
  try {
    const parsed = JSON.parse(contents) as unknown;
    if (isRecord(parsed)) return parsed;
    throw new ConfigError("config file must be a JSON object", path);
  } catch (error) {
    if (error instanceof ConfigError) throw error;
    throw new ConfigError(
      `invalid JSON: ${error instanceof Error ? error.message : String(error)}`,
      path,
    );
  }
}

function readConfigFileQuiet(path: string): Record<string, unknown> {
  try {
    return readConfigFile(path);
  } catch (error) {
    console.error(`[phala-cloud] failed to read config file ${path}:`, error);
    return {};
  }
}

function parseBoolean(value: string | undefined): boolean | undefined {
  if (value === undefined) return undefined;
  const trimmed = value.trim().toLowerCase();
  if (trimmed === "true" || trimmed === "1") return true;
  if (trimmed === "false" || trimmed === "0") return false;
  return undefined;
}

function envConfigPatch(env: NodeJS.ProcessEnv): PhalaCloudConfigPatch {
  const patch: PhalaCloudConfigPatch = {};

  const baseUrl =
    env.PHALA_CLOUD_API_PREFIX?.trim() ||
    env.PHALA_BASE_URL?.trim() ||
    env.PHALA_CLOUD_BASE_URL?.trim();
  if (baseUrl) patch.baseUrl = baseUrl;

  const isTeeOnly = parseBoolean(env.PHALA_CLOUD_IS_TEE_ONLY ?? env.PHALA_IS_TEE_ONLY);
  if (isTeeOnly !== undefined) patch.models = { ...patch.models, isTeeOnly };

  const thinkingFormat = env.PHALA_CLOUD_THINKING_FORMAT?.trim();
  if (thinkingFormat) patch.models = { ...patch.models, thinkingFormat };

  const autoFetch = parseBoolean(env.PHALA_CLOUD_AUTO_VERIFY);
  if (autoFetch !== undefined) patch.verify = { ...patch.verify, autoFetchReceipt: autoFetch };

  const defaultModel = env.PHALA_CLOUD_DEFAULT_MODEL?.trim();
  if (defaultModel) patch.defaultModel = defaultModel;

  return patch;
}

function fail(configPath: string, pointer: string, message: string): never {
  throw new ConfigError(message, configPath, pointer);
}

function requireRecord(raw: unknown, configPath: string, pointer: string): Record<string, unknown> {
  if (isRecord(raw)) return raw;
  return fail(
    configPath,
    pointer,
    `expected an object, got ${Array.isArray(raw) ? "array" : typeof raw}`,
  );
}

function requireString(raw: unknown, configPath: string, pointer: string): string {
  if (typeof raw === "string" && raw.length > 0) return raw;
  return fail(configPath, pointer, `expected a non-empty string, got ${JSON.stringify(raw)}`);
}

function requireOptionalString(
  raw: unknown,
  configPath: string,
  pointer: string,
): string | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw === "string" && raw.length > 0) return raw;
  return fail(configPath, pointer, `expected a non-empty string, got ${JSON.stringify(raw)}`);
}

function requireBoolean(raw: unknown, configPath: string, pointer: string): boolean {
  if (typeof raw === "boolean") return raw;
  return fail(configPath, pointer, `expected a boolean, got ${JSON.stringify(raw)}`);
}

function requireThinkingFormat(
  raw: unknown,
  configPath: string,
  pointer: string,
): ThinkingFormat {
  if (raw === "auto" || raw === "qwen" || raw === "openai" || raw === "off") return raw;
  return fail(
    configPath,
    pointer,
    `expected "auto" | "qwen" | "openai" | "off", got ${JSON.stringify(raw)}`,
  );
}

function requireStringArray(
  raw: unknown,
  configPath: string,
  pointer: string,
): string[] | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (!Array.isArray(raw)) {
    return fail(configPath, pointer, `expected an array, got ${typeof raw}`);
  }
  return raw.map((value, index) => {
    if (typeof value !== "string" || value.length === 0) {
      return fail(
        configPath,
        `${pointer}/${index}`,
        `expected a non-empty string, got ${JSON.stringify(value)}`,
      );
    }
    return value;
  });
}

function validateModelsConfig(
  raw: unknown,
  configPath: string,
  pointer: string,
): PhalaModelsConfig {
  const model = requireRecord(raw, configPath, pointer);
  return {
    isTeeOnly: requireBoolean(model.isTeeOnly, configPath, `${pointer}/isTeeOnly`),
    thinkingFormat: requireThinkingFormat(
      model.thinkingFormat,
      configPath,
      `${pointer}/thinkingFormat`,
    ),
    allowlist: requireStringArray(model.allowlist, configPath, `${pointer}/allowlist`),
  };
}

function validateVerifyConfig(
  raw: unknown,
  configPath: string,
  pointer: string,
): PhalaVerifyConfig {
  const verify = requireRecord(raw, configPath, pointer);
  return {
    autoFetchReceipt: requireBoolean(
      verify.autoFetchReceipt,
      configPath,
      `${pointer}/autoFetchReceipt`,
    ),
    requireAttestationMatch: requireBoolean(
      verify.requireAttestationMatch,
      configPath,
      `${pointer}/requireAttestationMatch`,
    ),
  };
}

function validateE2eeConfig(
  raw: unknown,
  configPath: string,
  pointer: string,
): PhalaE2eeConfig {
  const e2ee = requireRecord(raw, configPath, pointer);
  return {
    enabled: requireBoolean(e2ee.enabled, configPath, `${pointer}/enabled`),
  };
}

export function validatePhalaCloudConfig(
  raw: unknown,
  configPath = "<phala-cloud-config>",
): PhalaCloudConfig {
  const config = requireRecord(raw, configPath, "");
  return {
    baseUrl: requireString(config.baseUrl, configPath, "/baseUrl"),
    models: validateModelsConfig(config.models, configPath, "/models"),
    verify: validateVerifyConfig(config.verify, configPath, "/verify"),
    e2ee: validateE2eeConfig(config.e2ee, configPath, "/e2ee"),
    defaultModel: requireOptionalString(config.defaultModel, configPath, "/defaultModel"),
  };
}

function hasPath(config: Record<string, unknown>, path: readonly string[]): boolean {
  let current: unknown = config;
  for (const key of path) {
    if (!isRecord(current) || !Object.hasOwn(current, key)) return false;
    current = current[key];
  }
  return true;
}

function sourceForPath(
  layers: Array<{ source: PhalaConfigSource; config: Record<string, unknown> }>,
  path: readonly string[],
): PhalaConfigSource {
  for (let i = layers.length - 1; i >= 0; i--) {
    if (hasPath(layers[i].config, path)) return layers[i].source;
  }
  return "default";
}

function buildSources(
  layers: Array<{ source: PhalaConfigSource; config: Record<string, unknown> }>,
): PhalaCloudConfigSources {
  return {
    baseUrl: sourceForPath(layers, ["baseUrl"]),
    models: {
      isTeeOnly: sourceForPath(layers, ["models", "isTeeOnly"]),
      thinkingFormat: sourceForPath(layers, ["models", "thinkingFormat"]),
      allowlist: sourceForPath(layers, ["models", "allowlist"]),
    },
    verify: {
      autoFetchReceipt: sourceForPath(layers, ["verify", "autoFetchReceipt"]),
      requireAttestationMatch: sourceForPath(layers, ["verify", "requireAttestationMatch"]),
    },
    e2ee: { enabled: sourceForPath(layers, ["e2ee", "enabled"]) },
    defaultModel: sourceForPath(layers, ["defaultModel"]),
  };
}

function loadLayers(
  options: LoadPhalaCloudConfigOptions,
): Array<{ source: PhalaConfigSource; config: Record<string, unknown> }> {
  const layers: Array<{ source: PhalaConfigSource; config: Record<string, unknown> }> = [
    { source: "home", config: readConfigFile(getGlobalPhalaCloudConfigPath(options.home)) },
  ];
  if (options.includeProject !== false) {
    layers.push({
      source: "project",
      config: readConfigFile(getProjectPhalaCloudConfigPath(options.cwd)),
    });
  }
  layers.push(
    {
      source: "env",
      config: envConfigPatch(options.env ?? process.env) as Record<string, unknown>,
    },
    { source: "runtime", config: runtimeOverride as Record<string, unknown> },
  );
  return layers;
}

export function loadPhalaCloudConfig(
  options: LoadPhalaCloudConfigOptions,
  overrides?: PhalaCloudConfigPatch,
): PhalaCloudConfig {
  let merged = clone(DEFAULT_PHALA_CLOUD_CONFIG) as unknown as Record<string, unknown>;
  for (const layer of loadLayers(options)) {
    merged = mergeConfigPatch(merged, layer.config);
  }
  if (overrides) {
    merged = mergeConfigPatch(merged, overrides as Record<string, unknown>);
  }
  return validatePhalaCloudConfig(merged);
}

export function loadPhalaCloudConfigSources(
  options: LoadPhalaCloudConfigOptions,
): PhalaCloudConfigSources {
  return buildSources(loadLayers(options));
}

export function loadProjectPhalaCloudConfig(cwd: string): PhalaCloudConfig {
  return validatePhalaCloudConfig(
    mergeConfigPatch(
      clone(DEFAULT_PHALA_CLOUD_CONFIG) as unknown as Record<string, unknown>,
      readConfigFileQuiet(getProjectPhalaCloudConfigPath(cwd)),
    ),
  );
}

export function loadHomePhalaCloudConfig(home: string): PhalaCloudConfig {
  return validatePhalaCloudConfig(
    mergeConfigPatch(
      clone(DEFAULT_PHALA_CLOUD_CONFIG) as unknown as Record<string, unknown>,
      readConfigFileQuiet(getGlobalPhalaCloudConfigPath(home)),
    ),
  );
}

export function saveProjectPhalaCloudConfig(cwd: string, config: PhalaCloudConfig): void {
  savePhalaCloudConfigFile(getProjectPhalaCloudConfigPath(cwd), config);
}

export function saveHomePhalaCloudConfig(home: string, config: PhalaCloudConfig): void {
  savePhalaCloudConfigFile(getGlobalPhalaCloudConfigPath(home), config);
}

function savePhalaCloudConfigFile(path: string, config: PhalaCloudConfig): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(validatePhalaCloudConfig(config, path), null, 2)}\n`, "utf8");
}
