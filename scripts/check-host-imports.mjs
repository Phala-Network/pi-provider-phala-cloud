#!/usr/bin/env node
// Guards the host-module imports this package ships.
//
// Pi hands extensions a fixed set of host modules: `@earendil-works/pi-ai`
// (root/compat), `/models`, `/oauth`, `/providers/all`, plus the pi-tui,
// pi-coding-agent and pi-agent-core roots, and `typebox` with its /compile and
// /value subpaths. Peer dependencies of an installed package are not present on
// disk, so any other subpath — e.g. `@earendil-works/pi-ai/api/*` — resolves at
// type-check time from devDependencies but throws "Cannot find module" at
// runtime, which breaks extension loading entirely.
//
// Usage: node scripts/check-host-imports.mjs [root ...]

import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

const ALLOWED_HOST_SPECIFIERS = new Set([
  "@earendil-works/pi-ai",
  "@earendil-works/pi-ai/compat",
  "@earendil-works/pi-ai/models",
  "@earendil-works/pi-ai/oauth",
  "@earendil-works/pi-ai/providers/all",
  "@earendil-works/pi-agent-core",
  "@earendil-works/pi-coding-agent",
  "@earendil-works/pi-tui",
  "typebox",
  "typebox/compile",
  "typebox/value",
]);

const HOST_PREFIXES = ["@earendil-works", "typebox"];
const SOURCE_FILE = /\.(?:ts|tsx|mts|cts)$/u;
const SKIP_DIRECTORIES = new Set(["node_modules", ".git", "dist"]);
const SPECIFIER = /(?:\bfrom\s*|\bimport\s*\(\s*)(["'])([^"']+)\1/gu;

const roots = process.argv.slice(2);
const targets = roots.length > 0 ? roots : ["."];

const violations = [];
for (const target of targets) {
  for (const file of walk(target)) {
    const source = readFileSync(file, "utf8");
    for (const match of source.matchAll(SPECIFIER)) {
      const specifier = match[2];
      if (!isHostSpecifier(specifier)) continue;
      if (ALLOWED_HOST_SPECIFIERS.has(specifier)) continue;
      const line = source.slice(0, match.index).split("\n").length;
      violations.push(`${file}:${line}  ${specifier}`);
    }
  }
}

if (violations.length > 0) {
  console.error("Host modules outside pi's extension module map:");
  for (const violation of violations) console.error(`  ${violation}`);
  console.error(
    "\nInstalled packages cannot resolve these (peer dependencies are not on\n" +
      "disk). Import from an allowed entry point, or carry the code locally.",
  );
  process.exit(1);
}
console.log(`host imports ok (${[...ALLOWED_HOST_SPECIFIERS].length} allowed entry points)`);

function isHostSpecifier(specifier) {
  return HOST_PREFIXES.some(
    (prefix) => specifier === prefix || specifier.startsWith(`${prefix}/`),
  );
}

function* walk(target) {
  const stats = statSync(target, { throwIfNoEntry: false });
  if (!stats) return;
  if (stats.isFile()) {
    if (SOURCE_FILE.test(target)) yield target;
    return;
  }
  for (const entry of readdirSync(target, { withFileTypes: true })) {
    if (entry.isDirectory() && SKIP_DIRECTORIES.has(entry.name)) continue;
    yield* walk(path.join(target, entry.name));
  }
}
