#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const defaultConfigPath = path.join(os.homedir(), ".config", "opencode", "opencode.json");
const defaultFragmentPath = path.resolve(scriptDir, "..", "config", "opencode-agent-routing.json");

const args = parseArgs(process.argv.slice(2));

if (args.help) {
  printHelp();
  process.exit(0);
}

const configPath = path.resolve(args.config ?? defaultConfigPath);
const fragmentPath = path.resolve(args.fragment ?? defaultFragmentPath);
const dryRun = Boolean(args["dry-run"]);
const noBackup = Boolean(args["no-backup"]);
const skipValidate = Boolean(args["skip-validate"]);

main().catch((error) => {
  console.error(`Error: ${error.message}`);
  process.exit(1);
});

async function main() {
  const fragment = readJson(fragmentPath, "fragment");
  const existing = fs.existsSync(configPath) ? readJson(configPath, "OpenCode config") : {};
  const merged = mergeConfig(existing, fragment);

  if (args["default-agent"]) merged.default_agent = args["default-agent"];

  const output = `${JSON.stringify(merged, null, 2)}\n`;

  console.log(`Fragment: ${fragmentPath}`);
  console.log(`Target:   ${configPath}`);
  console.log(`Default:  ${merged.default_agent ?? "<not set>"}`);

  if (dryRun) {
    console.log("\nDry run only. Merged config preview:");
    console.log(output);
    return;
  }

  fs.mkdirSync(path.dirname(configPath), { recursive: true });

  if (fs.existsSync(configPath) && !noBackup) {
    const backupPath = `${configPath}.backup-${timestamp()}`;
    fs.copyFileSync(configPath, backupPath);
    console.log(`Backup:   ${backupPath}`);
  }

  fs.writeFileSync(configPath, output, "utf8");
  console.log("Installed OpenCode agent routing config.");

  if (!skipValidate) {
    validateWithOpenCode();
  }
}

function parseArgs(argv) {
  const parsed = {};

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    if (arg === "--help" || arg === "-h") {
      parsed.help = true;
      continue;
    }

    if (["--dry-run", "--no-backup", "--skip-validate"].includes(arg)) {
      parsed[arg.slice(2)] = true;
      continue;
    }

    if (["--config", "--fragment", "--default-agent"].includes(arg)) {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) {
        throw new Error(`${arg} requires a value`);
      }
      parsed[arg.slice(2)] = value;
      index += 1;
      continue;
    }

    throw new Error(`Unknown argument: ${arg}`);
  }

  return parsed;
}

function printHelp() {
  console.log(`Install the OpenCode multi-model agent routing configuration.

Usage:
  node scripts/install-opencode-routing.mjs [options]

Options:
  --config <path>          Target OpenCode config path
  --fragment <path>        Source routing config fragment
  --default-agent <agent>  Override default_agent after merge
  --dry-run                Print merged config without writing
  --no-backup              Do not backup an existing config
  --skip-validate          Do not run opencode debug config
  -h, --help               Show this help
`);
}

function readJson(filePath, label) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") {
      throw new Error(`Missing ${label}: ${filePath}`);
    }
    throw new Error(`Unable to read ${label} at ${filePath}: ${error.message}`);
  }
}

function mergeConfig(base, fragment) {
  const merged = deepMerge(base, fragment);

  if (base.agent || fragment.agent) {
    merged.agent = { ...(base.agent ?? {}) };
    for (const [name, agent] of Object.entries(fragment.agent ?? {})) {
      // Re-running the installer should replace managed agents exactly.
      merged.agent[name] = agent;
    }
  }

  return merged;
}

function deepMerge(base, override) {
  if (!isPlainObject(base) || !isPlainObject(override)) return structuredCloneFallback(override);

  const result = { ...base };
  for (const [key, value] of Object.entries(override)) {
    if (isPlainObject(value) && isPlainObject(base[key])) {
      result[key] = deepMerge(base[key], value);
      continue;
    }
    result[key] = structuredCloneFallback(value);
  }
  return result;
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function structuredCloneFallback(value) {
  if (typeof structuredClone === "function") return structuredClone(value);
  return JSON.parse(JSON.stringify(value));
}

function timestamp() {
  const now = new Date();
  const parts = [
    now.getFullYear(),
    String(now.getMonth() + 1).padStart(2, "0"),
    String(now.getDate()).padStart(2, "0"),
    "-",
    String(now.getHours()).padStart(2, "0"),
    String(now.getMinutes()).padStart(2, "0"),
    String(now.getSeconds()).padStart(2, "0")
  ];
  return parts.join("");
}

function validateWithOpenCode() {
  console.log("\nValidating with: opencode debug config");
  const result = spawnSync("opencode", ["debug", "config"], {
    encoding: "utf8",
    shell: process.platform === "win32"
  });

  if (result.error) {
    console.warn(`Warning: unable to run opencode debug config: ${result.error.message}`);
    return;
  }

  if (result.stdout.trim()) console.log(result.stdout.trim());
  if (result.stderr.trim()) console.error(result.stderr.trim());

  if (result.status !== 0) {
    throw new Error(`opencode debug config failed with exit code ${result.status}`);
  }
}
