#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const pluginDir = path.resolve(scriptDir, "..");
const entryFile = path.join(pluginDir, "index.ts");
const implFile = path.join(pluginDir, "src", "advisor.ts");
const commandSrc = path.join(pluginDir, "commands", "advisor.md");

const globalDir = path.join(os.homedir(), ".config", "opencode");
const commandsDir = path.join(globalDir, "commands");
const commandDest = path.join(commandsDir, "advisor.md");

// Substring identifying our own plugin entry in opencode.json(c). Searched
// with forward slashes because the installer records the entry as a file://
// URL. Matches both the v2 directory entry and a legacy file entry (which
// contains this path as a prefix), so migration keeps working no matter
// where this repo is cloned.
const entrySuffix = "oc/plugins/advisor";

const args = parseArgs(process.argv.slice(2));

if (args.help) {
  printHelp();
  process.exit(0);
}

main().catch((error) => {
  console.error(`Error: ${error.message}`);
  process.exit(1);
});

async function main() {
  requireFiles();
  // V2 config entries must be directories: local dirs resolve at the
  // package root index.ts (package.json main is ignored, file entries are
  // rejected). Settings live in plugin storage, so no entry options.
  const entryUrl = pathToFileURL(pluginDir).href;
  const entryText = `"${entryUrl}"`;
  const configPath = userConfigPath();

  if (args.status) {
    showStatus(configPath, entryUrl);
    return;
  }

  if (args.remove) {
    remove(configPath, entryUrl, args["dry-run"]);
    return;
  }

  install(configPath, entryText, args["dry-run"]);

  if (!args["dry-run"] && !args["skip-validate"]) {
    validateWithOpenCode();
  }
}

// Fails fast when the repo copy is incomplete.
function requireFiles() {
  for (const file of [entryFile, implFile, commandSrc]) {
    if (!fs.existsSync(file)) {
      throw new Error(`Missing plugin file: ${file}`);
    }
  }
}

// Prefers the config file that already exists so a .jsonc is never
// rewritten as .json or vice versa. Falls back to opencode.json.
function userConfigPath() {
  const jsonc = path.join(globalDir, "opencode.jsonc");
  if (fs.existsSync(jsonc)) return jsonc;
  return path.join(globalDir, "opencode.json");
}

function parseArgs(argv) {
  const parsed = {};

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    if (arg === "--help" || arg === "-h") {
      parsed.help = true;
      continue;
    }

    if (["--dry-run", "--remove", "--status", "--skip-validate"].includes(arg)) {
      parsed[arg.slice(2)] = true;
      continue;
    }

    throw new Error(`Unknown argument: ${arg}`);
  }

  return parsed;
}

function printHelp() {
  console.log(`Install the local oc advisor plugin into your OpenCode config.

Usage:
  node scripts/install.mjs [options]

Options:
  --dry-run                Print what would change without writing
  --remove                 Remove the plugin entry and command file
  --status                 Show whether the plugin entry and command file exist
  --skip-validate          Do not run opencode debug config
  -h, --help               Show this help
`);
}

// Advances past whitespace and // or /* */ comments.
function skipIgnored(text, i) {
  while (i < text.length) {
    const ch = text[i];
    if (ch === " " || ch === "\t" || ch === "\r" || ch === "\n") {
      i++;
      continue;
    }
    if (ch === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      continue;
    }
    if (ch === "/" && text[i + 1] === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    break;
  }
  return i;
}

// Index of the bracket closing text[openIdx]. Skips over strings and
// comments so brackets inside them do not count.
function findMatching(text, openIdx) {
  const close = text[openIdx] === "[" ? "]" : "}";
  let depth = 0;
  let i = openIdx;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '"') {
      i++;
      while (i < text.length && text[i] !== '"') {
        if (text[i] === "\\") i++;
        i++;
      }
      i++;
      continue;
    }
    if (ch === "/" && (text[i + 1] === "/" || text[i + 1] === "*")) {
      i = skipIgnored(text, i);
      continue;
    }
    if (ch === text[openIdx]) depth++;
    else if (ch === close) {
      depth--;
      if (depth === 0) return i;
    }
    i++;
  }
  throw new Error("unbalanced brackets in opencode config");
}

// Span of the top-level "plugins" array, or null when there is no such key.
// The key must follow { or , (skipping whitespace) so a "plugins" string
// inside a value cannot match.
function findPluginArray(text) {
  const re = /"plugins"\s*:/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    let j = m.index - 1;
    while (j >= 0 && " \t\r\n".includes(text[j])) j--;
    if (j < 0 || (text[j] !== "{" && text[j] !== ",")) continue;
    let k = skipIgnored(text, m.index + m[0].length);
    if (text[k] !== "[") continue;
    return { open: k, close: findMatching(text, k) };
  }
  return null;
}

// True when our plugin entry is already recorded in the config text.
function hasTuple(text) {
  return text.includes(entrySuffix);
}

// Span of our plugin entry: either the v2 plain "file://..." string or a
// legacy v1 tuple [...]. Returns null when absent. The discriminator: in a
// v1 tuple the URL string is followed by `, {`, in v2 by `,`/`]`/end.
function findTuple(text) {
  const at = text.indexOf(entrySuffix);
  if (at === -1) return null;
  const open = text.lastIndexOf('"', at);
  if (open === -1) return null;
  let end = at;
  while (end < text.length && text[end] !== '"') {
    if (text[end] === "\\") end++;
    end++;
  }
  if (end >= text.length) return null;
  let k = skipIgnored(text, end + 1);
  if (text[k] === ",") {
    k = skipIgnored(text, k + 1);
    if (text[k] === "{") {
      // Legacy v1 tuple ["url", {...}]: remove the whole tuple. Its "["
      // is the nearest one before our string.
      const tupleOpen = text.lastIndexOf("[", open);
      if (tupleOpen === -1) return null;
      return { open: tupleOpen, close: findMatching(text, tupleOpen) };
    }
  }
  return { open, close: end };
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
    String(now.getSeconds()).padStart(2, "0"),
  ];
  return parts.join("");
}

function backup(file) {
  const backupPath = `${file}.backup-${timestamp()}`;
  fs.copyFileSync(file, backupPath);
  console.log(`Backup:   ${backupPath}`);
}

function showStatus(configPath, entryUrl) {
  console.log(`Entry:    ${entryUrl}`);
  console.log(`Target:   ${configPath}`);
  if (fs.existsSync(configPath)) {
    const text = fs.readFileSync(configPath, "utf8");
    console.log(`Plugin:   ${hasTuple(text) ? "installed" : "not installed"}`);
  } else {
    console.log("Plugin:   not installed (no config file)");
  }
  const cmdExists = fs.existsSync(commandDest);
  const cmdCurrent = cmdExists && fs.readFileSync(commandDest, "utf8") === fs.readFileSync(commandSrc, "utf8");
  console.log(`Command:  ${cmdExists ? (cmdCurrent ? "installed" : "differs") : "not installed"} → ${commandDest}`);
}

function freshConfig(entryText) {
  return `{\n  "$schema": "https://opencode.ai/config.json",\n  "plugins": [\n    ${entryText}\n  ]\n}\n`;
}

// True when the span is a legacy v1 tuple ["url", {...}] rather than a
// v2 plain "url" string.
function isLegacyTuple(text, span) {
  return text[span.open] === "[";
}

function install(configPath, entryText, dryRun) {
  let text = fs.existsSync(configPath) ? fs.readFileSync(configPath, "utf8") : freshConfig(entryText);
  const existed = fs.existsSync(configPath);
  let changed = false;

  if (!existed) {
    changed = true;
  } else {
    let span = findTuple(text);
    if (span && isLegacyTuple(text, span)) {
      // Legacy v1 tuple: excise it (comma-safe), then add the v2 entry
      // to the "plugins" array below.
      const was = text.slice(span.open, Math.min(span.close + 1, span.open + 120));
      text = excise(text, span);
      console.log(`Migrated legacy v1 plugin entry to v2 (was: ${was}).`);
      span = null;
    }
    if (span && text.slice(span.open, span.close + 1) === entryText) {
      console.log("Plugin entry already configured.");
    } else {
      if (span) {
        // Outdated entry (e.g. a file path the server rejects): swap the
        // bare string in place; surrounding commas are unaffected.
        const was = text.slice(span.open, Math.min(span.close + 1, span.open + 120));
        text = text.slice(0, span.open) + entryText + text.slice(span.close + 1);
        console.log(`Updated plugin entry (was: ${was}).`);
      } else {
        const arr = findPluginArray(text);
        if (!arr) {
          text = insertPluginKey(text, entryText);
        } else if (skipIgnored(text, arr.open + 1) === arr.close) {
          text = `${text.slice(0, arr.open + 1)}\n    ${entryText}\n  ${text.slice(arr.close)}`;
        } else {
          text = `${text.slice(0, arr.close)},\n    ${entryText}\n  ${text.slice(arr.close)}`;
        }
      }
      changed = true;
    }
  }

  const cmdWanted = fs.readFileSync(commandSrc, "utf8");
  const cmdCurrent = fs.existsSync(commandDest) ? fs.readFileSync(commandDest, "utf8") : null;

  if (dryRun) {
    console.log(`Target:   ${configPath}`);
    console.log(`Entry:    ${entryText}`);
    console.log(`Command:  ${commandDest} (${cmdCurrent === cmdWanted ? "up to date" : "would write"})`);
    console.log(`\nDry run only. Resulting config:\n\n${text}`);
    return;
  }

  if (changed) {
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    if (existed) backup(configPath);
    fs.writeFileSync(configPath, text, "utf8");
    console.log(`Wrote:    ${configPath}`);
  }

  if (cmdCurrent !== cmdWanted) {
    fs.mkdirSync(commandsDir, { recursive: true });
    fs.writeFileSync(commandDest, cmdWanted, "utf8");
    console.log(`Wrote:    ${commandDest}`);
  } else {
    console.log("Command file already up to date.");
  }
}

// Inserts a "plugins" key before the root object's closing brace. Handles
// both empty and non-empty root objects.
function insertPluginKey(text, entryText) {
  const rootOpen = skipIgnored(text, 0);
  if (text[rootOpen] !== "{") throw new Error("config has no root object");
  const rootClose = findMatching(text, rootOpen);
  const innerEmpty = skipIgnored(text, rootOpen + 1) === rootClose;
  const key = `"plugins": [\n    ${entryText}\n  ]`;
  if (innerEmpty) {
    return `${text.slice(0, rootOpen + 1)}\n  ${key}\n${text.slice(rootClose)}`;
  }
  return `${text.slice(0, rootClose)},\n  ${key}\n${text.slice(rootClose)}`;
}

// Removes the span plus one adjacent comma (trailing preferred) so the
// surrounding array stays valid.
function excise(text, span) {
  let start = span.open;
  let end = span.close + 1;
  const after = skipIgnored(text, end);
  if (text[after] === ",") {
    end = after + 1;
  } else {
    let k = start - 1;
    while (k >= 0 && " \t\r\n".includes(text[k])) k--;
    if (text[k] === ",") start = k;
  }
  return text.slice(0, start) + text.slice(end);
}

function remove(configPath, entryUrl, dryRun) {
  if (!fs.existsSync(configPath)) {
    console.log("No config file; nothing to remove.");
  } else {
    const text = fs.readFileSync(configPath, "utf8");
    const span = findTuple(text);
    if (!span) {
      console.log("Plugin entry not found.");
    } else {
      const next = excise(text, span);
      if (dryRun) {
        console.log(`Would remove plugin entry from ${configPath}.`);
      } else {
        backup(configPath);
        fs.writeFileSync(configPath, next, "utf8");
        console.log(`Removed plugin entry → ${configPath}`);
      }
    }
  }

  if (!fs.existsSync(commandDest)) {
    console.log("Command file not present.");
  } else if (fs.readFileSync(commandDest, "utf8") !== fs.readFileSync(commandSrc, "utf8")) {
    console.log(`Command file differs, left in place → ${commandDest}`);
  } else if (dryRun) {
    console.log(`Would remove ${commandDest}.`);
  } else {
    fs.unlinkSync(commandDest);
    console.log(`Removed ${commandDest}`);
  }

  if (!dryRun) validateWithOpenCode();
}

function validateWithOpenCode() {
  console.log("\nValidating with: opencode --version");
  const result = spawnSync("opencode", ["--version"], {
    encoding: "utf8",
    shell: process.platform === "win32",
  });

  if (result.error) {
    console.warn(`Warning: unable to run opencode --version: ${result.error.message}`);
    return;
  }

  if (result.stdout.trim()) console.log(result.stdout.trim());
  if (result.stderr.trim()) console.error(result.stderr.trim());

  if (result.status !== 0) {
    throw new Error(`opencode --version failed with exit code ${result.status}`);
  }
  console.log("Next: restart opencode, then run /advisor status in a session.");
}
