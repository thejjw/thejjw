import { type Plugin, tool } from "@opencode-ai/plugin";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// Version of this copy. Reported by /advisor status.
const VERSION = "0.1.0";

// Slash command handled by this plugin (see commands/advisor.md).
const COMMAND = "advisor";

// Suffix identifying our own plugin tuple in opencode.json(c). The installer
// writes a file:// URL ending in this path, so matching on the suffix keeps
// working no matter where this repo is cloned.
const PLUGIN_ENTRY_SUFFIX = "oc/plugins/advisor/src/advisor.ts";

// Persisted settings, stored as the options object of our plugin tuple in
// the user's opencode.json(c). model "auto" means: reuse the calling
// session's active model.
type AdvisorSettings = {
  enabled: boolean;
  model: string;
};

const DEFAULT_SETTINGS: AdvisorSettings = {
  enabled: true,
  model: "auto",
};

let settings: AdvisorSettings = { ...DEFAULT_SETTINGS };

// Global default model from merged opencode config ("provider/model").
// Last resort when nothing else resolves a model.
let globalDefaultModel = "";

// Guard against the advisor model calling back into the advisor tool.
let inAdvisorCall = false;

// Optional model override from the environment. Highest precedence below
// per-call tool args.
function resolveModelFromEnv(): { providerID: string; modelID: string } | null {
  const env = (typeof process !== "undefined" && process.env) || {};
  const combined = env.OPENCODE_ADVISOR_MODEL;
  if (combined && combined.includes("/")) {
    const [providerID, ...rest] = combined.split("/");
    return { providerID, modelID: rest.join("/") };
  }
  const providerID = env.OPENCODE_ADVISOR_PROVIDER;
  const modelID = env.OPENCODE_ADVISOR_MODEL;
  if (providerID && modelID) return { providerID, modelID };
  return null;
}

// Reads our plugin-entry options. Accepts { enabled, model } and the
// upstream { providerID, modelID } form.
function applyOptions(opts: Record<string, unknown>) {
  if (typeof opts.enabled === "boolean") settings.enabled = opts.enabled;
  if (typeof opts.model === "string" && opts.model.length > 0) {
    settings.model = opts.model;
  } else if (typeof opts.providerID === "string" && typeof opts.modelID === "string") {
    settings.model = `${opts.providerID}/${opts.modelID}`;
  }
}

// Splits "provider/model" into parts. Null when malformed.
function splitModel(value: string): { providerID: string; modelID: string } | null {
  const [providerID, ...rest] = value.split("/");
  if (!providerID || rest.length === 0) return null;
  return { providerID, modelID: rest.join("/") };
}

// User's global opencode config. Prefers the file that already exists so a
// .jsonc is never rewritten as .json or vice versa.
function userConfigPath(): string {
  const dir = path.join(os.homedir(), ".config", "opencode");
  const jsonc = path.join(dir, "opencode.jsonc");
  if (fs.existsSync(jsonc)) return jsonc;
  return path.join(dir, "opencode.json");
}

// Locates the options object of our own plugin tuple in raw config text.
// The options object is flat (scalars only), so matching to the first "}"
// is safe. Returns null when our canonical entry is absent.
function findOwnOptions(text: string): { start: number; end: number } | null {
  const at = text.indexOf(PLUGIN_ENTRY_SUFFIX);
  if (at === -1) return null;
  const rest = text.slice(at);
  const closeQuote = rest.indexOf('"');
  if (closeQuote === -1) return null;
  const after = rest.slice(closeQuote + 1);
  const m = /^\s*,\s*\{[^}]*\}/.exec(after);
  if (!m) return null;
  const start = at + closeQuote + 1 + m[0].indexOf("{");
  return { start, end: start + (m[0].length - m[0].indexOf("{")) };
}

// Writes current settings back into our own plugin tuple. Surgical: only the
// options object is replaced, so comments and formatting elsewhere in the
// file survive. Returns an error message, or null on success.
function persistSettings(): string | null {
  const file = userConfigPath();
  let text: string;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch (error) {
    return `cannot read ${file}: ${(error as Error).message}`;
  }
  const span = findOwnOptions(text);
  if (!span) {
    return "our plugin entry was not found in opencode config; run scripts/install.mjs";
  }
  const replacement = `{ "enabled": ${settings.enabled ? "true" : "false"}, "model": ${JSON.stringify(settings.model)} }`;
  try {
    fs.writeFileSync(file, text.slice(0, span.start) + replacement + text.slice(span.end), "utf8");
  } catch (error) {
    return `cannot write ${file}: ${(error as Error).message}`;
  }
  return null;
}

// Active model of the calling session: the newest message carrying model
// info wins, so a mid-session /models switch is honored. Null when the
// transcript is unreachable (caller falls back to the global default).
async function sessionModel(
  client: any,
  sessionID: string,
): Promise<{ providerID: string; modelID: string } | null> {
  try {
    const res = await client.session.messages({ path: { id: sessionID } });
    const list = res?.data ?? [];
    for (let i = list.length - 1; i >= 0; i--) {
      const info = list[i]?.info;
      if (!info) continue;
      if (info.role === "assistant" && info.providerID && info.modelID) {
        return { providerID: info.providerID, modelID: info.modelID };
      }
      if (info.role === "user" && info.model?.providerID && info.model?.modelID) {
        return { providerID: info.model.providerID, modelID: info.model.modelID };
      }
    }
  } catch {
    // Ignored: caller falls back to the global default model.
  }
  return null;
}

type ResolvedModel = { providerID: string; modelID: string; source: string };

// Model precedence for one advisor call: per-call args, environment,
// advisor settings ("auto" = follow the calling session), calling
// session's active model, global default model.
async function resolveModel(
  client: any,
  context: any,
  args: { providerID?: string; modelID?: string },
): Promise<ResolvedModel | { error: string }> {
  if (args.providerID && args.modelID) {
    return { providerID: args.providerID, modelID: args.modelID, source: "per-call args" };
  }
  const env = resolveModelFromEnv();
  if (env) return { ...env, source: "environment" };
  if (settings.model && settings.model !== "auto") {
    const parsed = splitModel(settings.model);
    if (parsed) return { ...parsed, source: "advisor settings" };
    // Malformed value: fall through to the session model.
  }
  const sessionID = context?.sessionID;
  if (typeof sessionID === "string" && sessionID.length > 0) {
    const active = await sessionModel(client, sessionID);
    if (active) return { ...active, source: "calling session" };
  }
  if (globalDefaultModel) {
    const parsed = splitModel(globalDefaultModel);
    if (parsed) return { ...parsed, source: "global default model" };
  }
  return { error: "no model available: set one via /advisor configure model=<provider/model>" };
}

// One-line description of the configured model for status output.
function describeConfiguredModel(): string {
  const env = resolveModelFromEnv();
  if (env) return `${env.providerID}/${env.modelID} (from environment)`;
  if (settings.model === "auto") return "auto (follows the calling session model)";
  return `${settings.model} (from advisor settings)`;
}

function statusText(): string {
  return [
    `Advisor ${VERSION}: ${settings.enabled ? "enabled" : "disabled"}.`,
    `Model: ${describeConfiguredModel()}.`,
  ].join("\n");
}

function usageText(): string {
  return [
    "Usage: /advisor [on|off|status|configure]",
    "  on       Enable the advisor.",
    "  off      Disable the advisor (the tool answers with a disabled notice).",
    "  status   Show current state.",
    "  configure [model=<provider/model|auto>] [enabled=on|off]",
    "           With no args, shows current settings. Empty model means auto.",
  ].join("\n");
}

// Handles /advisor subcommands. Returns the reply text for the command card.
function handleCommand(rawArgs: string): string {
  const tokens = (rawArgs || "")
    .trim()
    .split(/\s+/)
    .filter((t) => t.length > 0);
  const sub = (tokens[0] || "status").toLowerCase();
  if (sub === "on") {
    settings.enabled = true;
    const err = persistSettings();
    return err ? `Advisor enabled for this process, but not saved: ${err}` : "Advisor enabled.";
  }
  if (sub === "off") {
    settings.enabled = false;
    const err = persistSettings();
    return err ? `Advisor disabled for this process, but not saved: ${err}` : "Advisor disabled. The advisor tool will answer with a disabled notice until /advisor on.";
  }
  if (sub === "status") return statusText();
  if (sub === "configure") {
    if (tokens.length === 1) return `${statusText()}\n\n${usageText()}`;
    for (const token of tokens.slice(1)) {
      const eq = token.indexOf("=");
      if (eq === -1) return `Unknown option "${token}".\n\n${usageText()}`;
      const key = token.slice(0, eq).toLowerCase();
      const value = token.slice(eq + 1);
      if (key === "model") {
        if (value.length === 0 || value.toLowerCase() === "auto") {
          settings.model = "auto";
        } else if (value.includes("/")) {
          settings.model = value;
        } else {
          return `Bad model "${value}". Use provider/model or auto.\n\n${usageText()}`;
        }
      } else if (key === "enabled") {
        if (value.toLowerCase() === "on") settings.enabled = true;
        else if (value.toLowerCase() === "off") settings.enabled = false;
        else return `Bad enabled value "${value}". Use on or off.\n\n${usageText()}`;
      } else {
        return `Unknown option "${key}".\n\n${usageText()}`;
      }
    }
    const err = persistSettings();
    return `${err ? `Applied for this process, but not saved: ${err}\n` : "Saved.\n"}${statusText()}`;
  }
  return usageText();
}

const SYSTEM_PROMPT = `You are a strategic advisor for a coding agent. Read the context below and provide a concise plan or course correction.

Your advice must be actionable — tell the executor:
- What to do next
- What order to proceed in
- What to watch out for
- What not to do

Key heuristics:
- Prefer the simplest approach that meets the spec
- Flag approaches that create maintenance burden
- If the executor is stuck or looping, suggest a different approach
- If tests or evidence contradict an assumption, say so explicitly

Respond in under 300 words. Use enumerated steps. Do NOT write code — only advise.`;

const TOOL_DESCRIPTION = `Consult a strategic advisor (a second model giving a concise plan or course correction; defaults to reusing your own active model unless configured otherwise) that requires all context necessary for the advisor tool and provides a concise plan or course correction.

Call advisor BEFORE substantive work — before writing code, editing files, committing to an interpretation, or building on an assumption. If the task requires orientation first (finding files, reading code, fetching docs), do that, then call advisor. Orientation is NOT substantive work.

Also call advisor:
- When stuck — errors recurring, approach not converging, results that don't fit
- When considering a change of approach
- When you believe the task is complete. BEFORE this call, make your deliverable durable: write the file, save the result, commit the change

On tasks longer than a few steps, call advisor at least once before committing to an approach and once before declaring done. On short reactive turns where tool output directly dictates the next action, skip advisor.

Optional tool args \`providerID\` and \`modelID\` override the advisor model for this one call; leave them blank to use the configured default (/advisor status shows it).

Required tool arg \`prompt\` must include all context the advisor needs for this call.

Give the advice serious weight. Only override if you have primary-source evidence that contradicts a specific claim. Surface conflicts in another advisor call rather than silently switching approaches.`;

export const AdvisorPlugin: Plugin = async ({ client }, options) => {
  if (options && typeof options === "object") {
    applyOptions(options as Record<string, unknown>);
  }
  return {
    config: async (config: any) => {
      // When loaded from a local path (no options), read our tuple from the
      // plugin array in opencode.json(c).
      const entries = config?.plugin ?? [];
      for (const entry of entries) {
        if (
          Array.isArray(entry) &&
          typeof entry[0] === "string" &&
          entry[0].includes(PLUGIN_ENTRY_SUFFIX) &&
          entry[1] &&
          typeof entry[1] === "object"
        ) {
          applyOptions(entry[1] as Record<string, unknown>);
        }
      }
      if (typeof config?.model === "string" && config.model.length > 0) {
        globalDefaultModel = config.model;
      }
    },
    "command.execute.before": async (input: any, output: any) => {
      if (input?.command !== COMMAND) return;
      output.parts = [{ type: "text", text: handleCommand(input.arguments ?? "") }];
    },
    tool: {
      advisor: tool({
        description: TOOL_DESCRIPTION,
        args: {
          prompt: tool.schema.string(),
          providerID: tool.schema.string().default(""),
          modelID: tool.schema.string().default(""),
        },
        async execute(args: any, context: any) {
          if (!settings.enabled) {
            return "Advisor is disabled. Run /advisor on to enable it.";
          }
          if (inAdvisorCall) {
            return "Error: advisor tool cannot be called recursively. The advisor model must respond with text only.";
          }
          if (typeof args.prompt !== "string" || args.prompt.trim().length === 0) {
            return "Error: advisor prompt is required and must not be empty.";
          }
          const resolved = await resolveModel(client, context, args);
          if ("error" in resolved) return `Error: ${resolved.error}`;
          try {
            inAdvisorCall = true;
            const session = await client.session.create({
              body: { title: "advisor-subcall" },
            });
            try {
              const model = {
                providerID: resolved.providerID,
                modelID: resolved.modelID,
              };
              const response = await client.session.prompt({
                path: { id: session.data!.id },
                body: {
                  model,
                  parts: [
                    {
                      type: "text",
                      text: `${SYSTEM_PROMPT}\n\n--- CONTEXT ---\n\n${args.prompt.trim()}`,
                    },
                  ],
                },
              });
              const text = response.data?.parts
                ?.filter((p: any) => p.type === "text")
                .map((p: any) => p.text)
                .join("\n");
              return text || "Advisor returned no advice.";
            } finally {
              await client.session.delete({ path: { id: session.data!.id } }).catch(() => {});
            }
          } finally {
            inAdvisorCall = false;
          }
        },
      }),
    },
  };
};
