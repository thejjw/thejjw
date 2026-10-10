import { type Plugin, tool } from "@opencode-ai/plugin";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// oc advisor plugin: registers the advisor tool (pull-style second-model
// guidance) plus the advisor_ctl tool (programmatic management: status,
// on/off/configure, implemented in code). /advisor is a thin command
// template (commands/advisor.md) that tells the model to call advisor_ctl
// and relay its result.
//
// Why not intercept the command from the plugin? command.execute.before
// DOES fire for TUI-invoked slash commands, but its output is ignored:
// traced live on opencode 1.18.35, the hook ran to completion, built the
// exact 72-byte status reply, assigned output.parts without error, and the
// default template path ran anyway. Upstream confirms the gap: the hook can
// only mutate parts, never skip the following LLM turn (anomalyco/opencode
// issues 25916, 28292, 18554; noReply plumbing PR 46579 still open). The
// only workaround is throwing a sentinel error, which surfaces as a bogus
// command failure, so we do not use it. If a later opencode honors hook
// output, a 5-line hook calling applyCommand() restores interception; the
// logic is already shaped for it.
//
// Consequences of the above: the tool re-reads settings from disk on every
// call, so control changes apply without a restart.

// Version of this copy. Reported by advisor_ctl status.
const VERSION = "0.1.0";

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

// Options captured from our plugin-entry tuple at startup. The file tuple
// (see currentSettings) wins when both exist.
let initOptions: { enabled?: boolean; model?: string } = {};

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

// Reads our plugin-entry options into init state. Accepts { enabled, model }
// and the upstream { providerID, modelID } form.
function applyOptions(opts: Record<string, unknown>) {
  if (typeof opts.enabled === "boolean") initOptions.enabled = opts.enabled;
  if (typeof opts.model === "string" && opts.model.length > 0) {
    initOptions.model = opts.model;
  } else if (typeof opts.providerID === "string" && typeof opts.modelID === "string") {
    initOptions.model = `${opts.providerID}/${opts.modelID}`;
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

// Reads our tuple's options straight from disk. Parsed with regexes (never
// a full parse), so comments and formatting in opencode.json(c) do not
// matter. Empty when absent or unreadable.
function readOwnOptions(): { enabled?: boolean; model?: string } {
  let text: string;
  try {
    text = fs.readFileSync(userConfigPath(), "utf8");
  } catch {
    return {};
  }
  const span = findOwnOptions(text);
  if (!span) return {};
  const body = text.slice(span.start, span.end);
  const out: { enabled?: boolean; model?: string } = {};
  const enabled = /"enabled"\s*:\s*(true|false)/.exec(body);
  if (enabled) out.enabled = enabled[1] === "true";
  const model = /"model"\s*:\s*"([^"]*)"/.exec(body);
  if (model) out.model = model[1];
  return out;
}

// Effective settings for one call. Re-read from disk every time so control
// changes apply immediately, no restart needed. Precedence: defaults, init
// options, file tuple.
function currentSettings(): AdvisorSettings {
  const file = readOwnOptions();
  return {
    enabled: file.enabled ?? initOptions.enabled ?? DEFAULT_SETTINGS.enabled,
    model: file.model ?? initOptions.model ?? DEFAULT_SETTINGS.model,
  };
}

// Writes the given settings into our own plugin tuple. Surgical: only the
// options object is replaced, so comments and formatting elsewhere in the
// file survive. Returns an error message, or null on success.
function writeOwnOptions(next: AdvisorSettings): string | null {
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
  const replacement = `{ "enabled": ${next.enabled ? "true" : "false"}, "model": ${JSON.stringify(next.model)} }`;
  try {
    fs.writeFileSync(file, text.slice(0, span.start) + replacement + text.slice(span.end), "utf8");
  } catch (error) {
    return `cannot write ${file}: ${(error as Error).message}`;
  }
  return null;
}

// One-line description of the given settings for status output.
function describeSettings(settings: AdvisorSettings): string {
  const env = resolveModelFromEnv();
  if (env) return `${env.providerID}/${env.modelID} (from environment)`;
  if (settings.model === "auto") return "auto (follows the calling session model)";
  return `${settings.model} (from advisor settings)`;
}

function statusText(settings: AdvisorSettings): string {
  return [
    `Advisor ${VERSION}: ${settings.enabled ? "enabled" : "disabled"}.`,
    `Model: ${describeSettings(settings)}.`,
  ].join("\n");
}

function usageText(): string {
  return [
    "Usage: /advisor [on|off|status|models|configure]",
    "  on       Enable the advisor.",
    "  off      Disable the advisor (the tool answers with a disabled notice).",
    "  status   Show current state.",
    "  models   List provider/model ids usable with configure model=.",
    "  configure [model=<id|name|auto>] [enabled=on|off]",
    "           model accepts an exact provider/model id, a display name,",
    "           or a substring (unambiguous match applies, else a pick",
    "           list). Empty model means auto.",
  ].join("\n");
}

// One configured model candidate: provider/model id plus the display name
// the TUI shows (e.g. "Muse Spark 1.3 Free"), so users can type either.
type ModelCandidate = { providerID: string; modelID: string; name: string };

// All models of all configured providers, via client.config.providers().
// Empty when unreachable (caller falls back to verbatim input).
async function listModels(client: any): Promise<ModelCandidate[]> {
  try {
    const res = await client.config.providers();
    const providers = res?.data?.providers ?? res?.providers ?? [];
    const out: ModelCandidate[] = [];
    for (const provider of providers) {
      const models = provider?.models ?? {};
      for (const [key, model] of Object.entries(models) as Array<[string, any]>) {
        out.push({
          providerID: provider.id ?? model?.providerID ?? "",
          modelID: model?.id ?? key,
          name: model?.name ?? "",
        });
      }
    }
    return out.filter((m) => m.providerID && m.modelID);
  } catch {
    return [];
  }
}

// Resolves free-typed model input to a "provider/model" id (or "auto").
// Exact ids apply directly; anything else fuzzy-matches id and display
// name case-insensitively. Returns the id to store, or an error message
// (with a pick list when ambiguous). Never throws.
async function resolveModelInput(client: any, value: string): Promise<{ id: string } | { error: string }> {
  const text = (value || "").trim();
  if (text.length === 0 || text.toLowerCase() === "auto") return { id: "auto" };
  const candidates = await listModels(client);
  const lower = text.toLowerCase();
  const exact = candidates.find((m) => `${m.providerID}/${m.modelID}`.toLowerCase() === lower);
  if (exact) return { id: `${exact.providerID}/${exact.modelID}` };
  if (candidates.length === 0) {
    // Provider list unreachable: accept verbatim rather than blocking.
    if (text.includes("/")) return { id: text };
    return { error: `Bad model "${text}". Use provider/model or auto.` };
  }
  const hits = candidates.filter(
    (m) => `${m.providerID}/${m.modelID}`.toLowerCase().includes(lower) || m.name.toLowerCase().includes(lower),
  );
  if (hits.length === 1) return { id: `${hits[0].providerID}/${hits[0].modelID}` };
  if (hits.length > 1) {
    const shown = hits
      .slice(0, 8)
      .map((m) => `  ${m.providerID}/${m.modelID}${m.name ? ` (${m.name})` : ""}`)
      .join("\n");
    const more = hits.length > 8 ? `\n  ...and ${hits.length - 8} more` : "";
    return { error: `"${text}" matches ${hits.length} models, be more specific:\n${shown}${more}` };
  }
  return { error: `No model matches "${text}". Run \`opencode models\` for exact provider/model ids, or use auto.` };
}

// Applies one control command (on|off|status|configure ...) in code and
// returns the exact reply text. This backs the advisor_ctl tool, which the
// /advisor template invokes.
async function applyCommand(client: any, rawArgs: string): Promise<string> {
  const tokens = (rawArgs || "")
    .trim()
    .split(/\s+/)
    .filter((t) => t.length > 0);
  const sub = (tokens[0] || "status").toLowerCase();
  const live = currentSettings();
  if (sub === "on") {
    const err = writeOwnOptions({ ...live, enabled: true });
    if (err) return `Error: not saved: ${err}`;
    return "Advisor enabled.";
  }
  if (sub === "off") {
    const err = writeOwnOptions({ ...live, enabled: false });
    if (err) return `Error: not saved: ${err}`;
    return "Advisor disabled. The advisor tool will answer with a disabled notice until /advisor on.";
  }
  if (sub === "status") return statusText(live);
  if (sub === "models") {
    const candidates = await listModels(client);
    if (candidates.length === 0) {
      return "Could not list models from the provider registry. Run `opencode models` for exact provider/model ids.";
    }
    const lines = candidates.map(
      (m) => `${m.providerID}/${m.modelID}${m.name ? ` (${m.name})` : ""}`,
    );
    return `${candidates.length} models (use one with /advisor configure model=):\n${lines.join("\n")}`;
  }
  if (sub === "configure") {
    // Rejoin: display names contain spaces, so model= consumes everything
    // up to an enabled= clause or the end, in any order.
    const argStr = tokens.slice(1).join(" ");
    if (!argStr) return `${statusText(live)}\n\n${usageText()}`;
    const next = { ...live };
    let rest = argStr;
    const modelMatch = /(?:^|\s)model\s*=\s*(.*?)(?=\s+enabled\s*=\s*\S+|$)/i.exec(argStr);
    if (modelMatch) {
      rest = rest.replace(modelMatch[0], " ");
      const resolved = await resolveModelInput(client, (modelMatch[1] || "").trim());
      if ("error" in resolved) return `${resolved.error}\n\n${usageText()}`;
      next.model = resolved.id;
    }
    const enabledMatch = /(?:^|\s)enabled\s*=\s*(\S+)/i.exec(argStr);
    if (enabledMatch) {
      rest = rest.replace(enabledMatch[0], " ");
      const value = enabledMatch[1].toLowerCase();
      if (value === "on") next.enabled = true;
      else if (value === "off") next.enabled = false;
      else return `Bad enabled value "${enabledMatch[1]}". Use on or off.\n\n${usageText()}`;
    }
    if (rest.trim().length > 0) return `Unknown option "${rest.trim()}".\n\n${usageText()}`;
    const err = writeOwnOptions(next);
    if (err) return `Error: not saved: ${err}`;
    return `Saved.\n${statusText(next)}`;
  }
  return usageText();
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
  settings: AdvisorSettings,
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
    tool: {
      // Programmatic control surface. A custom tool (not a command hook)
      // because hook output cannot steer TUI-invoked commands (see header).
      advisor_ctl: tool({
        description:
          "Control the oc advisor plugin itself (status, on/off, configure). This manages the advisor; it is not the advisor. Call it when the user invokes /advisor, passing the words after /advisor as the action (empty means status), and relay its result back verbatim without adding anything.",
        args: {
          action: tool.schema.string().default(""),
        },
        async execute(args: any) {
          return applyCommand(client, typeof args.action === "string" ? args.action : "");
        },
      }),
      advisor: tool({
        description: TOOL_DESCRIPTION,
        args: {
          prompt: tool.schema.string(),
          providerID: tool.schema.string().default(""),
          modelID: tool.schema.string().default(""),
        },
        async execute(args: any, context: any) {
          const live = currentSettings();
          if (!live.enabled) {
            return "Advisor is disabled. Run /advisor on to enable it.";
          }
          if (inAdvisorCall) {
            return "Error: advisor tool cannot be called recursively. The advisor model must respond with text only.";
          }
          if (typeof args.prompt !== "string" || args.prompt.trim().length === 0) {
            return "Error: advisor prompt is required and must not be empty.";
          }
          const resolved = await resolveModel(client, context, args, live);
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
