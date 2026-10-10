import { type Plugin, tool } from "@opencode-ai/plugin";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// oc advisor plugin: registers the advisor tool (pull-style second-model
// guidance). /advisor on|off|status|configure is a plain command template
// (commands/advisor.md) carried out by the model itself: hook-set command
// output is ignored for TUI-invoked commands in current opencode, so the
// template reads/edits our tuple in opencode.json(c) directly. The tool
// re-reads settings from disk on every call, so those edits apply without
// a restart.

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

// Effective settings for one call. Re-read from disk every time so /advisor
// edits (which change the file) apply immediately, no restart needed.
// Precedence: defaults, init options, file tuple.
function currentSettings(): AdvisorSettings {
  const file = readOwnOptions();
  return {
    enabled: file.enabled ?? initOptions.enabled ?? DEFAULT_SETTINGS.enabled,
    model: file.model ?? initOptions.model ?? DEFAULT_SETTINGS.model,
  };
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
