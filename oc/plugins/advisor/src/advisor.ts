import { Plugin } from "@opencode/plugin";
import fs from "node:fs";
import path from "node:path";

// oc advisor plugin (v2 API): registers the advisor tool (pull-style
// second-model guidance) plus the advisor_ctl tool (programmatic
// management: status, on/off, models, thinking, configure). /advisor is a
// thin command template (commands/advisor.md) that tells the model to call
// advisor_ctl and relay its result.
//
// Ported from the v1 implementation (see git history). V1 code does not
// run on v2 hosts, so the scaffolding is rewritten against @opencode/plugin
// while the behavior contract is preserved:
// - pull-style: the executor decides when to call advisor, following the
//   timing rules in the tool description.
// - each call creates an ephemeral session, prompts the advisor model with
//   a short reviewer preamble plus caller-supplied context, returns the
//   text, then deletes the session. A recursion guard stops re-entry.
// - settings live in plugin storage (ctx.storage), seeded once from plugin
//   options; no hand-edited config surgery.

// Version of this copy. Reported by advisor_ctl status.
const VERSION = "0.2.0";

// Persisted settings. model "auto" means: reuse the calling session's
// active model. thinking "auto" means: mirror the calling session's
// variant when the model is also followed, else use the catalog default
// (pass no variant). An explicit thinking value is a variant id validated
// against the resolved model's catalog variants.
type AdvisorSettings = {
  enabled: boolean;
  model: string;
  thinking: string;
  watch: boolean;
  reviewInterval: number;
};

const DEFAULT_SETTINGS: AdvisorSettings = {
  enabled: true,
  model: "auto",
  thinking: "auto",
  watch: false,
  reviewInterval: 1,
};

const STORAGE_KEY = "settings";
const LAST_REVIEW_KEY = "lastReview";

// Summary of the most recent auto-review delivery, for /advisor status.
type LastReview = {
  time: number;
  sessionID: string;
  severity: "nit" | "concern" | "blocker";
  preview: string;
};

async function readLastReview(ctx: any): Promise<LastReview | null> {
  try {
    const raw = (await ctx.storage.get(LAST_REVIEW_KEY)) as Record<string, unknown> | undefined;
    if (raw && typeof raw === "object" && typeof raw.time === "number" && typeof raw.sessionID === "string") {
      return {
        time: raw.time,
        sessionID: raw.sessionID,
        severity: raw.severity === "blocker" || raw.severity === "concern" ? raw.severity : "nit",
        preview: typeof raw.preview === "string" ? raw.preview : "",
      };
    }
  } catch {
    // Ignored.
  }
  return null;
}

// Guard against the advisor model calling back into the advisor tool.
let inAdvisorCall = false;

// One catalog model: provider/model id, display name, variant ids, and
// flags feeding the /advisor models pick.
type ModelCandidate = {
  providerID: string;
  modelID: string;
  name: string;
  variants: string[];
  free: boolean;
  context: number;
  status: string;
  enabled: boolean;
};

// Splits "provider/model" into parts. Null when malformed. A "#variant"
// suffix is rejected here: variants belong in thinking, not the model id.
function splitModel(value: string): { providerID: string; modelID: string } | null {
  const hash = value.indexOf("#");
  if (hash !== -1) return null;
  const [providerID, ...rest] = value.split("/");
  if (!providerID || rest.length === 0) return null;
  return { providerID, modelID: rest.join("/") };
}

// Splits "provider/model[#variant]" used by configure model= and the
// environment override. The variant part (if any) is returned unvalidated;
// callers validate it against the model's catalog variants.
function splitModelRef(value: string): { providerID: string; modelID: string; variant?: string } | null {
  const text = (value || "").trim();
  const hash = text.indexOf("#");
  const head = hash === -1 ? text : text.slice(0, hash);
  const variant = hash === -1 ? undefined : text.slice(hash + 1);
  const parsed = splitModel(head);
  if (!parsed) return null;
  if (variant !== undefined && variant.length === 0) return null;
  return { ...parsed, variant };
}

// Optional model override from the environment, with optional #variant.
function resolveModelFromEnv(): { providerID: string; modelID: string; variant?: string } | null {
  const env = (typeof process !== "undefined" && process.env) || {};
  const combined = env.OPENCODE_ADVISOR_MODEL;
  if (combined && combined.includes("/")) {
    const parsed = splitModelRef(combined);
    if (parsed) {
      const envVariant = env.OPENCODE_ADVISOR_VARIANT;
      if (envVariant && envVariant.length > 0 && !parsed.variant) parsed.variant = envVariant;
      return parsed;
    }
    return null;
  }
  const providerID = env.OPENCODE_ADVISOR_PROVIDER;
  const modelID = env.OPENCODE_ADVISOR_MODEL;
  if (providerID && modelID) {
    const parsed = splitModel(`${providerID}/${modelID}`);
    if (!parsed) return null;
    const envVariant = env.OPENCODE_ADVISOR_VARIANT;
    return { ...parsed, variant: envVariant && envVariant.length > 0 ? envVariant : undefined };
  }
  return null;
}

// Reads settings: storage wins once written, plugin options seed first run,
// defaults last. Never throws; callers get usable settings offline.
async function currentSettings(ctx: any): Promise<AdvisorSettings> {
  const opts = (ctx?.options ?? {}) as Record<string, unknown>;
  let stored: AdvisorSettings | null = null;
  try {
    const raw = await ctx.storage.get(STORAGE_KEY);
    if (raw && typeof raw === "object") {
      const r = raw as Record<string, unknown>;
      stored = {
        enabled: typeof r.enabled === "boolean" ? r.enabled : DEFAULT_SETTINGS.enabled,
        model: typeof r.model === "string" && r.model.length > 0 ? r.model : DEFAULT_SETTINGS.model,
        thinking:
          typeof r.thinking === "string" && r.thinking.length > 0 ? r.thinking : DEFAULT_SETTINGS.thinking,
        watch: typeof r.watch === "boolean" ? r.watch : DEFAULT_SETTINGS.watch,
        reviewInterval:
          typeof r.reviewInterval === "number" && Number.isInteger(r.reviewInterval) && r.reviewInterval >= 1
            ? r.reviewInterval
            : DEFAULT_SETTINGS.reviewInterval,
      };
    }
  } catch {
    stored = null;
  }
  if (stored) return stored;
  return {
    enabled: typeof opts.enabled === "boolean" ? opts.enabled : DEFAULT_SETTINGS.enabled,
    model: typeof opts.model === "string" && (opts.model as string).length > 0 ? (opts.model as string) : DEFAULT_SETTINGS.model,
    thinking:
      typeof opts.thinking === "string" && (opts.thinking as string).length > 0
        ? (opts.thinking as string)
        : DEFAULT_SETTINGS.thinking,
    watch: typeof opts.watch === "boolean" ? opts.watch : DEFAULT_SETTINGS.watch,
    reviewInterval:
      typeof opts.reviewInterval === "number" && Number.isInteger(opts.reviewInterval) && (opts.reviewInterval as number) >= 1
        ? (opts.reviewInterval as number)
        : DEFAULT_SETTINGS.reviewInterval,
  };
}

async function writeSettings(ctx: any, next: AdvisorSettings): Promise<string | null> {
  try {
    await ctx.storage.set(STORAGE_KEY, { ...next });
  } catch (error) {
    return `cannot persist settings: ${(error as Error).message}`;
  }
  return null;
}

// One-line description of the given settings for status output.
function describeSettings(settings: AdvisorSettings, env: { providerID: string; modelID: string; variant?: string } | null): string {
  if (env) return `${env.providerID}/${env.modelID}${env.variant ? `#${env.variant}` : ""} (from environment)`;
  const model = settings.model === "auto" ? "auto (follows the calling session model)" : settings.model;
  const thinking = settings.thinking === "auto" ? "auto" : settings.thinking;
  return `${model}, thinking ${thinking} (from advisor settings)`;
}

function statusText(
  settings: AdvisorSettings,
  env: { providerID: string; modelID: string; variant?: string } | null,
  last: LastReview | null,
): string {
  const lines = [
    `Advisor ${VERSION}: ${settings.enabled ? "enabled" : "disabled"}.`,
    `Model: ${describeSettings(settings, env)}.`,
    `Watch: ${settings.watch ? `on (every ${settings.reviewInterval === 1 ? "turn" : `${settings.reviewInterval} turns`})` : "off"}.`,
  ];
  if (last) {
    const when = new Date(last.time).toLocaleString();
    lines.push(`Last review: [${last.severity}] ${when}${last.preview ? ` — ${last.preview}` : ""}`);
  }
  return lines.join("\n");
}

function usageText(): string {
  return [
    "Usage: /advisor [on|off|status|models|thinking|configure]",
    "  on       Enable the advisor.",
    "  off      Disable the advisor (the tool answers with a disabled notice).",
    "  status   Show current state.",
    "  models   Write available models to a file and recommend 4-5.",
    "  thinking List valid thinking variants for the advisor model.",
    "  configure [model=<id|name|auto>] [thinking=<variant|auto>] [enabled=on|off] [watch=on|off] [reviewInterval=N]",
    "           model accepts an exact provider/model id, a display name,",
    "           or a substring (unambiguous match applies, else a pick",
    "           list). Empty model means auto. thinking accepts a variant",
    "           id valid for the resolved model, or auto. watch enables",
    "           automatic turn-boundary reviews; reviewInterval reviews",
    "           every Nth turn (default 1).",
  ].join("\n");
}

// All catalog models via ctx.model.list(). The call returns a
// { location, data } envelope (a bare array is also tolerated). Empty
// when unreachable. A model counts as free when its name mentions free
// or every cost tier is zero input+output.
async function listModels(ctx: any, directory?: string): Promise<ModelCandidate[]> {
  try {
    const res = directory ? await ctx.model.list({ location: { directory } }) : await ctx.model.list();
    const models = Array.isArray(res) ? res : (res?.data ?? []);
    const out: ModelCandidate[] = [];
    for (const model of models ?? []) {
      const costs = Array.isArray(model?.cost) ? model.cost : [];
      const priced = costs.some((c: any) => (c?.input ?? 0) !== 0 || (c?.output ?? 0) !== 0);
      const name = model?.name ?? "";
      const variants = Array.isArray(model?.variants) ? model.variants.map((v: any) => String(v?.id ?? "")).filter(Boolean) : [];
      out.push({
        providerID: model?.providerID ?? "",
        modelID: model?.modelID ?? model?.id ?? "",
        name,
        variants,
        free: /free/i.test(name) || (costs.length > 0 && !priced),
        context: typeof model?.limit?.context === "number" ? model.limit.context : 0,
        status: typeof model?.status === "string" ? model.status : "",
        enabled: model?.enabled !== false,
      });
    }
    return out.filter((m) => m.providerID && m.modelID);
  } catch {
    return [];
  }
}

// Pick criteria for /advisor models. Shared by the file dump fallback and
// the compact summary.
const MODELS_CRITERIA: string[] = [
  "What makes a good advisor: it must rank at or above the main executor",
  "model, so it catches what the doer rushes past. Strong reasoning and",
  "instruction-following matter more than speed, and occasional use keeps",
  "a premium model still affordable. For providers, prefer opencode-go",
  "first (subscription, use-or-waste), then consider opencode/ providers",
  "(compatibility-tested). Include one or two free models when available.",
];

// Timestamp like 20261010-201500 for the models dump filename.
function dumpTimestamp(): string {
  const now = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  return `${now.getFullYear()}${p(now.getMonth() + 1)}${p(now.getDate())}-${p(now.getHours())}${p(now.getMinutes())}${p(now.getSeconds())}`;
}

// Candidates grouped by provider, one header per provider plus one line
// per model. Variant ids are shown when few, else a count.
function formatModelLines(candidates: ModelCandidate[]): string[] {
  const byProvider = new Map<string, ModelCandidate[]>();
  for (const m of candidates) {
    const list = byProvider.get(m.providerID) ?? [];
    list.push(m);
    byProvider.set(m.providerID, list);
  }
  const lines: string[] = [];
  for (const [providerID, list] of [...byProvider.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    lines.push(`${providerID} (${list.length}):`);
    for (const m of list.sort((a, b) => a.modelID.localeCompare(b.modelID))) {
      const tags: string[] = [];
      if (m.name && m.name !== m.modelID) tags.push(m.name);
      if (m.free) tags.push("free");
      if (m.variants.length > 0 && m.variants.length <= 4) tags.push(`variants: ${m.variants.join(", ")}`);
      else if (m.variants.length > 4) tags.push(`${m.variants.length} variants`);
      if (m.status && m.status !== "active") tags.push(m.status);
      if (!m.enabled) tags.push("disabled");
      lines.push(`  ${m.providerID}/${m.modelID}${tags.length > 0 ? ` (${tags.join(", ")})` : ""}`);
    }
  }
  return lines;
}

function modelsFileText(candidates: ModelCandidate[]): string {
  return [`Available models (${candidates.length}):`, ...formatModelLines(candidates)].join("\n");
}

function modelsCounts(candidates: ModelCandidate[]): string {
  const counts = new Map<string, number>();
  for (const m of candidates) counts.set(m.providerID, (counts.get(m.providerID) ?? 0) + 1);
  return [...counts.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([id, n]) => `${id} (${n})`)
    .join(", ");
}

function modelsDumpFallback(): string {
  return [
    "Could not list models via the model catalog.",
    "Run `opencode models > models_<timestamp>.txt` in the workspace root",
    "(timestamp like 20261010-201500 from the current date and time), read",
    "the file back, and recommend 4-5 as the advisor model.",
    "",
    ...MODELS_CRITERIA,
    "Present your picks with one-line reasons and exact ids ready",
    "for /advisor configure model=<id>.",
  ].join("\n");
}

function modelsSummary(candidates: ModelCandidate[], executor: string | null, file: string): string {
  return [
    `Wrote ${candidates.length} models to ${file}.`,
    `By provider: ${modelsCounts(candidates)}.`,
    ...(executor ? [`Current executor model: ${executor}.`] : []),
    "",
    ...MODELS_CRITERIA,
    "",
    `Read ${file} and recommend 4-5 as the advisor model: give one-line`,
    "reasons and exact ids ready for /advisor configure model=<id>.",
  ].join("\n");
}

// --- Push-style auto-review (watch mode) ---
//
// While the pull-style advisor tool waits to be called, watch mode reviews
// primary turn boundaries on its own: execution-end events snapshot the
// transcript delta since the last review into an ephemeral sidecar review,
// then deliver severity-tagged notes back (nits as record-only synthetic
// messages, concerns/blockers as new turns).
//
// Phase 2 sidecar: instead of a single transient generation, the sidecar
// runs a short tool loop (read/grep/glob under deny-by-default session
// permissions) so findings are verified against the workspace, then the
// final verdict text is parsed for severity. An emission guard (ported
// from omp's AdvisorEmissionGuard, adapted to one reply per review)
// suppresses noise, repeats, and over-budget findings; a cooldown
// downgrades concerns after a steered delivery.

// Turn-terminal events that end a reviewable unit of primary work.
const TURN_END_EVENTS = new Set([
  "session.execution.succeeded",
  "session.execution.failed",
  "session.execution.interrupted",
]);

// Prefix marking advisor-delivered turns, for the cascade guard: a
// boundary whose newest user message carries it is captured but never
// scheduled, so deliveries cannot re-wake reviewers in a loop.
const DELIVERY_MARKER = "[advisor-note] ";

// Sidecar sessions created by this process. Their own execution events
// are ignored so reviews never review themselves.
const sidecarSessions = new Set<string>();

// Sandbox permissions for the investigative sidecar: deny everything,
// then allow read-only discovery. Last matching rule wins.
const SIDECAR_PERMISSIONS = [
  { action: "*", resource: "*", effect: "deny" },
  { action: "read", resource: "*", effect: "allow" },
  { action: "glob", resource: "*", effect: "allow" },
  { action: "grep", resource: "*", effect: "allow" },
] as const;

// Upper bound for one sidecar tool loop. A timeout aborts the review
// rather than blocking later boundaries behind it.
const SIDECAR_TIMEOUT_MS = 3 * 60 * 1000;

// Turns after a steered concern/blocker during which new concerns ride
// as record-only notes instead of waking the agent. Blockers are exempt.
const IMMUNE_TURNS = 3;

// --- Emission guard (omp AdvisorEmissionGuard, adapted) ---
//
// One sidecar reply may hold several severity-tagged findings. The guard
// splits the reply into sections, drops noise and repeats (rank-aware:
// escalation re-admits), and caps non-blocker sections per review.

const SEVERITY_RANK = { nit: 1, concern: 2, blocker: 3 } as const;
type Severity = keyof typeof SEVERITY_RANK;

// Short content-free phrases that carry no finding.
const NOISE_PHRASES = new Set([
  "stop",
  "halt",
  "done",
  "complete",
  "lgtm",
  "no issue",
  "no issues",
  "nothing to add",
  "no concerns",
  "looks good",
  "continue",
  "proceed",
]);

function normalizeNote(text: string): string {
  return text
    .toLowerCase()
    .normalize("NFKC")
    .replace(/[^\p{L}\p{N}]+/gu, " ")
    .trim();
}

type Finding = { severity: Severity; text: string };

// Splits a review reply into severity-tagged findings. Lines starting
// with [nit]/[concern]/[blocker] open a section; untagged leading text
// becomes one nit finding (omp's omitted-severity default). Returns null
// for silence (NO_CONCERNS sentinel or empty).
function splitFindings(reply: string): Finding[] | null {
  const trimmed = (reply || "").trim();
  if (trimmed.length === 0 || trimmed === "NO_CONCERNS") return null;
  const findings: Finding[] = [];
  let current: Finding | null = null;
  for (const line of trimmed.split("\n")) {
    const m = /^\[(nit|concern|blocker)\]\s*(.*)$/i.exec(line.trim());
    if (m) {
      current = { severity: m[1].toLowerCase() as Severity, text: m[2] };
      findings.push(current);
    } else if (current) {
      current.text += `\n${line}`;
    } else if (line.trim().length > 0) {
      current = { severity: "nit", text: line };
      findings.push(current);
    }
  }
  const cleaned = findings
    .map((f) => ({ severity: f.severity, text: f.text.trim() }))
    .filter((f) => f.text.length > 0);
  return cleaned.length > 0 ? cleaned : null;
}

// Per-primary-session guard state (in-memory; resets on reload, which is
// safe: worst case a repeat is delivered once after a restart).
type GuardState = { seen: Map<string, number>; order: string[] };
const guardStates = new Map<string, GuardState>();

function guardFor(sessionID: string): GuardState {
  let state = guardStates.get(sessionID);
  if (!state) {
    state = { seen: new Map(), order: [] };
    guardStates.set(sessionID, state);
  }
  return state;
}

function guardReset(sessionID: string): void {
  guardStates.delete(sessionID);
}

// Admits reply findings through noise filter, rank-aware dedupe, and the
// per-review non-blocker budget (default 4, omp parity; blockers exempt).
// Returns the deliverable text, or null when nothing survives.
function guardAdmit(sessionID: string, reply: string, budget = 4): string | null {
  const findings = splitFindings(reply);
  if (!findings) return null;
  const state = guardFor(sessionID);
  const admitted: Finding[] = [];
  let nonBlockers = 0;
  for (const f of findings) {
    const key = normalizeNote(f.text);
    if (key.length === 0 || NOISE_PHRASES.has(key)) continue;
    const seenRank = state.seen.get(key) ?? 0;
    const rank = SEVERITY_RANK[f.severity];
    if (rank <= seenRank) continue;
    if (f.severity !== "blocker") {
      if (nonBlockers >= budget) continue;
      nonBlockers++;
    }
    state.seen.set(key, rank);
    state.order.push(key);
    if (state.order.length > 4096) {
      const oldest = state.order.shift();
      if (oldest) state.seen.delete(oldest);
    }
    admitted.push(f);
  }
  if (admitted.length === 0) return null;
  return admitted.map((f) => `[${f.severity}] ${f.text}`).join("\n\n");
}

// Overall severity of admitted text: highest tag present.
function overallSeverity(text: string): Severity {
  if (/\bblocker\b/i.test(text)) return "blocker";
  if (/\bconcern\b/i.test(text)) return "concern";
  return "nit";
}

// Cooldown after a steered delivery: remaining turns during which new
// concerns ride record-only instead of waking the agent. Blockers exempt.
function immuneKey(sessionID: string): string {
  return `immune:${sessionID}`;
}

async function readImmune(ctx: any, sessionID: string): Promise<number> {
  try {
    const raw = await ctx.storage.get(immuneKey(sessionID));
    if (typeof raw === "number" && raw > 0) return Math.floor(raw);
    if (raw && typeof raw === "object" && typeof (raw as any).turns === "number" && (raw as any).turns > 0) {
      return Math.floor((raw as any).turns);
    }
  } catch {
    // Ignored.
  }
  return 0;
}

async function writeImmune(ctx: any, sessionID: string, turns: number): Promise<void> {
  try {
    if (turns <= 0) await ctx.storage.remove(immuneKey(sessionID));
    else await ctx.storage.set(immuneKey(sessionID), { turns });
  } catch {
    // Ignored: cooldown is best-effort.
  }
}

// Last assistant text in a transcript (skips tool-only messages). The
// sidecar's verdict; null when absent.
function lastAssistantText(messages: any[]): string | null {
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i];
    if (!m || m.type !== "assistant" || !Array.isArray(m.content)) continue;
    const text = m.content
      .filter((p: any) => p && (p.type === "text" || p.type === "reasoning") && typeof p.text === "string")
      .map((p: any) => p.text)
      .join("\n")
      .trim();
    if (text.length > 0) return text;
  }
  return null;
}

// Runs one investigative sidecar review: prompt (tool loop under the
// sandbox permissions), bounded wait, then read the verdict. Returns the
// verdict text, or null on timeout/failure. Never throws.
async function runSidecarReview(
  ctx: any,
  model: { id: string; providerID: string; variant?: string },
  directory: string | null,
  promptText: string,
): Promise<string | null> {
  let sidecar: string | null = null;
  try {
    const session = await ctx.session.create({
      title: "advisor-review",
      model,
      ...(directory ? { location: { directory } } : {}),
      permissions: [...SIDECAR_PERMISSIONS],
    });
    sidecar = typeof session?.id === "string" && session.id.length > 0 ? session.id : null;
    if (!sidecar) return null;
    sidecarSessions.add(sidecar);
    await ctx.session.prompt({ sessionID: sidecar, text: promptText });
    const settled = await Promise.race([
      ctx.session.wait({ sessionID: sidecar }).then(() => true),
      new Promise<boolean>((resolve) => setTimeout(() => resolve(false), SIDECAR_TIMEOUT_MS)),
    ]);
    if (!settled) {
      await ctx.session.interrupt({ sessionID: sidecar, continue: false }).catch(() => {});
      return null;
    }
    const res = await ctx.session.context({ sessionID: sidecar });
    const messages = Array.isArray(res) ? res : (res?.data ?? []);
    if (!Array.isArray(messages)) return null;
    return lastAssistantText(messages);
  } catch {
    return null;
  } finally {
    if (sidecar) {
      sidecarSessions.delete(sidecar);
      await ctx.session.remove({ sessionID: sidecar }).catch(() => {});
    }
  }
}

type WatchCursor = { count: number; turns: number };

function cursorKey(sessionID: string): string {
  return `watch:${sessionID}`;
}

async function readCursor(ctx: any, sessionID: string): Promise<WatchCursor> {
  try {
    const raw = (await ctx.storage.get(cursorKey(sessionID))) as Record<string, unknown> | undefined;
    if (raw && typeof raw === "object") {
      const count = typeof raw.count === "number" && raw.count >= 0 ? Math.floor(raw.count) : 0;
      const turns = typeof raw.turns === "number" && raw.turns >= 0 ? Math.floor(raw.turns) : 0;
      return { count, turns };
    }
  } catch {
    // Ignored: start from zero.
  }
  return { count: 0, turns: 0 };
}

async function writeCursor(ctx: any, sessionID: string, cursor: WatchCursor): Promise<void> {
  try {
    await ctx.storage.set(cursorKey(sessionID), { ...cursor });
  } catch {
    // Ignored: next boundary re-derives from zero.
  }
}

// Best-effort text of the newest user message, for the cascade guard.
function newestUserText(messages: any[]): string | null {
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i];
    if (m && m.type === "user" && typeof m.text === "string") return m.text;
  }
  return null;
}

// Renders transcript messages into reviewable text: user text plus
// assistant text, tool calls with inputs, and tool results (truncated).
// Unknown message shapes are skipped rather than guessed at.
function renderDelta(messages: any[]): string {
  const perMessage = 1500;
  const totalCap = 12000;
  const out: string[] = [];
  let total = 0;
  const push = (line: string) => {
    if (total >= totalCap) return;
    const clipped = line.length > perMessage ? line.slice(0, perMessage) + " […]" : line;
    total += clipped.length;
    out.push(clipped);
  };
  const textOf = (part: any): string | null => {
    if (part && (part.type === "text" || part.type === "reasoning") && typeof part.text === "string") return part.text;
    return null;
  };
  for (const m of messages) {
    if (!m || typeof m !== "object") continue;
    if (m.type === "user" && typeof m.text === "string") {
      push(`User: ${m.text}`);
    } else if (m.type === "assistant" && Array.isArray(m.content)) {
      for (const part of m.content) {
        const text = textOf(part);
        if (text) {
          push(`Assistant: ${text}`);
        } else if (part && part.type === "tool" && typeof part.name === "string") {
          const state = part.state;
          const status = state && typeof state.status === "string" ? state.status : "unknown";
          push(`Tool ${part.name} (${status})`);
          if (state && state.input && typeof state.input === "object") {
            const input = JSON.stringify(state.input);
            push(`  input: ${input.length > 300 ? input.slice(0, 300) + " […]" : input}`);
          }
          if (state && Array.isArray(state.content)) {
            for (const c of state.content) {
              if (c && c.type === "text" && typeof c.text === "string" && c.text.length > 0) {
                push(`  result: ${c.text}`);
              }
            }
          }
          if (state && state.status === "error") {
            push(`  error: ${JSON.stringify(state.error ?? state).slice(0, 300)}`);
          }
        }
      }
    }
  }
  return out.join("\n").slice(0, totalCap);
}

// Handles one turn-terminal event. Never throws; resolve failures skip
// without advancing (cheap retry next boundary), execution failures
// advance (no retry storm).
async function handleTurnEnd(ctx: any, sessionID: string, interrupted: boolean): Promise<void> {
  const live = await currentSettings(ctx);
  if (!live.enabled || !live.watch) return;
  if (sidecarSessions.has(sessionID)) return;
  let messages: any[];
  try {
    const res = await ctx.session.context({ sessionID });
    messages = Array.isArray(res) ? res : (res?.data ?? []);
  } catch {
    return;
  }
  if (!Array.isArray(messages)) return;
  let cursor = await readCursor(ctx, sessionID);
  if (messages.length < cursor.count) {
    // Transcript rewritten (e.g. compaction): reseed, no replay. Guard
    // state resets with it so re-primed findings can re-raise.
    guardReset(sessionID);
    await writeCursor(ctx, sessionID, { count: messages.length, turns: 0 });
    return;
  }
  const fresh = messages.slice(cursor.count);
  if (fresh.length === 0) return;
  const turns = cursor.turns + 1;
  const interval = live.reviewInterval >= 1 ? live.reviewInterval : 1;
  // Capture-but-skip: our own delivery must never schedule a review.
  const newest = newestUserText(messages);
  if (newest && newest.startsWith(DELIVERY_MARKER)) {
    await writeCursor(ctx, sessionID, { count: messages.length, turns });
    return;
  }
  if (turns % interval !== 0) {
    // Cadence skip: count the turn but hold the delta for the next
    // scheduled review (cursor stays).
    await writeCursor(ctx, sessionID, { count: cursor.count, turns });
    return;
  }
  const delta = renderDelta(fresh);
  if (delta.trim().length === 0) {
    await writeCursor(ctx, sessionID, { count: messages.length, turns });
    return;
  }
  const resolved = await resolveModel(ctx, sessionID, {}, live);
  if ("error" in resolved) return;
  const model: { id: string; providerID: string; variant?: string } = {
    id: resolved.modelID,
    providerID: resolved.providerID,
  };
  if (resolved.variant) model.variant = resolved.variant;
  let directory: string | null = await sessionDirectory(ctx, sessionID);
  if (!directory && typeof ctx?.location?.directory === "string" && ctx.location.directory.length > 0) {
    directory = ctx.location.directory;
  }
  // Cooldown tick: every processed boundary ages the immune window.
  const immune = await readImmune(ctx, sessionID);
  if (immune > 0) await writeImmune(ctx, sessionID, immune - 1);
  const verdict = await runSidecarReview(
    ctx,
    model,
    directory,
    `${WATCH_SYSTEM_PROMPT}\n\n--- TRANSCRIPT DELTA ---\n\n${delta}`,
  );
  // Execution failure (timeout, model error, sandbox refusal): advance the
  // cursor so one bad review cannot retry-storm every later boundary.
  await writeCursor(ctx, sessionID, { count: messages.length, turns });
  if (!verdict) return;
  const admitted = guardAdmit(sessionID, verdict);
  if (!admitted) return;
  let severity = overallSeverity(admitted);
  const note = admitted;
  let delivered = false;
  // Interrupted primaries and immune-window concerns never wake the agent;
  // blockers always steer.
  const recordOnly = severity === "nit" || interrupted || (severity === "concern" && immune > 0);
  if (recordOnly) {
    // Record-only: never wake the agent (resume defaults to waking).
    try {
      await ctx.session.synthetic({ sessionID, text: `[advisor ${severity}]\n${note}`, resume: false });
      delivered = true;
    } catch {
      // Delivery failure: cursor already advanced, next boundary retries.
    }
  } else {
    try {
      await ctx.session.prompt({ sessionID, text: `${DELIVERY_MARKER}[advisor ${severity}]\n${note}` });
      delivered = true;
      // Steering restarts the cooldown (blockers exempt from aging it,
      // but a steered blocker still re-arms it for later concerns).
      await writeImmune(ctx, sessionID, IMMUNE_TURNS);
    } catch {
      // Delivery failure: cursor already advanced, next boundary retries.
    }
  }
    if (delivered) {
      const firstLine = note.split("\n", 1)[0] ?? "";
      try {
        await ctx.storage.set(LAST_REVIEW_KEY, {
          time: Date.now(),
          sessionID,
          severity,
          preview: firstLine.length > 120 ? firstLine.slice(0, 120) + " [...]" : firstLine,
        });
      } catch {
        // Observability only: never fail a review over it.
      }
    }
}

// Subscribes to turn-terminal events for the process lifetime. Returns a
// cleanup that stops the loop (run on plugin unload so hot reloads never
// double-subscribe).
function startWatchLoop(ctx: any): () => void {
  const controller = new AbortController();
  void (async () => {
    try {
      for await (const event of ctx.event.subscribe({ signal: controller.signal })) {
        try {
          const type = (event as any)?.type;
          if (typeof type !== "string" || !TURN_END_EVENTS.has(type)) continue;
          const data = (event as any)?.data ?? {};
          const sessionID = typeof data.sessionID === "string" ? data.sessionID : (event as any)?.sessionID;
          if (typeof sessionID !== "string" || sessionID.length === 0) continue;
          await handleTurnEnd(ctx, sessionID, type === "session.execution.interrupted");
        } catch {
          // Per-event failure: never break the loop.
        }
      }
    } catch {
      // Aborted on cleanup.
    }
  })();
  return () => controller.abort();
}

// Resolves free-typed model input to a "provider/model" id (or "auto").
// A "#variant" suffix is accepted as shorthand and split into a thinking
// value. Exact ids apply directly; anything else fuzzy-matches id and
// display name case-insensitively. Never throws.
async function resolveModelInput(
  ctx: any,
  value: string,
): Promise<{ id: string; thinking?: string } | { error: string }> {
  const text = (value || "").trim();
  if (text.length === 0 || text.toLowerCase() === "auto") return { id: "auto" };
  const ref = splitModelRef(text);
  if (!ref) {
    if (text.includes("#")) {
      return { error: `Bad model "${text}". Use provider/model with thinking set separately, or provider/model#variant.` };
    }
    return { error: `Bad model "${text}". Use provider/model or auto.` };
  }
  const candidates = await listModels(ctx);
  const id = `${ref.providerID}/${ref.modelID}`;
  const lower = id.toLowerCase();
  const exact = candidates.find((m) => `${m.providerID}/${m.modelID}`.toLowerCase() === lower);
  if (exact) {
    if (ref.variant && !exact.variants.includes(ref.variant)) {
      return { error: `"${ref.variant}" is not a variant of ${id}. Valid: ${exact.variants.join(", ") || "(none)"}.` };
    }
    return { id, thinking: ref.variant };
  }
  if (candidates.length === 0) {
    // Catalog unreachable: accept verbatim rather than blocking.
    return { id: ref.variant ? `${id}#${ref.variant}` : id };
  }
  const hits = candidates.filter(
    (m) => `${m.providerID}/${m.modelID}`.toLowerCase().includes(lower) || m.name.toLowerCase().includes(text.toLowerCase()),
  );
  if (hits.length === 1) {
    const hit = hits[0];
    if (ref.variant && !hit.variants.includes(ref.variant)) {
      return {
        error: `"${ref.variant}" is not a variant of ${hit.providerID}/${hit.modelID}. Valid: ${hit.variants.join(", ") || "(none)"}.`,
      };
    }
    return { id: `${hit.providerID}/${hit.modelID}`, thinking: ref.variant };
  }
  if (hits.length > 1) {
    const shown = hits
      .slice(0, 8)
      .map((m) => `  ${m.providerID}/${m.modelID}${m.name ? ` (${m.name})` : ""}`)
      .join("\n");
    const more = hits.length > 8 ? `\n  ...and ${hits.length - 8} more` : "";
    return { error: `"${text}" matches ${hits.length} models, be more specific:\n${shown}${more}` };
  }
  return { error: `No model matches "${text}". Run /advisor models for exact provider/model ids, or use auto.` };
}

// Calling session's model ref, read directly from the session (no
// transcript scan). Null when unreachable.
async function sessionModelRef(
  ctx: any,
  sessionID: string,
): Promise<{ providerID: string; modelID: string; variant?: string } | null> {
  try {
    const session = await ctx.session.get({ sessionID });
    const model = session?.model;
    if (model && model.providerID && (model.modelID || model.id)) {
      const ref: { providerID: string; modelID: string; variant?: string } = {
        providerID: model.providerID,
        modelID: model.modelID ?? model.id,
      };
      if (typeof model.variant === "string" && model.variant.length > 0) ref.variant = model.variant;
      return ref;
    }
  } catch {
    // Ignored: callers fall back to the global default model.
  }
  return null;
}

// Calling session's working directory, for the models dump file.
async function sessionDirectory(ctx: any, sessionID: string): Promise<string | null> {
  try {
    const session = await ctx.session.get({ sessionID });
    const dir = session?.location?.directory;
    if (typeof dir === "string" && dir.length > 0) return dir;
  } catch {
    // Ignored: caller falls back to the plugin location directory.
  }
  return null;
}

type ResolvedModel = { providerID: string; modelID: string; variant?: string; source: string };

// Model precedence for one advisor call: per-call args, environment,
// advisor settings ("auto" = follow the calling session), calling
// session's active model, global default model. Configured models are
// validated against the catalog; a stale configured value is a hard error
// (no silent fallback), while session/default lookup failures fall through.
async function resolveModel(
  ctx: any,
  sessionID: string | undefined,
  args: { providerID?: string; modelID?: string; variant?: string },
  settings: AdvisorSettings,
): Promise<ResolvedModel | { error: string }> {
  const candidates = await listModels(ctx);
  const known = (providerID: string, modelID: string) =>
    candidates.length === 0 || candidates.some((m) => m.providerID === providerID && m.modelID === modelID);
  const variantsOf = (providerID: string, modelID: string): string[] | null => {
    if (candidates.length === 0) return null;
    const hit = candidates.find((m) => m.providerID === providerID && m.modelID === modelID);
    return hit ? hit.variants : null;
  };
  if (args.providerID && args.modelID) {
    if (!known(args.providerID, args.modelID)) {
      return { error: `Unknown model ${args.providerID}/${args.modelID}. Run /advisor models for exact ids.` };
    }
    if (args.variant) {
      const valid = variantsOf(args.providerID, args.modelID);
      if (valid && !valid.includes(args.variant)) {
        return { error: `"${args.variant}" is not a variant of ${args.providerID}/${args.modelID}. Valid: ${valid.join(", ") || "(none)"}.` };
      }
    }
    return { providerID: args.providerID, modelID: args.modelID, variant: args.variant || undefined, source: "per-call args" };
  }
  const env = resolveModelFromEnv();
  if (env) {
    if (!known(env.providerID, env.modelID)) {
      return { error: `Unknown model ${env.providerID}/${env.modelID} from environment. Run /advisor models for exact ids.` };
    }
    const variant = env.variant ?? (settings.thinking !== "auto" ? settings.thinking : undefined);
    if (variant) {
      const valid = variantsOf(env.providerID, env.modelID);
      if (valid && !valid.includes(variant)) {
        return { error: `"${variant}" is not a variant of ${env.providerID}/${env.modelID}. Valid: ${valid.join(", ") || "(none)"}.` };
      }
    }
    return { ...env, variant, source: "environment" };
  }
  let sessionRef: { providerID: string; modelID: string; variant?: string } | null = null;
  if (typeof sessionID === "string" && sessionID.length > 0) {
    sessionRef = await sessionModelRef(ctx, sessionID);
  }
  if (settings.model && settings.model !== "auto") {
    const parsed = splitModel(settings.model);
    if (!parsed) {
      return { error: `Bad model "${settings.model}" in advisor settings. Use provider/model or auto.` };
    }
    if (!known(parsed.providerID, parsed.modelID)) {
      return { error: `Unknown model ${settings.model} in advisor settings. Run /advisor models for exact ids.` };
    }
    // An explicit variant wins; thinking "auto" with an explicitly chosen
    // model means the catalog default (never the session's variant, which
    // belongs to a different model).
    const variant = settings.thinking !== "auto" ? settings.thinking : undefined;
    if (variant) {
      const valid = variantsOf(parsed.providerID, parsed.modelID);
      if (valid && !valid.includes(variant)) {
        return {
          error: `"${variant}" is not a variant of ${parsed.providerID}/${parsed.modelID}. Valid: ${valid.join(", ") || "(none)"}. Run /advisor thinking to list them.`,
        };
      }
    }
    return { ...parsed, variant, source: "advisor settings" };
  }
  if (sessionRef) {
    if (!known(sessionRef.providerID, sessionRef.modelID)) {
      // Session model vanished from the catalog: environment drift, not a
      // config error, so fall through to the default instead of failing.
    } else {
      return {
        ...sessionRef,
        variant: settings.thinking !== "auto" ? settings.thinking : sessionRef.variant,
        source: "calling session",
      };
    }
  }
  try {
    const res = await ctx.model.default();
    const def = res?.data ?? res;
    if (def && def.providerID && def.modelID) {
      return { providerID: def.providerID, modelID: def.modelID, source: "global default model" };
    }
  } catch {
    // Ignored: reported as no-model error below.
  }
  return { error: "no model available: set one via /advisor configure model=<provider/model>" };
}

// Applies one control command and returns the exact reply text. Backs the
// advisor_ctl tool, which the /advisor template invokes.
async function applyCommand(ctx: any, rawArgs: string, sessionID?: string): Promise<string> {
  const tokens = (rawArgs || "")
    .trim()
    .split(/\s+/)
    .filter((t) => t.length > 0);
  const sub = (tokens[0] || "status").toLowerCase();
  const live = await currentSettings(ctx);
  const env = resolveModelFromEnv();
  if (sub === "on") {
    const err = await writeSettings(ctx, { ...live, enabled: true });
    if (err) return `Error: not saved: ${err}`;
    return "Advisor enabled.";
  }
  if (sub === "off") {
    const err = await writeSettings(ctx, { ...live, enabled: false });
    if (err) return `Error: not saved: ${err}`;
    return "Advisor disabled. The advisor tool will answer with a disabled notice until /advisor on.";
  }
  if (sub === "status") return statusText(live, env, await readLastReview(ctx));
  if (sub === "models") {
    let executor: string | null = null;
    let dir: string | null = null;
    if (typeof sessionID === "string" && sessionID.length > 0) {
      const active = await sessionModelRef(ctx, sessionID);
      if (active) executor = `${active.providerID}/${active.modelID}${active.variant ? `#${active.variant}` : ""}`;
      dir = await sessionDirectory(ctx, sessionID);
    }
    // Location-scoped catalog: list models visible at the calling
    // session's directory so the pick matches what the advisor can use.
    const candidates = await listModels(ctx, dir ?? undefined);
    if (candidates.length === 0) return modelsDumpFallback();
    // Calling session directory first, plugin location next, cwd last. A
    // failed write falls back to the model-run dump.
    if (!dir && typeof ctx?.location?.directory === "string" && ctx.location.directory.length > 0) {
      dir = ctx.location.directory;
    }
    if (!dir && typeof process !== "undefined" && process.cwd) dir = process.cwd();
    if (!dir) return modelsDumpFallback();
    const file = path.join(dir, `models_${dumpTimestamp()}.txt`);
    try {
      fs.writeFileSync(file, modelsFileText(candidates), "utf8");
    } catch {
      return modelsDumpFallback();
    }
    return modelsSummary(candidates, executor, file);
  }
  if (sub === "thinking") {
    // Resolve the advisor model without a variant, then list its catalog
    // variants: that list is the answer to "what can I choose".
    const resolved = await resolveModel(ctx, sessionID, {}, live);
    if ("error" in resolved) return `Error: ${resolved.error}`;
    const candidates = await listModels(ctx);
    if (candidates.length === 0) {
      return "Could not read the model catalog. Set thinking to a variant id shown by /models, or auto.";
    }
    const hit = candidates.find((m) => m.providerID === resolved.providerID && m.modelID === resolved.modelID);
    if (!hit) return `Error: model ${resolved.providerID}/${resolved.modelID} is not in the catalog.`;
    const lines = [
      `Thinking variants for ${resolved.providerID}/${resolved.modelID} (from ${resolved.source}):`,
      ...(hit.variants.length > 0 ? hit.variants.map((v) => `  ${v}`) : ["  (none: this model has no variants)"]),
      `Current: thinking ${live.thinking}.`,
      "Set with /advisor configure thinking=<variant|auto>.",
    ];
    return lines.join("\n");
  }
  if (sub === "configure") {
    // Rejoin: display names contain spaces, so model= consumes everything
    // up to a thinking=/enabled= clause or the end, in any order.
    const argStr = tokens.slice(1).join(" ");
    if (!argStr) return `${statusText(live, env, await readLastReview(ctx))}\n\n${usageText()}`;
    const next = { ...live };
    let rest = argStr;
    const modelMatch = /(?:^|\s)model\s*=\s*(.*?)(?=\s+(?:thinking|enabled|watch|reviewInterval)\s*=\s*\S+|$)/i.exec(argStr);
    if (modelMatch) {
      rest = rest.replace(modelMatch[0], " ");
      const resolved = await resolveModelInput(ctx, (modelMatch[1] || "").trim());
      if ("error" in resolved) return `${resolved.error}\n\n${usageText()}`;
      next.model = resolved.id;
      if (resolved.thinking) next.thinking = resolved.thinking;
    }
    const thinkingMatch = /(?:^|\s)thinking\s*=\s*(\S+)/i.exec(argStr);
    if (thinkingMatch) {
      rest = rest.replace(thinkingMatch[0], " ");
      const value = thinkingMatch[1];
      if (value.toLowerCase() === "auto") {
        next.thinking = "auto";
      } else {
        // Validate against the model being stored (the new one when
        // model= was given in the same command, else the current one).
        const target =
          next.model !== "auto"
            ? splitModel(next.model)
            : sessionID
              ? await sessionModelRef(ctx, sessionID).then((r) => (r ? { providerID: r.providerID, modelID: r.modelID } : null))
              : null;
        if (!target) {
          return `Cannot validate thinking "${value}" with no model resolved. Set model first, or use auto.\n\n${usageText()}`;
        }
        const candidates = await listModels(ctx);
        if (candidates.length > 0) {
          const hit = candidates.find((m) => m.providerID === target.providerID && m.modelID === target.modelID);
          if (!hit) {
            return `Error: model ${target.providerID}/${target.modelID} is not in the catalog.\n\n${usageText()}`;
          }
          if (!hit.variants.includes(value)) {
            return `"${value}" is not a variant of ${target.providerID}/${target.modelID}. Valid: ${hit.variants.join(", ") || "(none)"}.\n\n${usageText()}`;
          }
        }
        next.thinking = value;
      }
    }
    const enabledMatch = /(?:^|\s)enabled\s*=\s*(\S+)/i.exec(argStr);
    if (enabledMatch) {
      rest = rest.replace(enabledMatch[0], " ");
      const value = enabledMatch[1].toLowerCase();
      if (value === "on") next.enabled = true;
      else if (value === "off") next.enabled = false;
      else return `Bad enabled value "${enabledMatch[1]}". Use on or off.\n\n${usageText()}`;
    }
    const watchMatch = /(?:^|\s)watch\s*=\s*(\S+)/i.exec(argStr);
    if (watchMatch) {
      rest = rest.replace(watchMatch[0], " ");
      const value = watchMatch[1].toLowerCase();
      if (value === "on") next.watch = true;
      else if (value === "off") next.watch = false;
      else return `Bad watch value "${watchMatch[1]}". Use on or off.\n\n${usageText()}`;
    }
    const intervalMatch = /(?:^|\s)reviewInterval\s*=\s*(\S+)/i.exec(argStr);
    if (intervalMatch) {
      rest = rest.replace(intervalMatch[0], " ");
      const n = Number(intervalMatch[1]);
      if (!Number.isInteger(n) || n < 1) {
        return `Bad reviewInterval "${intervalMatch[1]}". Use a positive integer.\n\n${usageText()}`;
      }
      next.reviewInterval = n;
    }
    if (rest.trim().length > 0) return `Unknown option "${rest.trim()}".\n\n${usageText()}`;
    const err = await writeSettings(ctx, next);
    if (err) return `Error: not saved: ${err}`;
    // Enabling watch seeds the cursor at the current transcript length so
    // the first review covers only new turns, never old history.
    if (next.watch && !live.watch && typeof sessionID === "string" && sessionID.length > 0) {
      try {
        const res = await ctx.session.context({ sessionID });
        const messages = Array.isArray(res) ? res : (res?.data ?? []);
        if (Array.isArray(messages)) await writeCursor(ctx, sessionID, { count: messages.length, turns: 0 });
        guardReset(sessionID);
      } catch {
        // Ignored: cursor starts from zero on first boundary.
      }
    }
    return `Saved.\n${statusText(next, env, await readLastReview(ctx))}`;
  }
  return usageText();
}

const SYSTEM_PROMPT_BASE = `You are a strategic advisor for a coding agent: a peer reviewer shadowing a capable executor. You receive the executor's context and return a concise plan or course correction.

Silence first: if the executor is on track with no material risk, reply with exactly NO_CONCERNS and nothing else. Never manufacture advice to fill space; vague unease is not a finding.

When you do advise, be actionable — tell the executor:
- What to do next, and in what order
- What to watch out for
- What not to do

Tag each finding with severity: [nit] (cleanup, consider later), [concern] (may be heading wrong; executor decides), [blocker] (stop: contradicts explicit instruction, fundamentally unsound, or declares done what was never verified).

Rules:
- Cite only evidence in the context or your own verified reasoning; never assert values you cannot see.
- Never restate errors, diagnostics, or facts the executor already shows it knows. Never repeat advice already given.
- Prefer the simplest approach that meets the spec; flag maintenance burden and stuck/looping patterns explicitly.
- Do not second-guess decisions the executor understands and commits to unless you are certain. Large diffs and ambitious rewrites are not problems by themselves.
- Keep it succinct: at most 4 findings, or under 300 words, whichever binds first. Do NOT write code — only advise.`;

// Pull-style on-demand calls run tool-free (transient generation).
const SYSTEM_PROMPT = SYSTEM_PROMPT_BASE;

// Watch-mode sidecars run a read-only tool loop before verdicting.
const WATCH_SYSTEM_PROMPT = `${SYSTEM_PROMPT_BASE}

You have read, grep, and glob tools. Verify suspicions against the workspace with a few targeted calls first; never edit, run, or change anything. Then give your final verdict with severity tags — or exactly NO_CONCERNS when there is nothing material.`;

const TOOL_DESCRIPTION = `Consult a strategic advisor (a second model giving a concise plan or course correction; defaults to reusing your own active model unless configured otherwise) that requires all context necessary for the advisor tool and provides a concise plan or course correction.

Call advisor BEFORE substantive work — before writing code, editing files, committing to an interpretation, or building on an assumption. If the task requires orientation first (finding files, reading code, fetching docs), do that, then call advisor. Orientation is NOT substantive work.

Also call advisor:
- When stuck — errors recurring, approach not converging, results that don't fit
- When considering a change of approach
- When you believe the task is complete. BEFORE this call, make your deliverable durable: write the file, save the result, commit the change

On tasks longer than a few steps, call advisor at least once before committing to an approach and once before declaring done. On short reactive turns where tool output directly dictates the next action, skip advisor.

Optional tool args \`providerID\` and \`modelID\` (plus \`variant\`) override the advisor model for this one call; leave them blank to use the configured default (/advisor status shows it).

Required tool arg \`prompt\` must include all context the advisor needs for this call.

Give the advice serious weight. Only override if you have primary-source evidence that contradicts a specific claim. Surface conflicts in another advisor call rather than silently switching approaches.

When watch mode is on (/advisor status shows it), turn-boundary reviews also arrive automatically as advisor notes; this tool remains for on-demand checks. Reply NO_CONCERNS when there is nothing material to say.`;

export default Plugin.define({
  id: "advisor",
  async setup(ctx) {
    // Seed storage from plugin options on first run only; afterwards the
    // stored settings (written by /advisor configure) are the source of
    // truth so direct config edits cannot silently override them.
    try {
      const existing = await ctx.storage.get(STORAGE_KEY);
      if (!existing) {
        const opts = (ctx.options ?? {}) as Record<string, unknown>;
        await ctx.storage.set(STORAGE_KEY, {
          enabled: typeof opts.enabled === "boolean" ? opts.enabled : DEFAULT_SETTINGS.enabled,
          model:
            typeof opts.model === "string" && (opts.model as string).length > 0
              ? (opts.model as string)
              : DEFAULT_SETTINGS.model,
          thinking:
            typeof opts.thinking === "string" && (opts.thinking as string).length > 0
              ? (opts.thinking as string)
              : DEFAULT_SETTINGS.thinking,
          watch: typeof opts.watch === "boolean" ? opts.watch : DEFAULT_SETTINGS.watch,
          reviewInterval:
            typeof opts.reviewInterval === "number" &&
            Number.isInteger(opts.reviewInterval) &&
            (opts.reviewInterval as number) >= 1
              ? (opts.reviewInterval as number)
              : DEFAULT_SETTINGS.reviewInterval,
        });
      }
    } catch {
      // Storage unavailable: settings fall back to options/defaults per call.
    }

    // Push-style auto-review: one process-lifetime subscription. The
    // cleanup stops it so hot reloads never double-subscribe.
    const stopWatch = startWatchLoop(ctx);

    await ctx.tool.transform((editor) => {
      // Programmatic control surface for the /advisor command template.
      editor.add({
        name: "advisor_ctl",
        description:
          "Control the oc advisor plugin itself (status, on/off, models, thinking, configure). This manages the advisor; it is not the advisor. Call it when the user invokes /advisor, passing the words after /advisor as the action (empty means status), and relay its result back verbatim without adding anything, unless the result itself asks for a recommendation (models) - then follow it.",
        input: {
          type: "object",
          properties: {
            action: { type: "string" },
          },
          additionalProperties: false,
        },
        execute: async (input, context) => {
          const args = (input ?? {}) as { action?: unknown };
          const action = typeof args.action === "string" ? args.action : "";
          const text = await applyCommand(ctx, action, context?.sessionID);
          return { content: text };
        },
      });
      editor.add({
        name: "advisor",
        description: TOOL_DESCRIPTION,
        input: {
          type: "object",
          properties: {
            prompt: { type: "string" },
            providerID: { type: "string" },
            modelID: { type: "string" },
            variant: { type: "string" },
          },
          required: ["prompt"],
          additionalProperties: false,
        },
        execute: async (input, context) => {
          const args = (input ?? {}) as { prompt?: unknown; providerID?: unknown; modelID?: unknown; variant?: unknown };
          const live = await currentSettings(ctx);
          if (!live.enabled) {
            return { content: "Advisor is disabled. Run /advisor on to enable it." };
          }
          if (inAdvisorCall) {
            return {
              content: "Error: advisor tool cannot be called recursively. The advisor model must respond with text only.",
            };
          }
          if (typeof args.prompt !== "string" || args.prompt.trim().length === 0) {
            return { content: "Error: advisor prompt is required and must not be empty." };
          }
          // A literal "auto" variant means catalog default: omit it rather
          // than sending an id no model defines.
          const rawVariant = typeof args.variant === "string" ? args.variant : "";
          const over = {
            providerID: typeof args.providerID === "string" && args.providerID.length > 0 ? args.providerID : undefined,
            modelID: typeof args.modelID === "string" && args.modelID.length > 0 ? args.modelID : undefined,
            variant: rawVariant.length > 0 && rawVariant.toLowerCase() !== "auto" ? rawVariant : undefined,
          };
          const resolved = await resolveModel(ctx, context?.sessionID, over, live);
          if ("error" in resolved) return { content: `Error: ${resolved.error}` };
          let subcall: { sessionID: string };
          try {
            inAdvisorCall = true;
            const model: { id: string; providerID: string; variant?: string } = {
              id: resolved.modelID,
              providerID: resolved.providerID,
            };
            if (resolved.variant) model.variant = resolved.variant;
            const session = await ctx.session.create({
              title: "advisor-subcall",
              model,
            });
            subcall = { sessionID: session.id };
          } catch (error) {
            inAdvisorCall = false;
            return { content: `Error: advisor call failed: ${(error as Error).message}` };
          }
          try {
            // Transient generation: no history, returns text directly.
            const response = await ctx.session.generate({
              sessionID: subcall.sessionID,
              prompt: `${SYSTEM_PROMPT}\n\n--- CONTEXT ---\n\n${args.prompt.trim()}`,
            });
            const text = response?.text;
            return { content: text || "Advisor returned no advice." };
          } catch (error) {
            return { content: `Error: advisor call failed: ${(error as Error).message}` };
          } finally {
            inAdvisorCall = false;
            await ctx.session.remove({ sessionID: subcall.sessionID }).catch(() => {});
          }
        },
      });
    });

    return () => stopWatch();
  },
});
