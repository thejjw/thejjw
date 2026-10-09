/**
 * Editor-adjacent tok/s readout, one line: `⚡ live / ∑ turn-average [t/s]`,
 * with an optional trailing `(◈ ∑ n)` segment for this session's advisor.
 *
 * omp's built-in working-row readout (`composer.tokenRate`) is deliberately
 * off: it renders in the working row, which extensions cannot write into, so
 * its number could never share a line with the average. Keeping both values
 * on this widget line -- directly above the editor -- puts the pair adjacent:
 * one glyph each, the unit stated once, for both agents.
 *
 * `⚡` is a local rate over the last few paints of stream time. `∑` is the
 * turn average: a running average of the in-flight message while streaming,
 * then the provider's billed `usage.output / duration` at message end (local
 * count as fallback). At rest only the average remains --
 * a live number would sit there reading as "0 tok/s right now".
 *
 * The advisor segment is a turn average only. The advisor is a separate
 * `Agent` whose stream never reaches `message_update` handlers (only its
 * `tool_call`/`tool_result` events cross into this session), and no
 * extension hook carries mid-flight token counts: usage exists only once the
 * advisor's message finalizes into `<session>/__advisor[.<slug>].jsonl`,
 * whose `usage.output` + `duration` are tailed here. There is no `⚡` for
 * the advisor and there cannot be one; do not fake it from the file.
 *
 * Staleness: the segment becomes `(◈ ∑ n?)`, dimmed in the TUI, once the
 * primary transcript has advanced more than `ADVISOR_STALE_MS` past the
 * advisor's last logged turn. `/advisor on|off` never touches the settings
 * registry, so no setting can answer this; the transcript can. The last
 * known average is never hidden -- the `?` marks uncertainty (e.g. a long
 * `agent-end` reviewer between reviews), it is not a claim of "off".
 */
import * as fs from "node:fs";
import * as path from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";

/** Instantaneous-rate glyph, matching omp's own throughput icon. */
const LIVE_GLYPH = "⚡";
/** Summation glyph: "total over the turn". `~` is the ASCII-safe stand-in. */
const AVG_GLYPH = "∑";
/** Advisor-average glyph; the advisor has no live counterpart. */
const ADVISOR_GLYPH = "◈";
/** Chars-per-token estimate for streamed deltas; billed usage supersedes it. */
const CHARS_PER_TOKEN = 4;
/** Widget repaint budget. */
const PAINT_MS = 250;
/** Paints retained for the live rate (~2s at the 250ms paint cadence). */
const LIVE_SAMPLES = 8;
/** Below this the window rate is noise (provider buffering, slow trickle). */
const MIN_LIVE_SPAN_MS = 300;
/** Sub-100ms spans produce garbage averages. */
const MIN_SPAN_MS = 100;
/** Cadence for tailing advisor transcripts. */
const POLL_MS = 2000;
/** Advisor turns averaged into the readout. */
const ADVISOR_WINDOW = 5;
/** Primary progress past the advisor's last logged turn before flagging `?`. */
const ADVISOR_STALE_MS = 600_000;
/** Advisor transcript names, mirroring core's isAdvisorTranscriptName:
 *  `__advisor.jsonl` or anything `__advisor.*.jsonl` (dotted slugs included). */
const ADVISOR_TRANSCRIPT = (name: string): boolean =>
  name === "__advisor.jsonl" || (name.startsWith("__advisor.") && name.endsWith(".jsonl"));

/** One in-flight provider response. A tool-loop turn therefore reports each
 * assistant message's own rate instead of one blurred turn-wide number. */
type Span = { startedAt: number; localTokens: number };
/** One paint in the live-rate window. */
type Sample = { at: number; tokens: number };
/** One parsed advisor assistant turn. */
type AdvisorTurn = { at: number; tokens: number; ms: number };
/** Incremental tail state for one advisor transcript file. */
type Reader = { offset: number; buffer: string; birthtimeMs: number; mtimeMs: number };

export default function tpsExtension(pi: ExtensionAPI) {
  let span: Span | null = null;
  let samples: Sample[] = [];
  let lastLabel = "";
  let lastPaint = 0;

  // Two independent producers write one line: live stream events own
  // `primaryPart`, the advisor poll owns `advisorInner`. `renderLine` is the
  // only composer, so neither half can repaint alone with the other missing
  // (no blinking advisor segment, no orphan advisor-only line).
  let primaryPart = "";
  let advisorInner = "";
  let advisorStale = false;

  // Advisor transcript tail state, keyed by file path. Maps, not records:
  // the keys are discovered at runtime and both are mutated and iterated.
  let readers = new Map<string, Reader>();
  let series = new Map<string, AdvisorTurn[]>();
  // Directory the current session's advisor transcripts live in. Tracked
  // separately from resetAdvisorState: the poll is the safety net for moves
  // no session event announces (lease sibling, /move, re-rooting), and the
  // series are keyed by absolute path, so a stale directory's turns would
  // otherwise keep merging into the readout forever.
  let advisorDir = "";
  // Managed timers are unref'd and cleared automatically on session_shutdown;
  // the flag only keeps the four session-boundary events from double-arming.
  let pollArmed = false;
  // Newest ctx seen. The poll interval reads the session through it, so a
  // session switch (which rebinds managers) can never leave the timer
  // polling the previous session's files.
  let latestCtx: ExtensionContext | undefined;

  /** Dim the advisor segment; a custom theme missing the token must not
   *  throw inside the paint path -- plain text still carries the `?`. */
  const dimAdvisor = (ctx: ExtensionContext, text: string): string => {
    if (ctx.mode !== "tui") return text;
    try {
      return ctx.ui.theme.fg("dim", text);
    } catch {
      return text;
    }
  };

  const renderLine = (ctx: ExtensionContext) => {
    // `advisorInner` is the segment body; the `?` belongs inside the parens.
    // It also mutates the composed text, so the dedupe key needs no stale flag.
    const advisorText = advisorInner === "" ? "" : `(${advisorInner}${advisorStale ? "?" : ""})`;
    const plain = [primaryPart, advisorText].filter(part => part !== "").join(" ");
    const key = plain;
    if (key === lastLabel) return;
    lastLabel = key;
    if (plain === "") {
      ctx.ui.setWidget("tps", undefined);
      return;
    }
    // Colors are baked at paint time and do not re-resolve on a live theme
    // switch. RPC forwards widget strings verbatim, so escapes are emitted
    // in the TUI only and the `?` carries the signal everywhere else. Only
    // the stale variant is dimmed; a fresh advisor segment stays plain.
    const styled =
      advisorText === "" || !advisorStale || ctx.mode !== "tui"
        ? plain
        : `${primaryPart === "" ? "" : `${primaryPart} `}${dimAdvisor(ctx, advisorText)}`;
    ctx.ui.setWidget("tps", [`${styled} [t/s]`], { placement: "aboveEditor" });
  };

  const resetAdvisorState = () => {
    readers = new Map();
    series = new Map();
    advisorInner = "";
    advisorStale = false;
  };

  /** One advisor assistant entry, or null for anything not billable: headers,
   *  user updates, tool results, zero-output quota/error rows. Narrowed from
   *  `unknown` because the file is external data. */
  const parseAdvisorTurn = (line: string): AdvisorTurn | null => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      return null;
    }
    if (typeof parsed !== "object" || parsed === null) return null;
    if (!("type" in parsed) || parsed.type !== "message") return null;
    if (!("message" in parsed)) return null;
    const message: unknown = parsed.message;
    if (typeof message !== "object" || message === null) return null;
    if (!("role" in message) || message.role !== "assistant") return null;
    if (!("usage" in message) || !("duration" in message)) return null;
    const usage: unknown = message.usage;
    if (typeof usage !== "object" || usage === null) return null;
    if (!("output" in usage)) return null;
    const tokens: unknown = usage.output;
    const ms: unknown = message.duration;
    if (typeof tokens !== "number" || tokens <= 0) return null;
    if (typeof ms !== "number" || ms < MIN_SPAN_MS) return null;
    // Entry timestamps are ISO 8601 strings; an unparseable one sorts oldest.
    const rawAt = "timestamp" in parsed ? parsed.timestamp : undefined;
    const at = typeof rawAt === "string" ? Date.parse(rawAt) : NaN;
    return { at: Number.isFinite(at) ? at : 0, tokens, ms };
  };

  const tailAdvisorFile = (file: string) => {
    const stat = fs.statSync(file);
    const size = stat.size;
    let reader = readers.get(file);
    if (reader === undefined) {
      reader = { offset: 0, buffer: "", birthtimeMs: stat.birthtimeMs, mtimeMs: stat.mtimeMs };
      readers.set(file, reader);
    }
    // An atomic rewrite (temp file + rename) replaces the file. The new one
    // can be LONGER than the old offset, which a size-only check would read
    // as an append of garbage and silently mis-parse every later line, so
    // the replace is detected by birthtime (0 on platforms that do not
    // report it, where only the size reset applies). Re-opening per tick
    // already keeps Windows from serving the pre-rename inode.
    //
    // The mtime term covers an in-place rewrite of equal byte length: the
    // offset would not move, the bytes would not be re-read, and superseded
    // turns would keep counting. An append always changes the size, so this
    // term never re-parses an unchanged file.
    if (
      size < reader.offset ||
      stat.birthtimeMs !== reader.birthtimeMs ||
      (size === reader.offset && stat.mtimeMs !== reader.mtimeMs)
    ) {
      reader.offset = 0;
      reader.buffer = "";
      series.delete(file);
    }
    reader.birthtimeMs = stat.birthtimeMs;
    reader.mtimeMs = stat.mtimeMs;
    if (size > reader.offset) {
      // Open per tick for the same reason: a held descriptor keeps serving
      // the pre-rename inode on Windows.
      const fd = fs.openSync(file, "r");
      try {
        const length = size - reader.offset;
        const chunk = Buffer.alloc(length);
        const read = fs.readSync(fd, chunk, 0, length, reader.offset);
        reader.offset += read;
        reader.buffer += chunk.toString("utf8", 0, read);
      } finally {
        fs.closeSync(fd);
      }
    }
    // Only whole lines are parsed. A torn final row stays buffered so the
    // advisor turn it belongs to is not lost forever.
    const lastBreak = reader.buffer.lastIndexOf("\n");
    if (lastBreak < 0) return;
    const complete = reader.buffer.slice(0, lastBreak + 1);
    reader.buffer = reader.buffer.slice(lastBreak + 1);
    for (const line of complete.split("\n")) {
      if (line === "") continue;
      const turn = parseAdvisorTurn(line);
      if (turn === null) continue;
      const turns = series.get(file);
      if (turns === undefined) series.set(file, [turn]);
      else turns.push(turn);
    }
  };

  /** Stale = the primary transcript advanced past the advisor's last logged
   *  turn by more than ADVISOR_STALE_MS. An idle session reads negative (the
   *  advisor's review postdates the final yield) and stays fresh. A busy
   *  `agent-end` reviewer can still trip this; the `?`, not hiding, is the
   *  tolerance for that. */
  const isAdvisorStale = (ctx: ExtensionContext, lastAdvisorAt: number): boolean => {
    if (lastAdvisorAt <= 0) return false;
    const branch = ctx.sessionManager.getBranch();
    for (let i = branch.length - 1; i >= 0; i--) {
      const entry = branch[i];
      if (entry === undefined || entry.type !== "message") continue;
      const at = Date.parse(entry.timestamp);
      if (Number.isFinite(at) && at > 0) return at - lastAdvisorAt > ADVISOR_STALE_MS;
    }
    return false;
  };

  const refreshAdvisorPart = (ctx: ExtensionContext) => {
    const turns: AdvisorTurn[] = [];
    let newest = 0;
    for (const fileTurns of series.values()) {
      for (const turn of fileTurns) {
        turns.push(turn);
        if (turn.at > newest) newest = turn.at;
      }
    }
    if (turns.length === 0) {
      advisorInner = "";
      advisorStale = false;
      return;
    }
    // Per-file series merged here: append order in one file is not global
    // order once a named-advisor roster interleaves transcripts.
    turns.sort((left, right) => left.at - right.at);
    const window = turns.slice(-ADVISOR_WINDOW);
    const tokens = window.reduce((sum, turn) => sum + turn.tokens, 0);
    const ms = window.reduce((sum, turn) => sum + turn.ms, 0);
    advisorInner = `${ADVISOR_GLYPH} ${AVG_GLYPH} ${((tokens * 1000) / ms).toFixed(1)}`;
    advisorStale = isAdvisorStale(ctx, newest);
  };

  const pollAdvisor = () => {
    const ctx = latestCtx;
    if (ctx === undefined) return;
    try {
      const sessionFile = ctx.sessionManager.getSessionFile();
      // An unsaved session has no file yet: derive nothing. Core guards the
      // same way -- slicing `undefined` would throw every tick.
      const dir =
        typeof sessionFile === "string" && sessionFile.endsWith(".jsonl")
          ? sessionFile.slice(0, -".jsonl".length)
          : undefined;
      if (dir === undefined) {
        resetAdvisorState();
        renderLine(ctx);
        return;
      }
      if (dir !== advisorDir) {
        advisorDir = dir;
        resetAdvisorState();
      }
      // withFileTypes + isFile: a directory matching the transcript name
      // would make openSync throw and stall every later tick (the catch
      // swallows it), so it is skipped rather than fatal.
      for (const dirent of fs.readdirSync(dir, { withFileTypes: true })) {
        if (!dirent.isFile() || !ADVISOR_TRANSCRIPT(dirent.name)) continue;
        tailAdvisorFile(path.join(dir, dirent.name));
      }
      refreshAdvisorPart(ctx);
      renderLine(ctx);
    } catch {
      // One bad tick is skipped, never thrown: a transient fs error would
      // otherwise repeat through the extension error channel every POLL_MS.
    }
  };

  // Transcript state must be rebuilt on every boundary that replaces the
  // conversation: session_start / session_switch / session_branch /
  // session_tree (the set core's own extensions register). A lazy reset on
  // the next poll tick would show a cross-session primary/advisor pair for
  // up to POLL_MS.
  const rebuildSession = (_event: unknown, ctx: ExtensionContext) => {
    latestCtx = ctx;
    resetAdvisorState();
    primaryPart = "";
    const branch = ctx.sessionManager.getBranch();
    for (let i = branch.length - 1; i >= 0; i--) {
      const entry = branch[i];
      if (entry === undefined || entry.type !== "message") continue;
      const message = entry.message;
      if (message.role !== "assistant") continue;
      if (message.duration === undefined || message.duration < MIN_SPAN_MS) continue;
      if (message.usage.output <= 0) continue;
      primaryPart = `${AVG_GLYPH} ${((message.usage.output * 1000) / message.duration).toFixed(1)}`;
      break;
    }
    if (!pollArmed) {
      pollArmed = true;
      ctx.setInterval(pollAdvisor, POLL_MS);
    }
    renderLine(ctx);
  };
  pi.on("session_start", rebuildSession);
  pi.on("session_switch", rebuildSession);
  pi.on("session_branch", rebuildSession);
  pi.on("session_tree", rebuildSession);

  pi.on("message_start", event => {
    if (event.message.role !== "assistant") return;
    span = { startedAt: Date.now(), localTokens: 0 };
    samples = [];
    lastPaint = 0;
  });

  pi.on("message_update", (event, ctx) => {
    latestCtx = ctx;
    if (span === null) return;
    const message = event.message;
    if (message.role !== "assistant") return;

    // text/thinking/tool-call argument deltas are all generated output tokens.
    const streamEvent = event.assistantMessageEvent;
    if (
      streamEvent.type !== "text_delta" &&
      streamEvent.type !== "thinking_delta" &&
      streamEvent.type !== "toolcall_delta"
    ) {
      return;
    }
    span.localTokens += Math.max(1, Math.round(streamEvent.delta.length / CHARS_PER_TOKEN));

    const at = Date.now();
    if (at - lastPaint < PAINT_MS) return;
    lastPaint = at;

    // Live rate: sample at the paint cadence and read across the retained
    // paints. A per-delta ratio flickers with provider buffering; a time-based
    // window would collapse to one sample on a slow trickle and blank the
    // live number entirely.
    samples.push({ at, tokens: span.localTokens });
    while (samples.length > LIVE_SAMPLES) samples.shift();
    const oldest = samples[0];
    const newest = samples.at(-1);
    if (oldest === undefined || newest === undefined) return;
    const windowMs = newest.at - oldest.at;
    const live =
      samples.length >= 2 && windowMs >= MIN_LIVE_SPAN_MS
        ? ((newest.tokens - oldest.tokens) * 1000) / windowMs
        : null;

    const elapsed = at - span.startedAt;
    if (elapsed < MIN_SPAN_MS || span.localTokens <= 0) return;
    const average = (span.localTokens * 1000) / elapsed;
    primaryPart =
      live === null
        ? `${AVG_GLYPH} ${average.toFixed(1)}`
        : `${LIVE_GLYPH} ${live.toFixed(1)} / ${AVG_GLYPH} ${average.toFixed(1)}`;
    renderLine(ctx);
  });

  pi.on("message_end", (event, ctx) => {
    latestCtx = ctx;
    const message = event.message;
    if (message.role !== "assistant") return;
    const measured = span === null ? 0 : Date.now() - span.startedAt;
    const elapsed = message.duration !== undefined && message.duration > 0 ? message.duration : measured;
    const tokens = message.usage.output > 0 ? message.usage.output : (span?.localTokens ?? 0);
    if (elapsed >= MIN_SPAN_MS && tokens > 0) {
      primaryPart = `${AVG_GLYPH} ${((tokens * 1000) / elapsed).toFixed(1)}`;
      renderLine(ctx);
    }
    span = null;
    samples = [];
  });
}
