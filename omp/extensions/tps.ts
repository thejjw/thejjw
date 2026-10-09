/**
 * Editor-adjacent tok/s readout, one line: `⚡ live / ∑ turn-average`.
 *
 * omp's built-in working-row readout (`composer.tokenRate`) is deliberately
 * off: it renders in the working row, which extensions cannot write into, so
 * its number could never share a line with the average. Keeping both values
 * on this widget line — directly above the editor — puts the pair adjacent:
 * one glyph each, the unit stated once.
 *
 * `⚡` is a local rate over the last few paints of stream time. `∑` is the
 * turn average: a running average of the in-flight message while streaming,
 * then the provider's billed `usage.output / duration` at message end (local
 * count as fallback). At rest only the average remains —
 * a live number would sit there reading as "0 tok/s right now".
 */
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

/** Instantaneous-rate glyph, matching omp's own throughput icon. */
const LIVE_GLYPH = "⚡";
/** Summation glyph: "total over the turn". `~` is the ASCII-safe stand-in. */
const AVG_GLYPH = "∑";
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

/** One in-flight provider response. A tool-loop turn therefore reports each
 * assistant message's own rate instead of one blurred turn-wide number. */
type Span = { startedAt: number; localTokens: number };
/** One paint in the live-rate window. */
type Sample = { at: number; tokens: number };

export default function tpsExtension(pi: ExtensionAPI) {
  let span: Span | null = null;
  let samples: Sample[] = [];
  let lastLabel = "";
  let lastPaint = 0;

  // Repaint gate + shared label shape: streaming, message end and the resume
  // seed all publish through here and must not flicker or diverge in format.
  const publish = (
    ui: {
      setWidget(
        key: string,
        content: string[] | undefined,
        options?: { placement?: "aboveEditor" | "belowEditor" },
      ): void;
    },
    text: string,
  ) => {
    if (text === lastLabel) return;
    lastLabel = text;
    ui.setWidget("tps", text === "" ? undefined : [text], { placement: "aboveEditor" });
  };

  pi.on("message_start", event => {
    if (event.message.role !== "assistant") return;
    span = { startedAt: Date.now(), localTokens: 0 };
    samples = [];
    lastPaint = 0;
  });

  pi.on("message_update", (event, ctx) => {
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
    publish(
      ctx.ui,
      live === null
        ? `${AVG_GLYPH} ${average.toFixed(1)} tok/s`
        : `${LIVE_GLYPH} ${live.toFixed(1)} / ${AVG_GLYPH} ${average.toFixed(1)} tok/s`,
    );
  });

  pi.on("message_end", (event, ctx) => {
    const message = event.message;
    if (message.role !== "assistant") return;
    const measured = span === null ? 0 : Date.now() - span.startedAt;
    const elapsed = message.duration !== undefined && message.duration > 0 ? message.duration : measured;
    const tokens = message.usage.output > 0 ? message.usage.output : (span?.localTokens ?? 0);
    if (elapsed >= MIN_SPAN_MS && tokens > 0) {
      publish(ctx.ui, `${AVG_GLYPH} ${((tokens * 1000) / elapsed).toFixed(1)} tok/s`);
    }
    span = null;
    samples = [];
  });

  // Resumed sessions have no in-flight window; seed from the most recent
  // assistant message so the readout shows the last turn's average instead of
  // sitting blank until the next response.
  pi.on("session_start", (_event, ctx) => {
    const branch = ctx.sessionManager.getBranch();
    for (let i = branch.length - 1; i >= 0; i--) {
      const entry = branch[i];
      if (entry === undefined || entry.type !== "message") continue;
      const message = entry.message;
      if (message.role !== "assistant") continue;
      if (message.duration === undefined || message.duration < MIN_SPAN_MS) continue;
      if (message.usage.output <= 0) continue;
      publish(ctx.ui, `${AVG_GLYPH} ${((message.usage.output * 1000) / message.duration).toFixed(1)} tok/s`);
      return;
    }
  });
}
