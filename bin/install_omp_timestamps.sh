#!/usr/bin/env bash
# Install/configure timestamps extension for Oh My Pi (OMP) on Linux and macOS.
# Target path: ${PI_CODING_AGENT_DIR:-$HOME/.omp/agent}/extensions/timestamps.ts
set -euo pipefail

# Print help message and exit
show_help() {
  cat << 'EOF'
Usage: install_omp_timestamps.sh [OPTIONS]

Options:
  -u, --uninstall   Remove the timestamps extension
  -n, --dry-run     Show what would be done without modifying files
  -h, --help        Show this help message
EOF
}

# Verify platform is Linux or macOS
check_platform() {
  local os
  os="$(uname -s)"
  case "$os" in
    Linux|Darwin) ;;
    *)
      echo "Error: unsupported operating system: $os (only Linux and macOS supported)" >&2
      exit 1
      ;;
  esac
}

# Resolve OMP user extensions directory
resolve_extensions_dir() {
  local base_dir="${PI_CODING_AGENT_DIR:-$HOME/.omp/agent}"
  echo "$base_dir/extensions"
}

# Uninstall extension if requested
uninstall_extension() {
  local target_file="$1"
  local dry_run="$2"

  if [ -f "$target_file" ]; then
    if [ "$dry_run" = "true" ]; then
      echo "[dry-run] Would remove: $target_file"
    else
      rm -f "$target_file"
      echo "Removed: $target_file"
    fi
  else
    echo "Extension not found at: $target_file (nothing to uninstall)"
  fi
}

# Install or update the timestamps extension
install_extension() {
  local target_file="$1"
  local target_dir="$2"
  local dry_run="$3"

  if [ "$dry_run" = "true" ]; then
    echo "[dry-run] Would create directory: $target_dir"
    echo "[dry-run] Would write extension: $target_file"
    return 0
  fi

  mkdir -p "$target_dir"

  # Stage in a temporary directory on the same filesystem for atomic replacement
  local temp_dir
  temp_dir="$(mktemp -d "${target_dir}/.timestamps.XXXXXX")"
  local temp_file="$temp_dir/timestamps.ts"
  trap 'rm -rf "$temp_dir"' EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM

  # Write extension TypeScript source to temporary file
  cat << 'EOF' > "$temp_file"
import type { ExtensionAPI, ExtensionContext, SessionEntry } from "@oh-my-pi/pi-coding-agent";

/** Format Date object to local 24-hour HH:mm:ss string. */
function formatClock(date: Date): string {
  return date.toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/** Format Date object to local HH:mm:ss YYYY.M.D string. */
function formatDateTime(date: Date): string {
  const clock = formatClock(date);
  const year = date.getFullYear();
  const month = date.getMonth() + 1;
  const day = date.getDate();
  return `${clock} ${year}.${month}.${day}`;
}

/** Format duration in milliseconds into human-readable text. */
function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${(s - m * 60).toFixed(0)}s`;
}

export default function (pi: ExtensionAPI): void {
  let promptTime: Date | null = null;
  let responseTime: Date | null = null;
  let startMs: number | null = null;

  /** Update timing status widget above the input composer. */
  function updateWidget(ctx: ExtensionContext): void {
    if (!ctx.hasUI) return;
    const theme = ctx.ui.theme;

    if (!promptTime) {
      ctx.ui.setWidget("timestamps", undefined);
      return;
    }

    const upIcon = theme.fg("dim", "up ");
    const downIcon = theme.fg("dim", "  down ");
    const timerIcon = theme.fg("dim", "  time ");

    let line = `${upIcon}${theme.fg("dim", formatClock(promptTime))}`;
    if (responseTime && startMs) {
      const duration = responseTime.getTime() - startMs;
      line += `${downIcon}${theme.fg("dim", formatClock(responseTime))}`;
      line += `${timerIcon}${theme.fg("dim", formatDuration(duration))}`;
    }
    ctx.ui.setWidget("timestamps", [line], { placement: "aboveEditor" });
  }

  // Hook turn lifecycle events
  pi.on("before_agent_start", async (_event, ctx) => {
    promptTime = new Date();
    responseTime = null;
    startMs = promptTime.getTime();
    updateWidget(ctx);
  });

  pi.on("agent_end", async (_event, ctx) => {
    responseTime = new Date();
    updateWidget(ctx);
  });

  pi.on("session_start", async (_event, ctx) => {
    promptTime = null;
    responseTime = null;
    startMs = null;
    ctx.ui.setWidget("timestamps", undefined);
  });

  // Register /timestamps command for interactive timeline inspection
  pi.registerCommand("timestamps", {
    description: "Inspect message timestamps for current session",
    handler: async (_args, ctx) => {
      const branch: SessionEntry[] = ctx.sessionManager.getBranch();
      const messages: { date: Date; role: string; preview: string }[] = [];

      for (const entry of branch) {
        if (entry.type !== "message") continue;
        const msg = entry.message;
        if (msg.role !== "user" && msg.role !== "assistant") continue;

        const ts = msg.timestamp ?? Date.parse(entry.timestamp);
        const d = new Date(ts);
        let preview = "";
        if (typeof msg.content === "string") {
          preview = msg.content;
        } else if (Array.isArray(msg.content) && msg.content.length > 0) {
          const first = msg.content[0];
          if (first && "text" in first && typeof first.text === "string") {
            preview = first.text;
          }
        }
        messages.push({ date: d, role: msg.role, preview: preview.slice(0, 60) });
      }

      if (messages.length === 0) {
        ctx.ui.notify("No messages in session", "info");
        return;
      }

      const firstMsg = messages[0]!;
      const lastMsg = messages[messages.length - 1]!;
      const rangeLine = `Range: last ${formatDateTime(lastMsg.date)} - first ${formatDateTime(firstMsg.date)} (${messages.length} messages)`;

      messages.reverse();
      const items: string[] = [rangeLine];
      for (const m of messages) {
        items.push(`${formatDateTime(m.date)} [${m.role}]: ${m.preview}`);
      }
      await ctx.ui.select("Message Timestamps", items);
    },
  });
}
EOF

  # Validate extension loading using omp without invoking a model
  if command -v omp >/dev/null 2>&1; then
    local check_output
    if ! check_output="$(omp models --no-extensions --json -e "$temp_file" 2>&1 >/dev/null)"; then
      echo "Error: omp failed to load extension ($temp_file):" >&2
      echo "$check_output" >&2
      rm -rf "$temp_dir"
      trap - EXIT HUP INT TERM
      return 1
    fi
    if echo "$check_output" | grep -i "Failed to load extension" >/dev/null 2>&1; then
      echo "Error: omp reported extension load failure:" >&2
      echo "$check_output" >&2
      rm -rf "$temp_dir"
      trap - EXIT HUP INT TERM
      return 1
    fi
    echo "Extension verified successfully with omp (no-model invocation)."
  elif command -v bun >/dev/null 2>&1; then
    if ! bun build --no-bundle "$temp_file" >/dev/null 2>&1; then
      echo "Error: bun failed to parse TypeScript in $temp_file" >&2
      rm -rf "$temp_dir"
      trap - EXIT HUP INT TERM
      return 1
    fi
    echo "Extension syntax verified with bun."
  fi

  # Atomically move the validated extension into place and clean temp directory
  mv -f "$temp_file" "$target_file"
  rm -rf "$temp_dir"
  trap - EXIT HUP INT TERM

  echo "Installed timestamps extension to: $target_file"
}

main() {
  local dry_run="false"
  local uninstall="false"

  while [ $# -gt 0 ]; do
    case "$1" in
      -u|--uninstall)
        uninstall="true"
        shift
        ;;
      -n|--dry-run)
        dry_run="true"
        shift
        ;;
      -h|--help)
        show_help
        exit 0
        ;;
      *)
        echo "Unknown option: $1" >&2
        show_help >&2
        exit 1
        ;;
    esac
  done

  check_platform

  local extensions_dir
  extensions_dir="$(resolve_extensions_dir)"
  local target_file="$extensions_dir/timestamps.ts"

  if [ "$uninstall" = "true" ]; then
    uninstall_extension "$target_file" "$dry_run"
  else
    install_extension "$target_file" "$extensions_dir" "$dry_run"
  fi
}

main "$@"
