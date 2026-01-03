#!/bin/bash

# AV1 Transcode Script
# 30%(40% -lq) reduction for h264, 20%(30% -lq) reduction for hevc
# 2025.12-2026.1 @thejjw

set -u
set -o pipefail

EXTENSIONS=( "mp4" "m4v" "mkv" "mov" "mpg" "mpeg" "avi" "wmv" "webm" "ts" "3gp" "flv" "m2ts" "mts" "f4v" "rmvb" "rm" "ogv" "divx" "xvid" )

usage() {
  cat <<'EOF'
Usage:
  av1_transcode.sh [OPTIONS] [DIRECTORY]

DIRECTORY
  Root directory to scan (default: .)

OPTIONS
  -d, --delete          Delete original after successful conversion ONLY if:
                        1) Output is smaller, AND
                        2) VMAF score is 90 or above.
                        If output is not smaller, output is deleted and original is kept.
  --delete-always       Delete original after successful conversion if output is smaller,
                        regardless of VMAF score. (Original -d behavior)
                        If output is not smaller, output is deleted and original is kept.
  --dry-run             Do not encode. Only list what would be processed and the target bitrates
                        including estimated size change.
  -e, --everything     Encode any supported video codec (default encodes only h264/hevc/h265).
  -f, --filter          Apply video filter chain during encode:
                        unsharp=5:5:1.0:5:5:0.0,hqdn3d=4:3:6:4
  --quality <low|1gb|2gb>
                        Quality preset:
                          * low  → h264 target = 60% (40% less), hevc target = 70% (30% less)
                          * 1gb  → compute video bitrate to target ~1 GiB total size
                          * 2gb  → compute video bitrate to target ~2 GiB total size
                        All presets use 2-pass SVT-AV1.
                        Default (no --quality): h264 target = 70% (30% less), hevc target = 80% (20% less).
  -h, --help            Show this help.

Output naming
  - Output is: "<original_basename>.av1.r.mkv"
  - If that already exists, a timestamp is inserted:
      "<original_basename>.av1.r.<YYYYmmdd_HHMMSS>.mkv"

FFmpeg verbosity / progress
  - This script runs ffmpeg with:
      -hide_banner -loglevel warning -stats -stats_period 300
    so you still get progress lines, but only every 300 seconds.

Behavior summary
  - Recursively finds files by extension under DIRECTORY.
  - Probes each candidate via ffprobe:
      * Default: only processes v:0 codec h264 or hevc/h265 (skips others)
      * With --everything: processes any detected video codec (h264 rules for bitrate)
      * Derives bitrate from:
          1) v:0 stream bit_rate, else
          2) format bit_rate, else
          3) computed from size/duration (average)
  - Encodes v:0 to AV1 using libsvtav1 in 2-pass mode.
  - Copies all other streams as-is (audio/subs/data/attachments/other video streams).
  - Logs: "transcode_av1_<YYYYmmdd_HHMMSS>.log" and stdout (tee).
EOF
}

need_cmd() {
  local c="$1"
  if ! command -v "$c" >/dev/null 2>&1; then
    echo "ERROR: Required tool not found in PATH: $c" >&2
    exit 1
  fi
}

has_encoder() {
  local enc="$1"
  ffmpeg -hide_banner -encoders 2>/dev/null | awk '{print $2}' | grep -qx "$enc"
}

has_filter() {
  local filter="$1"
  ffmpeg -hide_banner -filters 2>/dev/null | grep -qw "$filter"
}

fmt_seconds() {
  local s="$1"
  local h=$((s/3600))
  local m=$(((s%3600)/60))
  local sec=$((s%60))
  printf "%02dh:%02dm:%02ds" "$h" "$m" "$sec"
}

fmt_bytes() {
  local b="$1"
  awk -v bytes="$b" 'BEGIN{
    split("B KB MB GB TB PB", u, " ");
    i=1;
    while (bytes>=1024 && i<6) { bytes/=1024; i++; }
    printf "%.2f %s", bytes, u[i];
  }'
}

# --- logging helpers (timestamp + scoped elapsed) ---
RUN_START_EPOCH=0
LOG_SCOPE_START_EPOCH=0

log_init() {
  RUN_START_EPOCH="$(date +%s)"
  LOG_SCOPE_START_EPOCH="$RUN_START_EPOCH"
}

log_scope_run()  { LOG_SCOPE_START_EPOCH="$RUN_START_EPOCH"; }
log_scope_file() { LOG_SCOPE_START_EPOCH="$1"; }  # pass FILE_START_EPOCH

log() {
  local now_epoch now_ts elapsed
  now_epoch="$(date +%s)"
  now_ts="$(date '+%Y-%m-%d %H:%M:%S')"
  elapsed=$(( now_epoch - LOG_SCOPE_START_EPOCH ))
  printf "[%s] [%s] %s\n" "$now_ts" "$(fmt_seconds "$elapsed")" "$*"
}

# FFmpeg: quieter logs + progress only every 300s
# -stats_period is documented as the update period for stats/progress. :contentReference[oaicite:4]{index=4}
# -stats forces periodic stats even when loglevel is set. :contentReference[oaicite:5]{index=5}
FFMPEG_OPTS=( -hide_banner -loglevel warning -stats -stats_period 300 )

# Calculate VMAF score between distorted (output) and reference (original) video
calculate_vmaf() {
  local distorted="$1"
  local reference="$2"
  local json_log="$(mktemp -t vmaf_XXXXXXXX.json)"
  
  log "Calculating VMAF score..."
  
  # Run ffmpeg with libvmaf filter
  set +e
  ffmpeg -hide_banner -loglevel error \
    -i "$distorted" \
    -i "$reference" \
    -lavfi "libvmaf=log_path='${json_log}':log_fmt=json" \
    -f null - 2>&1
  local rc=$?
  set -e
  
  if [[ $rc -ne 0 || ! -s "$json_log" ]]; then
    log "WARNING: VMAF calculation failed (exit=$rc)"
    rm -f "$json_log" 2>/dev/null || true
    echo "0"
    return 1
  fi
  
  # Extract pooled VMAF score from JSON
  local vmaf_score
  vmaf_score=$(awk '
    /"pooled_metrics":/ { in_pooled=1; next }
    in_pooled && /"vmaf":/ {
      match($0, /"mean"[[:space:]]*:[[:space:]]*([0-9.]+)/, arr);
      if (arr[1] != "") {
        printf "%.0f", arr[1];
        exit;
      }
    }
    /}/ { in_pooled=0 }
  ' "$json_log")
  
  rm -f "$json_log" 2>/dev/null || true
  
  if [[ -z "$vmaf_score" ]]; then
    log "WARNING: Could not parse VMAF score from JSON"
    echo "0"
    return 1
  fi
  
  echo "$vmaf_score"
  return 0
}

get_video_codec() {
  local f="$1"
  ffprobe -v error -select_streams v:0 \
    -show_entries stream=codec_name \
    -of default=nk=1:nw=1 -- "$f" 2>/dev/null | head -n 1
}

get_format_duration() {
  local f="$1"
  ffprobe -v error \
    -show_entries format=duration \
    -of default=nk=1:nw=1 -- "$f" 2>/dev/null | head -n 1
}

get_video_bitrate_bps() {
  local f="$1"
  local br

  br="$(ffprobe -v error -select_streams v:0 \
    -show_entries stream=bit_rate \
    -of default=nk=1:nw=1 -- "$f" 2>/dev/null | head -n 1)"
  if [[ -n "${br:-}" && "$br" != "N/A" && "$br" != "0" ]]; then
    echo "$br"
    return 0
  fi

  br="$(ffprobe -v error \
    -show_entries format=bit_rate \
    -of default=nk=1:nw=1 -- "$f" 2>/dev/null | head -n 1)"
  if [[ -n "${br:-}" && "$br" != "N/A" && "$br" != "0" ]]; then
    echo "$br"
    return 0
  fi

  local dur size
  dur="$(get_format_duration "$f")"
  size="$(stat -c%s -- "$f" 2>/dev/null || echo 0)"

  awk -v bytes="$size" -v dur="$dur" 'BEGIN{
    if (dur<=0 || bytes<=0) { print 0; exit; }
    printf "%.0f", (bytes*8)/dur;
  }'
}

# Sum audio bitrates across all audio streams. Fallback to 128 kbps if unknown.
get_audio_bitrate_sum_bps() {
  local f="$1"
  local total=0
  local any=0
  while IFS= read -r br; do
    if [[ -n "$br" && "$br" != "N/A" && "$br" != "0" ]]; then
      any=1
      total=$(( total + br ))
    fi
  done < <(ffprobe -v error -select_streams a \
            -show_entries stream=bit_rate \
            -of default=nk=1:nw=1 -- "$f" 2>/dev/null)

  if [[ "$any" -eq 0 ]]; then
    # Assume 128 kbps for audio when unknown
    echo 128000
  else
    echo "$total"
  fi
}

compute_target_kbps() {
  local src_bps="$1"
  local factor="$2"
  awk -v bps="$src_bps" -v f="$factor" 'BEGIN{
    kbps = (bps*f)/1000.0;
    if (kbps < 250) kbps = 250;
    printf "%d", kbps + 0.5;
  }'
}

estimate_target_bytes_from_ratio() {
  local orig_bytes="$1"
  local src_bps="$2"
  local target_kbps="$3"
  awk -v o="$orig_bytes" -v sb="$src_bps" -v tb="$((target_kbps*1000))" 'BEGIN{
    if (o<=0 || sb<=0 || tb<=0) { print 0; exit; }
    printf "%.0f", (o * tb) / sb;
  }'
}

# ---------------- option parsing ----------------
DELETE_ORIGINAL=false
DELETE_ALWAYS=false
DRY_RUN=false
QUALITY_MODE="normal"
ROOT="."
APPLY_FILTER=false
FILTER_CHAIN='unsharp=5:5:1.0:5:5:0.0,hqdn3d=4:3:6:4'
TARGET_SIZE_BYTES=0
EVERYTHING=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--delete) DELETE_ORIGINAL=true; shift ;;
    --delete-always) DELETE_ORIGINAL=true; DELETE_ALWAYS=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    -e|--everything) EVERYTHING=true; shift ;;
    -f|--filter) APPLY_FILTER=true; shift ;;
    --quality)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --quality requires a value (low|1gb|2gb)" >&2
        usage
        exit 1
      fi
      case "$2" in
        low) QUALITY_MODE="low" ;;
        1gb) QUALITY_MODE="size"; TARGET_SIZE_BYTES=$((1000*1000*1000)) ;;
        2gb) QUALITY_MODE="size"; TARGET_SIZE_BYTES=$((2*1000*1000*1000)) ;;
        *) echo "ERROR: unknown --quality value: $2" >&2; usage; exit 1 ;;
      esac
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*)
      echo "ERROR: Unknown option: $1" >&2
      usage
      exit 1
      ;;
    *)
      ROOT="$1"
      shift
      ;;
  esac
done

# ---- Pre-flight checks ----
need_cmd bash
need_cmd find
need_cmd awk
need_cmd date
need_cmd stat
need_cmd mktemp
need_cmd tee
need_cmd ffmpeg
need_cmd ffprobe

if [[ ! -d "$ROOT" ]]; then
  echo "ERROR: Not a directory: $ROOT" >&2
  exit 1
fi

if ! has_encoder "libsvtav1"; then
  echo "ERROR: ffmpeg does not list 'libsvtav1' encoder." >&2
  echo "       Install/build FFmpeg with SVT-AV1 support enabled." >&2
  exit 1
fi

if ! has_filter "libvmaf"; then
  echo "ERROR: ffmpeg does not have 'libvmaf' filter support." >&2
  echo "       VMAF scoring is required. Install FFmpeg with libvmaf enabled." >&2
  exit 1
fi

TS="$(date +%Y%m%d_%H%M%S)"
LOGFILE="transcode_av1_${TS}.log"
exec > >(tee -a "$LOGFILE") 2>&1
log_init

# Array to track files with VMAF < 90
LOW_VMAF_FILES=()

log "=== AV1 Transcode Run Started ==="
log "Root            : $ROOT"
if $DELETE_ORIGINAL; then
  if $DELETE_ALWAYS; then
    log "Delete original : YES (always, if smaller)"
  else
    log "Delete original : YES (if smaller AND VMAF >= 90)"
  fi
else
  log "Delete original : NO"
fi
log "Dry-run         : $DRY_RUN"
log "Everything      : $EVERYTHING"
log "Quality mode    : $QUALITY_MODE"
if [[ "$QUALITY_MODE" == "size" ]]; then
  log "Target size     : $(fmt_bytes "$TARGET_SIZE_BYTES")"
fi
log "Log             : $LOGFILE"
log "Extensions      : ${EXTENSIONS[*]}"
log "FFmpeg opts     : ${FFMPEG_OPTS[*]}"
if $APPLY_FILTER; then
  log "Video filter    : ENABLED -> $FILTER_CHAIN"
else
  log "Video filter    : disabled"
fi

if [[ "$QUALITY_MODE" == "low" ]]; then
  H264_FACTOR="0.60"
  HEVC_FACTOR="0.70"
  log "Bitrate rule    : LOW-QUALITY (--quality low)"
  log "  h264 target   : 60% of detected bitrate (40% less)"
  log "  hevc target   : 70% of detected bitrate (30% less)"
elif [[ "$QUALITY_MODE" == "size" ]]; then
  # For size-targeted mode, factors not used; bitrate derived from duration & audio.
  H264_FACTOR="0.00"
  HEVC_FACTOR="0.00"
  log "Bitrate rule    : SIZE-TARGET (~$(fmt_bytes "$TARGET_SIZE_BYTES"))"
  log "  video target  : computed to fit total size minus audio"
else
  H264_FACTOR="0.70"
  HEVC_FACTOR="0.80"
  log "Bitrate rule    : NORMAL"
  log "  h264 target   : 70% of detected bitrate (30% less)"
  log "  hevc target   : 80% of detected bitrate (20% less)"
fi
if $EVERYTHING; then
  log "Everything mode : non-h264/hevc use h264 bitrate rule"
fi
log "Bitrate detect  : v:0 stream bit_rate -> format bit_rate -> avg(size/duration)"
log "Target floor    : 250 kbps"
log "Output suffix   : .av1.r.mkv"

# -------- Phase 1: gather candidates by extension --------
log "=== Phase 1/3: Collecting candidates by extension ==="
FIND_EXPR=()
for ext in "${EXTENSIONS[@]}"; do
  FIND_EXPR+=( -iname "*.${ext}" -o )
done
unset 'FIND_EXPR[${#FIND_EXPR[@]}-1]'

mapfile -d '' CANDIDATES < <(find "$ROOT" -type f \( "${FIND_EXPR[@]}" \) -print0)
log "Candidates found: ${#CANDIDATES[@]}"

if (( ${#CANDIDATES[@]} == 0 )); then
  log "Nothing to do."
  log "=== Finished ==="
  exit 0
fi

# -------- Phase 2: probe candidates and build plan --------
log "=== Phase 2/3: Probing candidates and building encode plan ==="
FILES_PROBED=0
FILES_SKIPPED=0

PLAN_FILES=()
PLAN_OUT=()
PLAN_CODEC=()
PLAN_SRC_BPS=()
PLAN_TARGET_KBPS=()
PLAN_ORIG_BYTES=()
PLAN_EST_TGT_BYTES=()

for FILE in "${CANDIDATES[@]}"; do
  FILES_PROBED=$((FILES_PROBED+1))

  if [[ "$FILE" == *.av1.r.mkv || "$FILE" == *.av1.mkv ]]; then
    FILES_SKIPPED=$((FILES_SKIPPED+1))
    continue
  fi

  CODEC="$(get_video_codec "$FILE")"
  if [[ -z "${CODEC:-}" ]]; then
    FILES_SKIPPED=$((FILES_SKIPPED+1))
    continue
  fi

  case "$CODEC" in
    h264) FACTOR="$H264_FACTOR" ;;
    hevc|h265) FACTOR="$HEVC_FACTOR" ;;
    *)
      if $EVERYTHING; then
        FACTOR="$H264_FACTOR"
      else
        FILES_SKIPPED=$((FILES_SKIPPED+1))
        continue
      fi
      ;;
  esac

  SRC_BPS="$(get_video_bitrate_bps "$FILE")"
  if [[ -z "${SRC_BPS:-}" || "$SRC_BPS" == "0" ]]; then
    FILES_SKIPPED=$((FILES_SKIPPED+1))
    continue
  fi

  ORIG_BYTES="$(stat -c%s -- "$FILE")"
  if [[ "$QUALITY_MODE" == "size" ]]; then
    # Derive target video kbps from desired total size and duration, subtracting audio bps.
    DUR="$(get_format_duration "$FILE")"
    AUDIO_BPS="$(get_audio_bitrate_sum_bps "$FILE")"
    # total bps to meet size (bytes*8/duration):
    TOTAL_BPS=$(awk -v bytes="$TARGET_SIZE_BYTES" -v dur="$DUR" 'BEGIN{ if(dur<=0){print 0} else { printf "%.0f", (bytes*8)/dur } }')
    VIDEO_BPS=$(( TOTAL_BPS - AUDIO_BPS ))
    if (( VIDEO_BPS <= 0 )); then
      VIDEO_BPS=250000
    fi
    TARGET_KBPS=$(( (VIDEO_BPS + 500) / 1000 ))
    EST_TGT_BYTES="$TARGET_SIZE_BYTES"
  else
    TARGET_KBPS="$(compute_target_kbps "$SRC_BPS" "$FACTOR")"
    EST_TGT_BYTES="$(estimate_target_bytes_from_ratio "$ORIG_BYTES" "$SRC_BPS" "$TARGET_KBPS")"
  fi

  BASE="${FILE%.*}"
  OUT="${BASE}.av1.r.mkv"
  if [[ -e "$OUT" ]]; then
    OUT="${BASE}.av1.r.${TS}.mkv"
  fi

  PLAN_FILES+=( "$FILE" )
  PLAN_OUT+=( "$OUT" )
  PLAN_CODEC+=( "$CODEC" )
  PLAN_SRC_BPS+=( "$SRC_BPS" )
  PLAN_TARGET_KBPS+=( "$TARGET_KBPS" )
  PLAN_ORIG_BYTES+=( "$ORIG_BYTES" )
  PLAN_EST_TGT_BYTES+=( "$EST_TGT_BYTES" )
done

log "Probed candidates: $FILES_PROBED"
log "Planned encodes  : ${#PLAN_FILES[@]}"
log "Skipped (probe)  : $FILES_SKIPPED"

if (( ${#PLAN_FILES[@]} == 0 )); then
  log "Nothing to encode after probing."
  log "=== Finished ==="
  exit 0
fi

if $DRY_RUN; then
  log "=== DRY RUN: Encode plan ==="
  for i in "${!PLAN_FILES[@]}"; do
    f="${PLAN_FILES[$i]}"
    c="${PLAN_CODEC[$i]}"
    src_kbps=$(( PLAN_SRC_BPS[$i] / 1000 ))
    tgt="${PLAN_TARGET_KBPS[$i]}"
    orig_b="${PLAN_ORIG_BYTES[$i]}"
    est_b="${PLAN_EST_TGT_BYTES[$i]}"
    log "[$((i+1))/${#PLAN_FILES[@]}] codec=$c src≈${src_kbps} kbps ($(fmt_bytes "$orig_b")) target=${tgt} kbps (~$(fmt_bytes "$est_b"))"
    log "  in : $f"
    log "  out: ${PLAN_OUT[$i]}"
    if $APPLY_FILTER; then
      log "  vf : $FILTER_CHAIN"
    fi
  done
  log_scope_run
  log "Dry-run complete. Total elapsed: $(fmt_seconds $(( $(date +%s) - RUN_START_EPOCH )))"
  log "=== Finished ==="
  exit 0
fi

# -------- Phase 3: encode planned list --------
log "=== Phase 3/3: Encoding starts ==="
log "Total files to process: ${#PLAN_FILES[@]}"

FILES_CONVERTED=0
FILES_FAILED=0
TOTAL_ORIG_BYTES=0
TOTAL_NEW_BYTES=0

for i in "${!PLAN_FILES[@]}"; do
  FILE="${PLAN_FILES[$i]}"
  OUT="${PLAN_OUT[$i]}"
  CODEC="${PLAN_CODEC[$i]}"
  SRC_BPS="${PLAN_SRC_BPS[$i]}"
  TARGET_KBPS="${PLAN_TARGET_KBPS[$i]}"
  ORIG_BYTES="${PLAN_ORIG_BYTES[$i]}"
  EST_TGT_BYTES="${PLAN_EST_TGT_BYTES[$i]}"

  log "--------------------------------------------------------------------------------"
  FILE_START_EPOCH="$(date +%s)"
  log_scope_file "$FILE_START_EPOCH"

  log "[$((i+1))/${#PLAN_FILES[@]}] Encoding: $FILE"
  log "codec=$CODEC src≈$((SRC_BPS/1000)) kbps ($(fmt_bytes "$ORIG_BYTES")) target=${TARGET_KBPS} kbps (~$(fmt_bytes "$EST_TGT_BYTES"))"
  log "Output  : $OUT"

  TOTAL_ORIG_BYTES=$((TOTAL_ORIG_BYTES + ORIG_BYTES))

  PASSDIR="$(mktemp -d -t av1pass_XXXXXXXX)"
  PASS_PREFIX="${PASSDIR}/ffmpeg2pass"
  log "Passlog dir: $PASSDIR"

  log "FFmpeg pass 1..."
  set +e
  # Optional filter args for v:0
  VF_ARGS=()
  if $APPLY_FILTER; then
    VF_ARGS+=( -filter:v:0 "$FILTER_CHAIN" )
  fi
  ffmpeg "${FFMPEG_OPTS[@]}" -y \
    -i "$FILE" \
    -map 0:v:0 \
    "${VF_ARGS[@]}" \
    -c:v libsvtav1 -b:v "${TARGET_KBPS}k" \
    -pass 1 -passlogfile "$PASS_PREFIX" \
    -an -sn -dn \
    -f null /dev/null
  RC1=$?
  set -e

  if [[ "$RC1" -ne 0 ]]; then
    log "ERROR: pass 1 failed (exit=$RC1)."
    rm -rf "$PASSDIR" 2>/dev/null || true
    FILES_FAILED=$((FILES_FAILED+1))
    log_scope_run
    continue
  fi

  log "FFmpeg pass 2..."
  set +e
  # Reuse VF_ARGS for pass 2
  VF_ARGS=()
  if $APPLY_FILTER; then
    VF_ARGS+=( -filter:v:0 "$FILTER_CHAIN" )
  fi
  ffmpeg "${FFMPEG_OPTS[@]}" -y \
    -i "$FILE" \
    -map 0 -map_metadata 0 -map_chapters 0 \
    -c copy \
    "${VF_ARGS[@]}" \
    -c:v:0 libsvtav1 -b:v:0 "${TARGET_KBPS}k" \
    -pass 2 -passlogfile "$PASS_PREFIX" \
    "$OUT" 2>&1 | tee /tmp/ffmpeg_pass2.log
  RC2=$?
  set -e

  rm -rf "$PASSDIR" 2>/dev/null || true

  # Check for matroska header write error - indicates corrupted/problematic input container
  if [[ "$RC2" -ne 0 ]] && grep -q "Could not write header" /tmp/ffmpeg_pass2.log 2>/dev/null; then
    log "ERROR: Matroska header write error detected. Container may be corrupted."
    log "Attempting to fix by re-muxing input file to clean MKV..."
    
    # Create a clean MKV copy of the input
    REMUX_FILE="${FILE}.remux.mkv"
    log "Creating clean MKV: $REMUX_FILE"
    set +e
    ffmpeg "${FFMPEG_OPTS[@]}" -y \
      -i "$FILE" \
      -map 0 -map_metadata 0 -map_chapters 0 \
      -c copy \
      "$REMUX_FILE"
    REMUX_RC=$?
    set -e
    
    if [[ "$REMUX_RC" -eq 0 && -s "$REMUX_FILE" ]]; then
      log "Re-mux successful. Replacing original and retrying transcode..."
      
      # Replace original with remuxed version
      rm -f -- "$FILE"
      mv "$REMUX_FILE" "$FILE"
      
      # Retry pass 1
      PASSDIR="$(mktemp -d -t av1pass_retry_XXXXXXXX)"
      PASS_PREFIX="${PASSDIR}/ffmpeg2pass"
      log "Retry: FFmpeg pass 1..."
      set +e
      VF_ARGS=()
      if $APPLY_FILTER; then
        VF_ARGS+=( -filter:v:0 "$FILTER_CHAIN" )
      fi
      ffmpeg "${FFMPEG_OPTS[@]}" -y \
        -i "$FILE" \
        -map 0:v:0 \
        "${VF_ARGS[@]}" \
        -c:v libsvtav1 -b:v "${TARGET_KBPS}k" \
        -pass 1 -passlogfile "$PASS_PREFIX" \
        -an -sn -dn \
        -f null /dev/null
      RC1=$?
      set -e
      
      if [[ "$RC1" -ne 0 ]]; then
        log "ERROR: Retry pass 1 failed (exit=$RC1)."
        rm -rf "$PASSDIR" 2>/dev/null || true
        FILES_FAILED=$((FILES_FAILED+1))
        log_scope_run
        continue
      fi
      
      # Retry pass 2
      log "Retry: FFmpeg pass 2..."
      set +e
      VF_ARGS=()
      if $APPLY_FILTER; then
        VF_ARGS+=( -filter:v:0 "$FILTER_CHAIN" )
      fi
      ffmpeg "${FFMPEG_OPTS[@]}" -y \
        -i "$FILE" \
        -map 0 -map_metadata 0 -map_chapters 0 \
        "${VF_ARGS[@]}" \
        -c:v:0 libsvtav1 -b:v:0 "${TARGET_KBPS}k" \
        -c:a copy -c:s copy -c:d copy -c:t copy \
        -c:v:1 copy -c:v:2 copy -c:v:3 copy -c:v:4 copy -c:v:5 copy \
        -pass 2 -passlogfile "$PASS_PREFIX" \
        "$OUT"
      RC2=$?
      set -e
      
      rm -rf "$PASSDIR" 2>/dev/null || true
      
      if [[ "$RC2" -ne 0 || ! -s "$OUT" ]]; then
        log "ERROR: Retry pass 2 failed or output missing/empty (exit=$RC2)."
        rm -f -- "$OUT" 2>/dev/null || true
        FILES_FAILED=$((FILES_FAILED+1))
        log_scope_run
        continue
      fi
      
      log "SUCCESS: Transcode completed after re-mux."
    else
      log "ERROR: Re-mux failed (exit=$REMUX_RC). Giving up on this file."
      rm -f -- "$REMUX_FILE" 2>/dev/null || true
      rm -f -- "$OUT" 2>/dev/null || true
      FILES_FAILED=$((FILES_FAILED+1))
      log_scope_run
      continue
    fi
  elif [[ "$RC2" -ne 0 || ! -s "$OUT" ]]; then
    log "ERROR: pass 2 failed or output missing/empty (exit=$RC2)."
    rm -f -- "$OUT" 2>/dev/null || true
    FILES_FAILED=$((FILES_FAILED+1))
    log_scope_run
    continue
  fi

  NEW_BYTES="$(stat -c%s -- "$OUT")"
  TOTAL_NEW_BYTES=$((TOTAL_NEW_BYTES + NEW_BYTES))

  SAVED_BYTES=$((ORIG_BYTES - NEW_BYTES))
  SAVED_PCT="$(awk -v o="$ORIG_BYTES" -v n="$NEW_BYTES" 'BEGIN{ if(o<=0){print "0.00"} else {printf "%.2f", (o-n)*100.0/o} }')"
  log "Size: original=$(fmt_bytes "$ORIG_BYTES") new=$(fmt_bytes "$NEW_BYTES") saved=$(fmt_bytes "$SAVED_BYTES") (${SAVED_PCT}%)"
  
  # Calculate VMAF score and rename output file
  VMAF_SCORE=$(calculate_vmaf "$OUT" "$FILE")
  if [[ "$VMAF_SCORE" != "0" ]]; then
    log "VMAF score: $VMAF_SCORE"
    
    # Rename output to include VMAF score: basename.VMAF.av1.r.mkv
    BASE="${FILE%.*}"
    OUT_DIR="$(dirname "$OUT")"
    OUT_NAME="$(basename "$OUT")"
    
    # Check if timestamp was added to output name
    if [[ "$OUT_NAME" =~ \.av1\.r\.[0-9]{8}_[0-9]{6}\.mkv$ ]]; then
      # Has timestamp: basename.av1.r.YYYYmmdd_HHMMSS.mkv -> basename.VMAF.av1.r.YYYYmmdd_HHMMSS.mkv
      NEW_OUT="${OUT%.av1.r.*.mkv}.${VMAF_SCORE}.av1.r.${TS}.mkv"
    else
      # No timestamp: basename.av1.r.mkv -> basename.VMAF.av1.r.mkv
      NEW_OUT="${BASE}.${VMAF_SCORE}.av1.r.mkv"
    fi
    
    mv "$OUT" "$NEW_OUT"
    log "Renamed to: $NEW_OUT"
    OUT="$NEW_OUT"
    
    # Track files with VMAF < 90
    if (( VMAF_SCORE < 90 )); then
      LOW_VMAF_FILES+=("$OUT (VMAF: $VMAF_SCORE)")
    fi
  fi

  if $DELETE_ORIGINAL; then
    if (( NEW_BYTES < ORIG_BYTES )); then
      # Check VMAF requirement unless --delete-always is used
      if $DELETE_ALWAYS || (( VMAF_SCORE >= 90 )); then
        rm -f -- "$FILE"
        if $DELETE_ALWAYS; then
          log "Deleted original (output is smaller, --delete-always)."
        else
          log "Deleted original (output is smaller and VMAF >= 90)."
        fi
      else
        log "Keeping original (VMAF $VMAF_SCORE < 90). Use --delete-always to override."
      fi
    else
      rm -f -- "$OUT"
      log "Output was not smaller; deleted output and kept original."
      TOTAL_NEW_BYTES=$((TOTAL_NEW_BYTES - NEW_BYTES))
      TOTAL_ORIG_BYTES=$((TOTAL_ORIG_BYTES - ORIG_BYTES))
      log_scope_run
      continue
    fi
  fi

  FILES_CONVERTED=$((FILES_CONVERTED+1))
  log "File done. Elapsed (file): $(fmt_seconds $(( $(date +%s) - FILE_START_EPOCH )))"

  log_scope_run
done

log "================================================================================"
log "=== Summary ==="
log "Candidates found : ${#CANDIDATES[@]}"
log "Planned encodes  : ${#PLAN_FILES[@]}"
log "Converted        : $FILES_CONVERTED"
log "Failed           : $FILES_FAILED"
log "Time total       : $(fmt_seconds $(( $(date +%s) - RUN_START_EPOCH )))"

if (( TOTAL_ORIG_BYTES > 0 && TOTAL_NEW_BYTES > 0 )); then
  TOTAL_SAVED=$((TOTAL_ORIG_BYTES - TOTAL_NEW_BYTES))
  TOTAL_SAVED_PCT="$(awk -v o="$TOTAL_ORIG_BYTES" -v n="$TOTAL_NEW_BYTES" 'BEGIN{ printf "%.2f", (o-n)*100.0/o }')"
  log "Bytes original   : $(fmt_bytes "$TOTAL_ORIG_BYTES")"
  log "Bytes new        : $(fmt_bytes "$TOTAL_NEW_BYTES")"
  log "Bytes saved      : $(fmt_bytes "$TOTAL_SAVED") (${TOTAL_SAVED_PCT}%)"
fi

if (( ${#LOW_VMAF_FILES[@]} > 0 )); then
  log "================================================================================"
  log "=== Files with VMAF < 90 (may need quality review) ==="
  for file in "${LOW_VMAF_FILES[@]}"; do
    log "  $file"
  done
fi

log "=== Finished ==="
