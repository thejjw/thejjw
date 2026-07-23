#!/bin/bash

# AV1 Transcode Script
# 30%(40% -lq) reduction for h264, 20%(30% -lq) reduction for hevc
# 2025.12-2026.4 @thejjw

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
                        2) VMAF score is 93 [1] or above.
                        If output is not smaller, output is deleted and original is kept.
[1] The "Average > 93" rule for VMAF is widely accepted in the video compression industry as the threshold for "Visually Lossless" (or "Transparent") quality.
  --delete-safe         Delete original after successful conversion ONLY if VMAF >= 93.
                        Otherwise keep both transcode and original for human comparison.
                        If output is not smaller, output is deleted and original is kept.
  --delete-always       Delete original after successful conversion if output is smaller,
                        regardless of VMAF score. (Original -d behavior)
                        If output is not smaller, output is deleted and original is kept.
    NOTE: "Bad quality" encodes are identified when the average VMAF < 70 OR any
      partition window VMAF < 55.
      - With no --delete* flag: output is kept for manual review.
      - With any --delete* flag: output is deleted and original is kept.

  NOTE: -d, --delete, --delete-safe, and --delete-always are mutually exclusive.
        Only one deletion mode can be specified.
  --dry-run             Do not encode. Only list what would be processed and the target bitrates
                        including estimated size change.
  -e, --everything     Encode any supported video codec (default encodes only h264/hevc/h265).
  -f, --filter          Apply video filter chain during encode:
                        unsharp=5:5:1.0:5:5:0.0,hqdn3d=4:3:6:4
  --quality <low|1gb|2gb|4gb>
                        Quality preset:
                          * low  → h264 target = 60% (40% less), hevc target = 70% (30% less)
                          * 1gb  → target ~1 GiB size limit (uses default bitrate if smaller)
                          * 2gb  → target ~2 GiB size limit (uses default bitrate if smaller)
                          * 4gb  → target ~4 GiB size limit (uses default bitrate if smaller)
                        All presets use 2-pass SVT-AV1.
                        Default (no --quality): h264 target = 70% (30% less), hevc target = 80% (20% less).
  --try-crf-first       Try 1-pass CRF first (complexity-derived CRF), then fallback to 2-pass ABR
                        if the CRF output fails policy. Cannot be used with --quality.
  --vmaf-mode <sequential|full|sampled>
                        VMAF evaluation strategy:
                          * sequential: single full-clip VMAF run (legacy behavior)
                          * full: split duration into equal partitions, score all partitions in parallel
                          * sampled: score a stratified subset of equal partitions in parallel (faster, approximate)
                        Default: full
  --vmaf-subsample <N>  libvmaf n_subsample (compute scores every Nth frame)
                        Practical values:
                          * 1 = highest-fidelity scoring (recommended for short clips/final checks)
                          * 3 = recommended speed/accuracy balance for long videos
                          * 5 = faster, with higher risk of score variance
                        Avoid even values > 1 due to known potential score bias.
                        Reference: https://github.com/Netflix/vmaf/issues/1214
                        Default policy: 3 for sufficiently long videos, forced to 1 when
                        duration < --vmaf-min-subsample-seconds.
  --vmaf-jobs <N>       Parallel VMAF workers for full/sampled modes (default: 4)
  --vmaf-partitions <N> Number of equal duration partitions for full mode (default: 12)
  --vmaf-samples <N>    Number of stratified partitions sampled in sampled mode (default: 6)
  --vmaf-min-parallel-seconds <N>
                        If duration < N, force sequential mode (default: 7200 = 120 minutes)
  --vmaf-min-subsample-seconds <N>
                        If duration < N, force n_subsample=1 (default: 600 = 10 minutes)
  -h, --help            Show this help.

Output naming
  - Output is: "<original_basename>.av1.r.mkv"
  - If that already exists, a timestamp is inserted:
      "<original_basename>.av1.r.<YYYYmmdd_HHMMSS>.mkv"

FFmpeg verbosity / progress
  - This script runs ffmpeg with:
      -hide_banner -loglevel warning -stats -stats_period 180
    so you still get progress lines, but only every 180 seconds.

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
  - Always deletes outputs with VMAF < 70 and reports them as bad quality encodes.
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
  ffmpeg -hide_banner -encoders 2>&1 | awk '{print $2}' | grep -qx "$enc"
}

has_libvmaf() {
  # Check if FFmpeg was built with libvmaf support by examining its configuration.
  # This is more reliable than using -filters which can be inconsistent.
  ffmpeg -version 2>&1 | grep -q -- "--enable-libvmaf"
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

# FFmpeg: quieter logs + progress only every 180s
# -stats_period is documented as the update period for stats/progress. :contentReference[oaicite:4]{index=4}
# -stats forces periodic stats even when loglevel is set. :contentReference[oaicite:5]{index=5}
FFMPEG_OPTS=( -hide_banner -loglevel warning -stats -stats_period 180 )

# Calculate VMAF score for a window between distorted (output) and reference (original) video.
# If duration is empty, the whole clip is scored.
calculate_vmaf_window() {
  local distorted="$1"
  local reference="$2"
  local start_sec="$3"
  local duration_sec="$4"
  local subsample="$5"
  local output_log="$(mktemp -t vmaf_output_XXXXXXXX.log)"

  local libvmaf_arg="libvmaf"
  if [[ "$subsample" =~ ^[0-9]+$ ]] && (( subsample > 1 )); then
    libvmaf_arg="libvmaf=n_subsample=${subsample}"
  fi

  # Build optional trim args once and apply to both inputs.
  local window_args=()
  if [[ -n "$start_sec" && -n "$duration_sec" ]]; then
    window_args=( -ss "$start_sec" -t "$duration_sec" )
  fi

  # Run ffmpeg with libvmaf filter; map only video streams and reset PTS to avoid DTS warnings.
  # Capture all output to parse for "VMAF score: XX.YY"
  set +e
  ffmpeg -hide_banner -loglevel info \
    "${window_args[@]}" -i "$distorted" \
    "${window_args[@]}" -i "$reference" \
    -map 0:v:0 -map 1:v:0 \
    -filter_complex "[0:v:0]setpts=PTS-STARTPTS[dist];[1:v:0]setpts=PTS-STARTPTS[ref];[dist][ref]${libvmaf_arg}" \
    -an -sn -dn \
    -f null - > "$output_log" 2>&1
  local rc=$?
  set -e

  # Parse stderr/stdout for "VMAF score: XX.YY" lines and take the last one (preserve 2 decimal places)
  local vmaf_score
  vmaf_score=$(grep -i "VMAF score:" "$output_log" 2>/dev/null | tail -n 1 | awk -F': ' '{print $2}' | awk '{printf "%.2f", $1}')

  if [[ -z "$vmaf_score" || "$vmaf_score" == "0.00" ]]; then
    log "WARNING: Could not parse VMAF score from output (exit=$rc)" >&2
    if [[ -s "$output_log" ]]; then
      log "FFmpeg output (last 20 lines):" >&2
      tail -n 20 "$output_log" | sed 's/^/  /' >&2
    fi
    rm -f "$output_log" 2>/dev/null || true
    echo "0"
    return 1
  fi

  rm -f "$output_log" 2>/dev/null || true

  echo "$vmaf_score"
  return 0
}

get_video_width_height_fps() {
  local f="$1"
  ffprobe -v error -select_streams v:0 \
    -show_entries stream=width,height,avg_frame_rate \
    -of default=nk=1:nw=1 -- "$f" 2>/dev/null | tr '\n' ' '
}

compute_crf_from_complexity() {
  local file="$1"
  local src_bps="$2"
  local whf width height fps_raw fps crf

  whf="$(get_video_width_height_fps "$file")"
  width="$(awk '{print $1}' <<< "$whf")"
  height="$(awk '{print $2}' <<< "$whf")"
  fps_raw="$(awk '{print $3}' <<< "$whf")"

  if [[ -z "$width" || -z "$height" || -z "$fps_raw" || "$width" == "N/A" || "$height" == "N/A" || "$fps_raw" == "N/A" ]]; then
    echo 30
    return 0
  fi

  fps="$(awk -v r="$fps_raw" 'BEGIN{
    split(r, a, "/");
    if (a[2] == "" || a[2] == 0) {
      if (r+0 > 0) printf "%.6f", r+0;
      else print "0";
    } else {
      printf "%.6f", a[1]/a[2];
    }
  }')"

  crf="$(awk -v bps="$src_bps" -v w="$width" -v h="$height" -v fps="$fps" 'BEGIN{
    if (bps<=0 || w<=0 || h<=0 || fps<=0) { print 30; exit; }
    bpppf = bps / (w*h*fps);
    if (bpppf >= 0.20) print 24;
    else if (bpppf >= 0.12) print 26;
    else if (bpppf >= 0.08) print 28;
    else if (bpppf >= 0.05) print 30;
    else print 32;
  }')"

  echo "$crf"
}

run_vmaf_jobs_with_limit() {
  local max_jobs="$1"
  while :; do
    local running
    running=$(jobs -rp | wc -l)
    if (( running < max_jobs )); then
      break
    fi
    wait -n 2>/dev/null || true
  done
}

# Returns: "avg|min|effective_mode|effective_subsample|window_count"
calculate_vmaf_mode() {
  local distorted="$1"
  local reference="$2"
  local requested_mode="$3"
  local requested_subsample="$4"
  local jobs="$5"
  local partitions="$6"
  local samples="$7"
  local min_parallel_secs="$8"
  local min_subsample_secs="$9"

  local duration
  duration="$(get_format_duration "$reference")"
  if [[ -z "$duration" || "$duration" == "N/A" ]]; then
    duration="0"
  fi

  local effective_mode="$requested_mode"
  if awk -v d="$duration" -v min="$min_parallel_secs" 'BEGIN{ exit !(d < min) }'; then
    if [[ "$requested_mode" != "sequential" ]]; then
      log "VMAF duration guard: duration=${duration}s < ${min_parallel_secs}s, forcing sequential mode." >&2
    fi
    effective_mode="sequential"
  fi

  local effective_subsample="$requested_subsample"
  if awk -v d="$duration" -v min="$min_subsample_secs" 'BEGIN{ exit !(d < min) }'; then
    if [[ "$requested_subsample" -gt 1 ]]; then
      log "VMAF subsample guard: duration=${duration}s < ${min_subsample_secs}s, forcing n_subsample=1." >&2
    fi
    effective_subsample=1
  fi

  if [[ "$effective_mode" == "sequential" ]]; then
    local score
    score="$(calculate_vmaf_window "$distorted" "$reference" "" "" "$effective_subsample")" || {
      echo "0|0|$effective_mode|$effective_subsample|0"
      return 1
    }
    echo "$score|$score|$effective_mode|$effective_subsample|1"
    return 0
  fi

  if [[ ! "$partitions" =~ ^[0-9]+$ ]] || (( partitions < 1 )); then
    partitions=1
  fi
  if [[ ! "$samples" =~ ^[0-9]+$ ]] || (( samples < 1 )); then
    samples=1
  fi
  if [[ ! "$jobs" =~ ^[0-9]+$ ]] || (( jobs < 1 )); then
    jobs=1
  fi

  local selected_count
  local selected_indices=()
  if [[ "$effective_mode" == "full" || samples -ge partitions ]]; then
    local idx
    for ((idx=0; idx<partitions; idx++)); do
      selected_indices+=("$idx")
    done
  else
    # Stratified picks across partition index space.
    declare -A seen
    local k idx
    for ((k=0; k<samples; k++)); do
      idx="$(awk -v k="$k" -v p="$partitions" -v s="$samples" 'BEGIN{ print int((k + 0.5) * p / s) }')"
      if (( idx >= partitions )); then
        idx=$((partitions-1))
      fi
      if [[ -z "${seen[$idx]:-}" ]]; then
        seen[$idx]=1
        selected_indices+=("$idx")
      fi
    done
  fi

  selected_count="${#selected_indices[@]}"
  if (( selected_count == 0 )); then
    log "WARNING: No VMAF windows selected; falling back to sequential." >&2
    local score
    score="$(calculate_vmaf_window "$distorted" "$reference" "" "" "$effective_subsample")" || {
      echo "0|0|sequential|$effective_subsample|0"
      return 1
    }
    echo "$score|$score|sequential|$effective_subsample|1"
    return 0
  fi

  local tmpdir
  tmpdir="$(mktemp -d -t vmaf_parts_XXXXXXXX)"

  local idx start end wdur
  for idx in "${selected_indices[@]}"; do
    start="$(awk -v i="$idx" -v d="$duration" -v p="$partitions" 'BEGIN{ printf "%.6f", (i*d)/p }')"
    end="$(awk -v i="$idx" -v d="$duration" -v p="$partitions" 'BEGIN{ printf "%.6f", ((i+1)*d)/p }')"
    wdur="$(awk -v s="$start" -v e="$end" 'BEGIN{ printf "%.6f", e-s }')"

    run_vmaf_jobs_with_limit "$jobs"
    (
      local s
      if s="$(calculate_vmaf_window "$distorted" "$reference" "$start" "$wdur" "$effective_subsample")"; then
        echo "$s $wdur" > "$tmpdir/$idx.ok"
      else
        echo "fail" > "$tmpdir/$idx.fail"
      fi
    ) &
  done

  wait

  local weighted_sum="0"
  local dur_sum="0"
  local min_score="101"

  for idx in "${selected_indices[@]}"; do
    if [[ -f "$tmpdir/$idx.fail" || ! -f "$tmpdir/$idx.ok" ]]; then
      rm -rf "$tmpdir" 2>/dev/null || true
      log "WARNING: Windowed VMAF failed; falling back to sequential." >&2
      local score
      score="$(calculate_vmaf_window "$distorted" "$reference" "" "" "$effective_subsample")" || {
        echo "0|0|sequential|$effective_subsample|0"
        return 1
      }
      echo "$score|$score|sequential|$effective_subsample|1"
      return 0
    fi

    local s d
    s="$(awk '{print $1}' "$tmpdir/$idx.ok")"
    d="$(awk '{print $2}' "$tmpdir/$idx.ok")"

    weighted_sum="$(awk -v ws="$weighted_sum" -v sc="$s" -v du="$d" 'BEGIN{ printf "%.10f", ws + (sc*du) }')"
    dur_sum="$(awk -v ds="$dur_sum" -v du="$d" 'BEGIN{ printf "%.10f", ds + du }')"
    min_score="$(awk -v m="$min_score" -v sc="$s" 'BEGIN{ if (sc<m) printf "%.2f", sc; else printf "%.2f", m }')"
  done

  rm -rf "$tmpdir" 2>/dev/null || true

  local avg
  avg="$(awk -v ws="$weighted_sum" -v ds="$dur_sum" 'BEGIN{ if (ds<=0) print "0.00"; else printf "%.2f", ws/ds }')"
  echo "$avg|$min_score|$effective_mode|$effective_subsample|$selected_count"
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
DELETE_SAFE=false
DRY_RUN=false
QUALITY_MODE="normal"
ROOT="."
APPLY_FILTER=false
FILTER_CHAIN='unsharp=5:5:1.0:5:5:0.0,hqdn3d=4:3:6:4'
TARGET_SIZE_BYTES=0
EVERYTHING=false
TRY_CRF_FIRST=false
VMAF_MODE="full"
VMAF_SUBSAMPLE=3
VMAF_JOBS=4
VMAF_PARTITIONS=12
VMAF_SAMPLES=6
VMAF_MIN_PARALLEL_SECONDS=7200
VMAF_MIN_SUBSAMPLE_SECONDS=600

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--delete)
      if $DELETE_SAFE || $DELETE_ALWAYS; then
        echo "ERROR: -d/--delete cannot be combined with --delete-safe or --delete-always" >&2
        usage
        exit 1
      fi
      DELETE_ORIGINAL=true
      shift
      ;;
    --delete-safe)
      if $DELETE_ORIGINAL || $DELETE_ALWAYS; then
        echo "ERROR: --delete-safe cannot be combined with -d/--delete or --delete-always" >&2
        usage
        exit 1
      fi
      DELETE_ORIGINAL=true
      DELETE_SAFE=true
      shift
      ;;
    --delete-always)
      if $DELETE_ORIGINAL || $DELETE_SAFE; then
        echo "ERROR: --delete-always cannot be combined with -d/--delete or --delete-safe" >&2
        usage
        exit 1
      fi
      DELETE_ORIGINAL=true
      DELETE_ALWAYS=true
      shift
      ;;
    --dry-run) DRY_RUN=true; shift ;;
    -e|--everything) EVERYTHING=true; shift ;;
    -f|--filter) APPLY_FILTER=true; shift ;;
    --try-crf-first)
      TRY_CRF_FIRST=true
      shift
      ;;
    --vmaf-mode)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --vmaf-mode requires a value (sequential|full|sampled)" >&2
        usage
        exit 1
      fi
      case "$2" in
        sequential|full|sampled) VMAF_MODE="$2" ;;
        *)
          echo "ERROR: unknown --vmaf-mode value: $2" >&2
          usage
          exit 1
          ;;
      esac
      shift 2
      ;;
    --vmaf-subsample)
      if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ || "$2" -lt 1 ]]; then
        echo "ERROR: --vmaf-subsample requires integer >= 1" >&2
        usage
        exit 1
      fi
      if (( "$2" > 1 )) && (( "$2" % 2 == 0 )); then
        echo "ERROR: --vmaf-subsample even values > 1 are not allowed (use 1, 3, 5, ...)." >&2
        echo "       Reason: even n_subsample values may cause biased VMAF scores on some content." >&2
        echo "       Re-check status: https://github.com/Netflix/vmaf/issues/1214" >&2
        echo "       Search keyword: Netflix VMAF n_subsample even values" >&2
        usage
        exit 1
      fi
      VMAF_SUBSAMPLE="$2"
      shift 2
      ;;
    --vmaf-jobs)
      if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ || "$2" -lt 1 ]]; then
        echo "ERROR: --vmaf-jobs requires integer >= 1" >&2
        usage
        exit 1
      fi
      VMAF_JOBS="$2"
      shift 2
      ;;
    --vmaf-partitions)
      if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ || "$2" -lt 1 ]]; then
        echo "ERROR: --vmaf-partitions requires integer >= 1" >&2
        usage
        exit 1
      fi
      VMAF_PARTITIONS="$2"
      shift 2
      ;;
    --vmaf-samples)
      if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ || "$2" -lt 1 ]]; then
        echo "ERROR: --vmaf-samples requires integer >= 1" >&2
        usage
        exit 1
      fi
      VMAF_SAMPLES="$2"
      shift 2
      ;;
    --vmaf-min-parallel-seconds)
      if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ || "$2" -lt 1 ]]; then
        echo "ERROR: --vmaf-min-parallel-seconds requires integer >= 1" >&2
        usage
        exit 1
      fi
      VMAF_MIN_PARALLEL_SECONDS="$2"
      shift 2
      ;;
    --vmaf-min-subsample-seconds)
      if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ || "$2" -lt 1 ]]; then
        echo "ERROR: --vmaf-min-subsample-seconds requires integer >= 1" >&2
        usage
        exit 1
      fi
      VMAF_MIN_SUBSAMPLE_SECONDS="$2"
      shift 2
      ;;
    --quality)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --quality requires a value (low|1gb|2gb|4gb)" >&2
        usage
        exit 1
      fi
      case "$2" in
        low) QUALITY_MODE="low" ;;
        1gb) QUALITY_MODE="size"; TARGET_SIZE_BYTES=$((1000*1000*1000)) ;;
        2gb) QUALITY_MODE="size"; TARGET_SIZE_BYTES=$((2*1000*1000*1000)) ;;
        4gb) QUALITY_MODE="size"; TARGET_SIZE_BYTES=$((4*1000*1000*1000)) ;;
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

if $TRY_CRF_FIRST && [[ "$QUALITY_MODE" != "normal" ]]; then
  echo "ERROR: --try-crf-first cannot be combined with --quality" >&2
  usage
  exit 1
fi

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

if ! has_libvmaf; then
  echo "ERROR: ffmpeg does not have 'libvmaf' support." >&2
  echo "       VMAF scoring is required. Install FFmpeg with libvmaf enabled." >&2
  exit 1
fi

TS="$(date +%Y%m%d_%H%M%S)"
LOGFILE="transcode_av1_${TS}.log"
exec > >(tee -a "$LOGFILE") 2>&1
log_init

# Array to track files with VMAF < 93
LOW_VMAF_FILES=()
# Array to track files with VMAF < 70 (bad quality encodes)
BAD_VMAF_FILES=()

log "=== AV1 Transcode Run Started ==="
log "Root            : $ROOT"
if $DELETE_ORIGINAL; then
  if $DELETE_ALWAYS; then
    log "Delete original : ALWAYS (if smaller)"
  elif $DELETE_SAFE; then
    log "Delete original : SAFE (delete only if VMAF > 93, otherwise keep both)"
  else
    log "Delete original : YES (if smaller AND VMAF >= 93)"
  fi
else
  log "Delete original : NO"
fi
log "Dry-run         : $DRY_RUN"
log "Everything      : $EVERYTHING"
log "Try CRF first   : $TRY_CRF_FIRST"
log "Quality mode    : $QUALITY_MODE"
if [[ "$QUALITY_MODE" == "size" ]]; then
  log "Target size     : $(fmt_bytes "$TARGET_SIZE_BYTES")"
fi
log "Log             : $LOGFILE"
log "Extensions      : ${EXTENSIONS[*]}"
log "FFmpeg opts     : ${FFMPEG_OPTS[*]}"
log "VMAF mode       : $VMAF_MODE"
log "VMAF subsample  : $VMAF_SUBSAMPLE"
log "VMAF jobs       : $VMAF_JOBS"
log "VMAF partitions : $VMAF_PARTITIONS"
log "VMAF samples    : $VMAF_SAMPLES"
log "VMAF min-par sec: $VMAF_MIN_PARALLEL_SECONDS"
log "VMAF min-sub sec: $VMAF_MIN_SUBSAMPLE_SECONDS"
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
  # For size-targeted mode, normal default rule is preferred if it yields a smaller size.
  H264_FACTOR="0.00"
  HEVC_FACTOR="0.00"
  log "Bitrate rule    : SIZE-TARGET (~$(fmt_bytes "$TARGET_SIZE_BYTES"))"
  log "  video target  : default normal rule if default size <= limit, else computed to fit limit"
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

  # Skip if video is already AV1 (since we're transcoding to AV1)
  if [[ "$CODEC" == "av1" ]]; then
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
    # 1. Compute Default (no --quality) bitrate and estimated size for comparison
    DEFAULT_FACTOR="0.70"
    case "$CODEC" in
      hevc|h265) DEFAULT_FACTOR="0.80" ;;
      *) DEFAULT_FACTOR="0.70" ;;
    esac

    DEFAULT_TARGET_KBPS="$(compute_target_kbps "$SRC_BPS" "$DEFAULT_FACTOR")"
    DEFAULT_EST_TGT_BYTES="$(estimate_target_bytes_from_ratio "$ORIG_BYTES" "$SRC_BPS" "$DEFAULT_TARGET_KBPS")"

    # 2. Use default if it is already smaller than the specified target size limit; otherwise, scale to fit limit.
    if awk -v def_est="$DEFAULT_EST_TGT_BYTES" -v limit="$TARGET_SIZE_BYTES" 'BEGIN { exit !(def_est <= limit) }'; then
      TARGET_KBPS="$DEFAULT_TARGET_KBPS"
      EST_TGT_BYTES="$DEFAULT_EST_TGT_BYTES"
      log "File: $(basename "$FILE") - Default target size (~$(fmt_bytes "$DEFAULT_EST_TGT_BYTES")) <= limit ($(fmt_bytes "$TARGET_SIZE_BYTES")). Using default normal bitrate (${TARGET_KBPS} kbps)."
    else
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
      log "File: $(basename "$FILE") - Default target size (~$(fmt_bytes "$DEFAULT_EST_TGT_BYTES")) > limit ($(fmt_bytes "$TARGET_SIZE_BYTES")). Applying size-constrained bitrate (${TARGET_KBPS} kbps)."
    fi
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

  ENCODED_WITH_CRF=false
  if $TRY_CRF_FIRST; then
    CRF_VALUE="$(compute_crf_from_complexity "$FILE" "$SRC_BPS")"
    log "Trying CRF-first encode (derived CRF=${CRF_VALUE}) before ABR fallback..."
    set +e
    VF_ARGS=()
    if $APPLY_FILTER; then
      VF_ARGS+=( -filter:v:0 "$FILTER_CHAIN" )
    fi
    ffmpeg "${FFMPEG_OPTS[@]}" -y \
      -i "$FILE" \
      -map 0 -map_metadata 0 -map_chapters 0 \
      -c copy \
      "${VF_ARGS[@]}" \
      -c:v:0 libsvtav1 -crf:v:0 "$CRF_VALUE" -b:v:0 0 \
      "$OUT"
    RC_CRF=$?
    set -e

    if [[ "$RC_CRF" -eq 0 && -s "$OUT" ]]; then
      ENCODED_WITH_CRF=true
      RC2=0
      log "CRF-first encode completed."
    else
      rm -f -- "$OUT" 2>/dev/null || true
      log "CRF-first failed (exit=$RC_CRF). Falling back to 2-pass ABR."
    fi
  fi

  RC2=1
  if ! $ENCODED_WITH_CRF; then
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
  fi

  rm -rf "$PASSDIR" 2>/dev/null || true

  # Check for matroska header write error - indicates corrupted/problematic input container
  if ! $ENCODED_WITH_CRF && [[ "$RC2" -ne 0 ]] && grep -q "Could not write header" /tmp/ffmpeg_pass2.log 2>/dev/null; then
    log "ERROR: Matroska header write error detected. Container may be corrupted."
    log "Attempting to fix by re-muxing input file to clean MKV..."
    
    # Create a clean MKV copy of the input
    # Only map supported Matroska streams (video, audio, subtitles) and skip unsupported types (data, attachments, etc.)
    REMUX_FILE="${FILE}.remux.mkv"
    log "Creating clean MKV: $REMUX_FILE"
    set +e
    ffmpeg "${FFMPEG_OPTS[@]}" -y \
      -i "$FILE" \
      -map 0:v:0 -map 0:a? -map 0:s? \
      -map_metadata 0 -map_chapters 0 \
      -c:v copy -c:a copy -c:s copy \
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

  # Always delete output if it's bigger than original (skip expensive VMAF for these).
  if (( NEW_BYTES >= ORIG_BYTES )); then
    if $ENCODED_WITH_CRF; then
      log "CRF-first output was not smaller; deleting and falling back to 2-pass ABR."
      OLD_NEW_BYTES="$NEW_BYTES"
      rm -f -- "$OUT"

      PASSDIR="$(mktemp -d -t av1pass_fallback_XXXXXXXX)"
      PASS_PREFIX="${PASSDIR}/ffmpeg2pass"

      log "ABR fallback pass 1..."
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
        log "ERROR: ABR fallback pass 1 failed (exit=$RC1)."
        rm -rf "$PASSDIR" 2>/dev/null || true
        FILES_FAILED=$((FILES_FAILED+1))
        log_scope_run
        continue
      fi

      log "ABR fallback pass 2..."
      set +e
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
        "$OUT"
      RC2=$?
      set -e
      rm -rf "$PASSDIR" 2>/dev/null || true

      if [[ "$RC2" -ne 0 || ! -s "$OUT" ]]; then
        log "ERROR: ABR fallback pass 2 failed or output missing/empty (exit=$RC2)."
        rm -f -- "$OUT" 2>/dev/null || true
        FILES_FAILED=$((FILES_FAILED+1))
        log_scope_run
        continue
      fi

      NEW_BYTES="$(stat -c%s -- "$OUT")"
      TOTAL_NEW_BYTES=$((TOTAL_NEW_BYTES - OLD_NEW_BYTES + NEW_BYTES))
      SAVED_BYTES=$((ORIG_BYTES - NEW_BYTES))
      SAVED_PCT="$(awk -v o="$ORIG_BYTES" -v n="$NEW_BYTES" 'BEGIN{ if(o<=0){print "0.00"} else {printf "%.2f", (o-n)*100.0/o} }')"
      log "Fallback size: original=$(fmt_bytes "$ORIG_BYTES") new=$(fmt_bytes "$NEW_BYTES") saved=$(fmt_bytes "$SAVED_BYTES") (${SAVED_PCT}%)"
    fi

    if (( NEW_BYTES >= ORIG_BYTES )); then
      rm -fv -- "$OUT"
      log "Output was not smaller; deleted output and kept original."
      TOTAL_NEW_BYTES=$((TOTAL_NEW_BYTES - NEW_BYTES))
      TOTAL_ORIG_BYTES=$((TOTAL_ORIG_BYTES - ORIG_BYTES))
      log_scope_run
      continue
    fi
  fi
  
  # Calculate VMAF score(s) and rename output file
  VMAF_SCORE=0
  VMAF_MIN_SCORE=0
  VMAF_EFFECTIVE_MODE="sequential"
  VMAF_EFFECTIVE_SUBSAMPLE=1
  VMAF_WINDOW_COUNT=0
  VMAF_RESULT=""
  if ! VMAF_RESULT=$(calculate_vmaf_mode "$OUT" "$FILE" "$VMAF_MODE" "$VMAF_SUBSAMPLE" "$VMAF_JOBS" "$VMAF_PARTITIONS" "$VMAF_SAMPLES" "$VMAF_MIN_PARALLEL_SECONDS" "$VMAF_MIN_SUBSAMPLE_SECONDS"); then
    VMAF_SCORE=0
    VMAF_MIN_SCORE=0
    log "WARNING: VMAF calculation failed; continuing without VMAF-driven actions."
  else
    VMAF_SCORE="$(awk -F'|' '{print $1}' <<< "$VMAF_RESULT")"
    VMAF_MIN_SCORE="$(awk -F'|' '{print $2}' <<< "$VMAF_RESULT")"
    VMAF_EFFECTIVE_MODE="$(awk -F'|' '{print $3}' <<< "$VMAF_RESULT")"
    VMAF_EFFECTIVE_SUBSAMPLE="$(awk -F'|' '{print $4}' <<< "$VMAF_RESULT")"
    VMAF_WINDOW_COUNT="$(awk -F'|' '{print $5}' <<< "$VMAF_RESULT")"
  fi

  if [[ "$VMAF_SCORE" != "0" && "$VMAF_SCORE" != "0.00" ]]; then
    log "VMAF average: $VMAF_SCORE (min window: $VMAF_MIN_SCORE, mode=$VMAF_EFFECTIVE_MODE, n_subsample=$VMAF_EFFECTIVE_SUBSAMPLE, windows=$VMAF_WINDOW_COUNT)"
    
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
    
    # Track files with VMAF < 93 (use awk for decimal comparison)
    if awk -v score="$VMAF_SCORE" 'BEGIN { exit !(score < 93) }'; then
      LOW_VMAF_FILES+=("$FILE (VMAF: $VMAF_SCORE)")
    fi

    # Detect outputs with average VMAF < 70 or a partition window VMAF < 55.
    # The min-window floor is intentionally generous: a single ~4-8 min partition
    # dipping into the 60s is usually just hard content (dark/grain/heavy motion),
    # not a broken encode. Below 55 a whole partition is genuinely degraded.
    if awk -v avg="$VMAF_SCORE" -v min="$VMAF_MIN_SCORE" 'BEGIN { exit !((avg < 70) || (min < 55)) }'; then
      BAD_VMAF_FILES+=("$FILE (VMAF avg: $VMAF_SCORE, min: $VMAF_MIN_SCORE)")
      if $DELETE_ORIGINAL; then
        rm -fv -- "$OUT"
        log "Bad quality encode (VMAF avg < 70 or min window < 55). Deleted output and kept original."
        TOTAL_NEW_BYTES=$((TOTAL_NEW_BYTES - NEW_BYTES))
        log_scope_run
        continue
      else
        log "Bad quality encode (VMAF avg < 70 or min window < 55). Keeping output (no --delete* flag)."
      fi
    fi
  fi

  # If output is smaller and --delete flag is used, consider deleting original
  if $DELETE_ORIGINAL; then
    if $DELETE_ALWAYS; then
      # Delete always: just delete the original
      rm -fv -- "$FILE"
      log "Deleted original (output is smaller, --delete-always)."
    elif $DELETE_SAFE; then
      # Safe delete: only delete if VMAF >= 93
      if awk -v score="$VMAF_SCORE" 'BEGIN { exit !(score >= 93) }'; then
        rm -fv -- "$FILE"
        log "Deleted original (VMAF $VMAF_SCORE >= 93, safe to delete)."
      else
        log "Keeping both files (VMAF $VMAF_SCORE < 93 requires human comparison)."
      fi
    else
      # Standard delete: check VMAF >= 93 (use awk for decimal comparison)
      if awk -v score="$VMAF_SCORE" 'BEGIN { exit !(score >= 93) }'; then
        rm -fv -- "$FILE"
        log "Deleted original (output is smaller and VMAF >= 93)."
      else
        log "Keeping original (VMAF $VMAF_SCORE < 93). Deleting the converted file instead."
        rm -fv -- "$OUT"
        log "Use --delete-always to override VMAF requirement."
      fi
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
  log "=== Files with VMAF < 93 (may need quality review) ==="
  if $DELETE_ORIGINAL; then
    log "Note: Transcoded outputs were deleted due to -d flag."
  else
    log "Note: Transcoded outputs kept (default behavior without -d flag)."
  fi
  for file in "${LOW_VMAF_FILES[@]}"; do
    log "  $file"
  done
fi

if (( ${#BAD_VMAF_FILES[@]} > 0 )); then
  log "================================================================================"
  log "=== Bad quality encodes (VMAF avg < 70 or min window < 55) ==="
  if $DELETE_ORIGINAL; then
    log "Note: Outputs were deleted and originals kept."
  else
    log "Note: Outputs were kept for manual review (no --delete* flag)."
  fi
  for file in "${BAD_VMAF_FILES[@]}"; do
    log "  $file"
  done
fi

log "=== Finished ==="
