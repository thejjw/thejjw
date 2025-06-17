#!/bin/bash
# 2025.6 @thejjw — Parallel edition with GNU parallel power

set -e

DISTANCE=0
EFFORT=9
DELETE_ORIGINAL=0
INCLUDE_WEBP=0

while getopts "dw" opt; do
  case $opt in
    d) DELETE_ORIGINAL=1 ;;
    w) INCLUDE_WEBP=1 ;;
  esac
done
shift $((OPTIND -1))

# Check for requirements
command -v parallel >/dev/null || { echo "Error: GNU parallel is not installed."; exit 1; }
ffmpeg -buildconf 2>/dev/null | grep -q 'libjxl' || { echo "Error: ffmpeg missing libjxl support."; exit 1; }

LOG_FILE="./convert_jpegxl_parallel_$(date "+%Y%m%d_%H%M%S").log"
START_TIME=$(date +%s)

log_elapsed() {
  local msg="$1"
  local now=$(date +%s)
  local elapsed=$((now - START_TIME))
  printf "[+%ds] %s\n" "$elapsed" "$msg" | tee -a "$LOG_FILE"
}

log_elapsed "Script started."

# Build find filter
EXT="-iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png'"
[ "$INCLUDE_WEBP" -eq 1 ] && EXT="$EXT -o -iname '*.webp'"

# Find and normalize file list
mapfile -t files < <(find . -type f \( $EXT \))

log_elapsed "Found ${#files[@]} files. Launching parallel conversion..."

# Define the processing function
convert_jxl() {
  input="$1"
  output="${input%.*}.jxl"
  orig_size=$(stat -c%s "$input" 2>/dev/null || echo 0)
  ffmpeg -y -i "$input" -c:v libjxl -distance $DISTANCE -effort $EFFORT "$output" 2>>"$LOG_FILE"

  if [ $? -eq 0 ]; then
    new_size=$(stat -c%s "$output")
    if [ "$DELETE_ORIGINAL" -eq 1 ] && [ "$new_size" -lt "$orig_size" ]; then
      rm "$input"
      echo "[OK] $input → $output ($orig_size → $new_size bytes). Original deleted."
    else
      [ "$DELETE_ORIGINAL" -eq 1 ] && rm "$output" && echo "[SKIP] $output not smaller. Deleted." || echo "[OK] $input → $output ($orig_size → $new_size bytes)"
    fi
  else
    echo "[FAIL] $input" >&2
  fi
}

export -f convert_jxl
export DISTANCE EFFORT DELETE_ORIGINAL LOG_FILE START_TIME

# Run in parallel
parallel --halt now,fail=1 --bar --jobs 100% convert_jxl ::: "${files[@]}"

log_elapsed "All conversions completed."
