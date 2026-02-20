  #!/bin/bash
# 2025.9-2026.2 @thejjw

# Set the distance parameter to 0 for lossless (JPEG), non-JPEG uses -d 1.0 by default
DELETE_ORIGINAL=0
INCLUDE_WEBP=0
VERBOSE_WEBP=0

usage() {
  cat <<HELP
Usage: $(basename "$0") [OPTIONS]

Options:
  -d        Delete original files when output .jxl is smaller
  -w        Include .webp files in the search (skips animated webp)
  --verbose-webp  Print webpinfo details when a WebP is skipped
  -h, --help  Show this help and exit

Description:
  Converts images in the current directory and subdirectories to JPEG XL (.jxl).
  JPEGs are transcoded losslessly; other formats use cjxl -e 9 -d 1.0 by default.
  WebP animation detection uses webpinfo (animated WebPs are skipped).
HELP
}

normalized_args=()
for arg in "$@"; do
  case "$arg" in
    --help) normalized_args+=("-h") ;;
    --verbose-webp) VERBOSE_WEBP=1 ;;
    *) normalized_args+=("$arg") ;;
  esac
done
set -- "${normalized_args[@]}"

while getopts "hdw" opt; do
  case $opt in
    h) usage; exit 0 ;;
    d) DELETE_ORIGINAL=1 ;;
    w) INCLUDE_WEBP=1 ;;
  esac
done
shift $((OPTIND -1))

# Check for required tools
for tool in webpinfo cjxl bc; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Error: '$tool' is not installed or not in PATH. Aborting."; echo "Tip: libjxl-tools provides cjxl (ubuntu)"; exit 1; }
done

# Create a timestamped log file (YYYYMMDD_HHMMSS)
# Capture initial time in seconds since epoch
LOG_TIMESTAMP=$(date "+%Y%m%d_%H%M%S")
LOG_FILE="./convert_jpegxl_${LOG_TIMESTAMP}.log"
START_TIME=$(date +%s)
START_HUMAN=$(date "+%Y-%m-%d %H:%M:%S")
echo "Script started at: $START_HUMAN" | tee -a "$LOG_FILE"

# Function to echo with timestamp and elapsed time (to both console and log file)
echo_elapsed() {
  local now now_s elapsed elapsed_fmt
  now=$(date '+[%Y-%m-%d %H:%M:%S]')
  now_s=$(date +%s)
  elapsed=$((now_s - START_TIME))
  elapsed_fmt=$(printf '[%02d:%02d:%02d]' $((elapsed/3600)) $(((elapsed%3600)/60)) $((elapsed%60)))
  echo "$now $elapsed_fmt $1" | tee -a "$LOG_FILE"
}

# Build find expression using an array
find_args=('-iname' '*.jpg' '-o' '-iname' '*.jpeg' '-o' '-iname' '*.png')
if [ "$INCLUDE_WEBP" -eq 1 ]; then
  find_args+=('-o' '-iname' '*.webp')
fi

mapfile -t files < <(find . -type f \( "${find_args[@]}" \))
total=${#files[@]}
echo_elapsed "Total files to process: $total"

total_orig_size=0
total_jxl_size=0
successful_conversions=0

count=0
for file in "${files[@]}"; do
  ((count++))
  ext="${file##*.}"
  ext_lc="${ext,,}"
  
  # Skip animated WebP
  if [[ "$ext_lc" == "webp" ]]; then
    webpinfo_out=$(webpinfo "$file" 2>&1)
    if [[ $? -ne 0 ]]; then
      echo_elapsed "[$count/$total] Skipping invalid/unreadable WebP: $file"
      if [[ "$VERBOSE_WEBP" -eq 1 && -n "$webpinfo_out" ]]; then
        echo_elapsed "[$count/$total] webpinfo details for skipped file: $file"
        while IFS= read -r line; do
          echo_elapsed "[webpinfo] $line"
        done <<< "$webpinfo_out"
      fi
      continue
    fi

    if grep -qE '^  Animation: 1$' <<< "$webpinfo_out"; then
      echo_elapsed "[$count/$total] Skipping animated WebP: $file"
      if [[ "$VERBOSE_WEBP" -eq 1 ]]; then
        echo_elapsed "[$count/$total] webpinfo details for skipped file: $file"
        while IFS= read -r line; do
          echo_elapsed "[webpinfo] $line"
        done <<< "$webpinfo_out"
      fi
      continue
    fi
  fi

  output="${file%.*}.jxl"
  echo_elapsed "[$count/$total] Converting: $file -> $output"

  orig_size=$(stat -c%s "$file")

  # Use conditional transcoding based on file type
  if [[ "$ext_lc" == "jpg" || "$ext_lc" == "jpeg" ]]; then
    # Use lossless JPEG-to-JXL transcoding. This is extremely fast and reversible.
    cjxl --effort 9 "$file" "$output" --lossless_jpeg=1
  else
    # Use standard encoding for other formats like PNG or WebP; set -d 1.0 by default
    cjxl --effort 9 --distance 1.0 "$file" "$output"
  fi
  status=$?
  
  if [ $status -eq 0 ]; then
    new_size=$(stat -c%s "$output")
    size_diff=$((orig_size - new_size))
    percent=0
    [ "$orig_size" -gt 0 ] && percent=$((100 * size_diff / orig_size))

    total_orig_size=$((total_orig_size + orig_size))
    total_jxl_size=$((total_jxl_size + new_size))
    successful_conversions=$((successful_conversions + 1))

    echo_elapsed "Success! $file: $orig_size bytes -> $new_size bytes (${percent}% change)."

    if [ "$DELETE_ORIGINAL" -eq 1 ]; then
      if [ "$new_size" -lt "$orig_size" ]; then
        echo_elapsed "Deleting original: $file"
        rm "$file"
      else
        echo_elapsed "Not deleting original, .jxl is not smaller. Deleting .jxl file."
        rm "$output"
      fi
    else
      echo_elapsed "Original not deleted. Use -d to enable deletion."
    fi
  else
    echo_elapsed "Conversion failed for: $file"
  fi
done

saved=$((total_orig_size - total_jxl_size))
reduction_percent=0
if [ "$total_orig_size" -gt 0 ]; then reduction_percent=$((100 * saved / total_orig_size)); fi

orig_mb=$(echo "scale=1; $total_orig_size / 1048576" | bc)
jxl_mb=$(echo "scale=1; $total_jxl_size / 1048576" | bc)
saved_mb=$(echo "scale=1; $saved / 1048576" | bc)

echo_elapsed "Summary: $successful_conversions files converted. Total original: ${orig_mb} MB, Total JXL: ${jxl_mb} MB, Saved: ${saved_mb} MB (${reduction_percent}% reduction)."

echo_elapsed "Script completed."
