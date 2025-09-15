  #!/bin/bash
# 2025.9 @thejjw

# Set the distance parameter to 0 for lossless
DELETE_ORIGINAL=0
INCLUDE_WEBP=0

while getopts "dw" opt; do
  case $opt in
    d) DELETE_ORIGINAL=1 ;;
    w) INCLUDE_WEBP=1 ;;
  esac
done
shift $((OPTIND -1))

# Check for required tools
for tool in ffprobe cjxl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Error: '$tool' is not installed or not in PATH. Aborting."; exit 1; }
done

# Create a timestamped log file (YYYYMMDD_HHMMSS)
# Capture initial time in seconds since epoch
LOG_TIMESTAMP=$(date "+%Y%m%d_%H%M%S")
LOG_FILE="./convert_jpegxl_${LOG_TIMESTAMP}.log"
START_TIME=$(date +%s)
START_HUMAN=$(date "+%Y-%m-%d %H:%M:%S")
echo "Script started at: $START_HUMAN" | tee -a "$LOG_FILE"

# Function to echo with elapsed time (to both console and log file)
echo_elapsed() {
  local now elapsed
  now=$(date +%s)
  elapsed=$((now - START_TIME))
  printf "[+%ds] %s\n" "$elapsed" "$1" | tee -a "$LOG_FILE"
}

# Build find expression using an array
find_args=('-iname' '*.jpg' '-o' '-iname' '*.jpeg' '-o' '-iname' '*.png')
if [ "$INCLUDE_WEBP" -eq 1 ]; then
  find_args+=('-o' '-iname' '*.webp')
fi

mapfile -t files < <(find . -type f \( "${find_args[@]}" \))
total=${#files[@]}
echo_elapsed "Total files to process: $total"

count=0
for file in "${files[@]}"; do
  ((count++))
  ext="${file##*.}"
  ext_lc="${ext,,}"
  
  # Skip animated WebP
  if [[ "$ext_lc" == "webp" ]]; then
    frames=$(ffprobe -v error -select_streams v:0 -show_entries stream=nb_frames \
      -of default=noprint_wrappers=1:nokey=1 "$file" 2>/dev/null)
    if [[ "$frames" == "N/A" || "$frames" -gt 1 ]]; then
      echo_elapsed "[$count/$total] Skipping animated WebP: $file"
      continue
    fi
  fi

  output="${file%.*}.jxl"
  echo_elapsed "[$count/$total] Converting: $file -> $output"

  orig_size=$(stat -c%s "$file")

  # Use conditional transcoding based on file type
  if [[ "$ext_lc" == "jpg" || "$ext_lc" == "jpeg" ]]; then
    # Use lossless JPEG-to-JXL transcoding. This is extremely fast and reversible.
    cjxl --effort 9 "$file" "$output"
  else
    # Use standard lossless encoding for other formats like PNG or WebP.
    cjxl --effort 9 "$file" "$output" --lossless
  fi
  status=$?
  
  if [ $status -eq 0 ]; then
    new_size=$(stat -c%s "$output")
    size_diff=$((orig_size - new_size))
    percent=0
    [ "$orig_size" -gt 0 ] && percent=$((100 * size_diff / orig_size))

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

echo_elapsed "Script completed."
