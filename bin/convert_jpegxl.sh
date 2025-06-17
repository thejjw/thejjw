#!/bin/bash
# 2025.6 @thejjw

set -e

# Set the distance parameter to 0 for lossless
DISTANCE=0

DELETE_ORIGINAL=0
INCLUDE_WEBP=0
while getopts "dw" opt; do
  case $opt in
    d)
      DELETE_ORIGINAL=1
      ;;
    w)
      INCLUDE_WEBP=1
      ;;
  esac
done
shift $((OPTIND -1))

# Check if ffmpeg is compiled with libjxl support
if ! ffmpeg -buildconf 2>/dev/null | grep -qE 'libjxl'; then
  echo "Error: ffmpeg is not compiled with libjxl support. Aborting."
  exit 1
fi

# Create a timestamped log file (YYYYMMDD_HHMMSS)
LOG_TIMESTAMP=$(date "+%Y%m%d_%H%M%S")
LOG_FILE="./convert_jpegxl_${LOG_TIMESTAMP}.log"

# Capture initial time in seconds since epoch
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

# Find files
if [ "$INCLUDE_WEBP" -eq 1 ]; then
    mapfile -t files < <(find . -type f \( -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.png" -o -iname "*.gif" -o -iname "*.webp" \))
else
    mapfile -t files < <(find . -type f \( -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.png" -o -iname "*.gif" \))
fi
total=${#files[@]}
echo_elapsed "Total files to process: $total"

count=0
for file in "${files[@]}"; do
    ((count++))
    output="${file%.*}.jxl"
    echo_elapsed "[$count/$total] Converting: $file -> $output"

    orig_size=$(stat -c%s "$file")
    ffmpeg -y -i "$file" -c:v libjxl -distance $DISTANCE -effort 9 "$output"
    status=$?

    # Check if conversion was successful
    if [ $status -eq 0 ]; then
        new_size=$(stat -c%s "$output")
        size_diff=$((orig_size - new_size))
        percent=0
        if [ "$orig_size" -gt 0 ]; then
            percent=$((100 * size_diff / orig_size))
        fi
        logmsg="Success! $file: $orig_size bytes -> $new_size bytes (${percent}% change)."
        echo_elapsed "$logmsg"

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
