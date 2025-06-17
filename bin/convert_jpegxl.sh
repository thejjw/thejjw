#!/bin/bash

# 2025.6 @thejjw

# Set the distance parameter to 0 for lossless
DISTANCE=0

# Capture initial time in seconds since epoch
START_TIME=$(date +%s)
START_HUMAN=$(date "+%Y-%m-%d %H:%M:%S")
echo "Script started at: $START_HUMAN"

# Function to echo with elapsed time
echo_elapsed() {
    local now elapsed
    now=$(date +%s)
    elapsed=$((now - START_TIME))
    printf "[+%ds] %s\n" "$elapsed" "$1"
}

# Find all .jpg and .jpeg files and count them
mapfile -t files < <(find . -type f \( -iname "*.jpg" -o -iname "*.jpeg" \))
total=${#files[@]}
echo_elapsed "Total files to process: $total"

count=0
for file in "${files[@]}"; do
    ((count++))
    output="${file%.*}.jxl"
    echo_elapsed "[$count/$total] Converting: $file -> $output"

    # Convert to JPEG XL using FFmpeg
    ffmpeg -y -i "$file" -c:v libjxl -distance $DISTANCE "$output"

    # Check if conversion was successful
    if [ $? -eq 0 ]; then
        echo_elapsed "Success! Deleting original: $file"
        rm "$file"
    else
        echo_elapsed "Conversion failed for: $file"
    fi
done
