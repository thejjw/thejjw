#!/bin/bash

# 2025.6 @thejjw

# Set the distance parameter to 0 for lossless
DISTANCE=0

# Find all .jpg and .jpeg files and count them
mapfile -t files < <(find . -type f \( -iname "*.jpg" -o -iname "*.jpeg" \))
total=${#files[@]}
echo "Total files to process: $total"

count=0
for file in "${files[@]}"; do
    ((count++))
    output="${file%.*}.jxl"
    echo "[$count/$total] Converting: $file -> $output"

    # Convert to JPEG XL using FFmpeg
    ffmpeg -y -i "$file" -c:v libjxl -distance $DISTANCE "$output"

    # Check if conversion was successful
    if [ $? -eq 0 ]; then
        echo "Success! Deleting original: $file"
        rm "$file"
    else
        echo "Conversion failed for: $file"
    fi
done
