#!/bin/bash

# 2025.6 @thejjw

# Set the distance parameter to 0 for lossless
DISTANCE=0

# Find and process all .jpg and .jpeg files
find . -type f \( -iname "*.jpg" -o -iname "*.jpeg" \) | while read -r file; do
    # Generate output filename by replacing .jpg or .jpeg with .jxl
    output="${file%.*}.jxl"
    
    echo "Converting: $file -> $output"

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
