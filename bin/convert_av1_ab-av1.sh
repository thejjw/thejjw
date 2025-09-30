#!/bin/bash

# This script recursively encodes all(most?) video files in the current directory tree to AV1 format using ab-av1,
# logging progress with timestamps, and optionally deletes the original files with -d/--delete only if the AV1 output is smaller.
# 2025.6-2025.9 @thejjw

LOGFILE="convert_av1_ab-av1_$(date +%Y%m%d_%H%M%S).log"
SCRIPT_START_TIME=$(date +%s)
DELETE_ORIGINAL=0

# Parse optional --delete or -d argument
if [[ "$1" == "-d" || "$1" == "--delete" ]]; then
    DELETE_ORIGINAL=1
elif [[ $# -gt 0 ]]; then
    echo "Unknown argument: $1"
    echo "Usage: $0 [-d|--delete] (for auto-delete)"
    exit 1
fi

log() {
    now=$(date '+[%Y-%m-%d %H:%M:%S]')
    now_s=$(date +%s)
    elapsed=$((now_s - SCRIPT_START_TIME))
    elapsed_fmt=$(printf '[%02d:%02d:%02d]' $((elapsed/3600)) $(((elapsed%3600)/60)) $((elapsed%60)))
    echo "$now $elapsed_fmt $*" | tee -a "$LOGFILE"
}

# Find all files and save to an array, filtering out those already encoded
mapfile -t ALL_FILES < <(find . \( -iname "*.mp4" -o -iname "*.mkv" -o -iname "*.mov" -o -iname "*.mpg" -o -iname "*.avi" -o -iname "*.wmv" -o -iname "*.webm" -o -iname "*.ts" -o -iname "*.3gp" -o -iname "*.flv" \))

# Filter out files that are already AV1 encoded (end with .av1.{extension})
FILELIST=()
for filepath in "${ALL_FILES[@]}"; do
    base=$(basename "$filepath")
    
    # Skip files that end with .av1.{extension} pattern (like movie.av1.mp4)
    if [[ ! "$base" =~ \.av1\.[^.]+$ ]]; then
        FILELIST+=("$filepath")
    fi
done

TOTAL_FILES="${#FILELIST[@]}"
SKIPPED_FILES=$((${#ALL_FILES[@]} - TOTAL_FILES))
COUNT=0

log "[INFO] Found ${#ALL_FILES[@]} video files total."
if [ $SKIPPED_FILES -gt 0 ]; then
    log "[INFO] Skipping $SKIPPED_FILES files that are already AV1 encoded."
fi
log "[INFO] Processing $TOTAL_FILES video files."

for filepath in "${FILELIST[@]}"; do
    COUNT=$((COUNT + 1))
    file_start=$(date +%s)
    log "[INFO] ($COUNT/$TOTAL_FILES) Encoding: $filepath"
    if [ $DELETE_ORIGINAL -eq 1 ]; then
        log "[INFO] !!!WE WILL DELETE ORIGINAL FILE IF AV1 ENCODE SUCCEEDS!!!"
        log "[INFO] (or if av1 is not smaller or not produced, original file is left as is)"
    fi
    RUST_LOG=ab_av1=debug ab-av1 auto-encode -i "$filepath" 2>&1 | tee -a "$LOGFILE"
    file_end=$(date +%s)
    file_elapsed=$((file_end - file_start))
    file_elapsed_fmt=$(printf '%02d:%02d:%02d' $((file_elapsed/3600)) $(((file_elapsed%3600)/60)) $((file_elapsed%60)))

    # Compute base for expected output
    dir=$(dirname "$filepath")
    base=$(basename "$filepath")
    ext="${base##*.}"
    fname="${base%.*}"   # filename without extension

    # Escape brackets in fname for safe globbing
    safe_fname="${fname//\[/\\[}"
    safe_fname="${safe_fname//\]/\\]}"
    safe_fname="${safe_fname//\*/\\*}"
    safe_fname="${safe_fname//\?/\\?}"

    # Try the most likely output filename first
    av1_path="$dir/$fname.av1.$ext"
    if [ ! -f "$av1_path" ]; then
        # Wait up to 3 seconds for the file to appear
        for i in {1..10}; do
            av1_path=$(find "$dir" -maxdepth 1 -type f -name "$safe_fname.av1.*" | head -n 1)
            [ -n "$av1_path" ] && break
            sleep 0.3
        done
    fi

    orig_hr=$(du -h "$filepath" | cut -f1)
    av1_hr="N/A"
    if [ -n "$av1_path" ] && [ -f "$av1_path" ]; then
        av1_hr=$(du -h "$av1_path" | cut -f1)
        log "[INFO] Output found: $av1_path ($av1_hr)"
        if [ $DELETE_ORIGINAL -eq 1 ]; then
            orig_size=$(stat -c %s "$filepath")
            av1_size=$(stat -c %s "$av1_path")
            if [ "$av1_size" -lt "$orig_size" ]; then
                log "[INFO] Deleting original (smaller AV1): $filepath"
                rm -v "$filepath" | tee -a "$LOGFILE"
                log "[INFO] Final file: $av1_path ($orig_hr -> $av1_hr)"
            else
                log "[INFO] Deleting AV1 file (not smaller): $av1_path"
                rm -v "$av1_path" | tee -a "$LOGFILE"
                log "[INFO] Final file: $filepath ($orig_hr)"
            fi
        else
            log "[INFO] Final file: $av1_path ($orig_hr -> $av1_hr)"
        fi
    else
        log "[WARN] No AV1 output found for: $filepath"
        log "[INFO] Final file: $filepath ($orig_hr)"
    fi

    log "[INFO] ($COUNT/$TOTAL_FILES) Done: $filepath (Elapsed for file: $file_elapsed_fmt)"
    log "-----------------------------------"
done

log "[INFO] All encodes finished. Log saved to $LOGFILE"
