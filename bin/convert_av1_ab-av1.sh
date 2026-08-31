#!/bin/bash

# This script recursively encodes all(most?) video files in the current directory tree to AV1 format using ab-av1,
# logging progress with timestamps, and optionally deletes the original files with -d/--delete only if the AV1 output is smaller.
# 2025.6-2025.9 @thejjw

LOGFILE="convert_av1_ab-av1_$(date +%Y%m%d_%H%M%S).log"
SCRIPT_START_TIME=$(date +%s)
DELETE_ORIGINAL=0

# Array of file extensions to search for
# Add or remove extensions from this list as needed
EXTENSIONS=( "mp4" "m4v" "mkv" "mov" "mpg" "mpeg" "avi" "wmv" "webm" "ts" "3gp" "flv" "m2ts" "mts" "f4v" "rmvb" "rm" "ogv" "divx" "xvid" )

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

# Prepare the arguments for the find command
FIND_ARGS=()
for EXT in "${EXTENSIONS[@]}"; do
    FIND_ARGS+=( -o -iname "*.${EXT}" )
done

# Remove the initial "-o" from the arguments
unset FIND_ARGS[0]

# Find all files with the specified extensions and save to an array, filtering out those already encoded
mapfile -t ALL_FILES < <(find . \( "${FIND_ARGS[@]}" \))

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
    RUST_LOG=ab_av1=debug ab-av1 auto-encode -i "$filepath" --fail-fast --verify 2>&1 | tee -a "$LOGFILE"
    enc_rc=${PIPESTATUS[0]}

    # If encoding failed (e.g. malformed container / header error), attempt MKV remux and retry
    if [ $enc_rc -ne 0 ]; then
        log "[WARN] Encode failed for $filepath (exit code $enc_rc). Input container may be malformed."
        log "[INFO] Attempting MKV remux repair..."

        dir=$(dirname "$filepath")
        base=$(basename "$filepath")
        fname="${base%.*}"

        # Escape brackets/wildcards for safe matching
        safe_fname="${fname//\[/\\[}"
        safe_fname="${safe_fname//\]/\\]}"
        safe_fname="${safe_fname//\*/\\*}"
        safe_fname="${safe_fname//\?/\\?}"

        # Find, log, and delete any partial/stale AV1 output left from the failed run
        while IFS= read -r stale_file; do
            if [ -n "$stale_file" ]; then
                log "[INFO] Cleaned up stale partial encode output: $stale_file"
                rm -f "$stale_file"
            fi
        done < <(find "$dir" -maxdepth 1 -type f -name "$safe_fname.av1.*" 2>/dev/null)

        remux_target="$dir/$fname.mkv"
        remux_temp="$dir/.${fname}.remux.mkv"

        ffmpeg -hide_banner -loglevel warning -y \
            -i "$filepath" \
            -map 0:v:0 -map 0:a? -map 0:s? \
            -map_metadata 0 -map_chapters 0 \
            -c:v copy -c:a copy -c:s copy \
            "$remux_temp" 2>&1 | tee -a "$LOGFILE"
        remux_rc=${PIPESTATUS[0]}

        if [ $remux_rc -eq 0 ] && [ -s "$remux_temp" ]; then
            log "[INFO] Remux successful. Deleting original malformed file: $filepath"
            rm -f "$filepath"
            mv "$remux_temp" "$remux_target"
            log "[INFO] Replaced original with clean remux: $remux_target"
            filepath="$remux_target"

            log "[INFO] Retrying encode on remuxed file: $filepath"
            RUST_LOG=ab_av1=debug ab-av1 auto-encode -i "$filepath" --fail-fast --verify 2>&1 | tee -a "$LOGFILE"
        else
            log "[ERROR] Remux repair failed (exit code $remux_rc). Giving up on this file."
            if [ -e "$remux_temp" ]; then
                log "[INFO] Cleaned up failed remux artifact: $remux_temp"
                rm -f "$remux_temp"
            fi
        fi
    fi
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
