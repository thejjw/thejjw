#!/bin/bash
# 2025.8 @thejjw
# --- Script to intelligently convert WebP files ---
# Uses Google's webpmux for detection/extraction and FFmpeg for conversion.

# --- Configuration ---
REQUIRED_FFMPEG_VERSION_AV1="5.0"
LOG_DIR="."
DEFAULT_FRAMERATE="30"

# Function to display usage instructions
usage() {
    echo "Usage: $0 <directory> [options]"
    echo "  <directory>     : The directory to scan for .webp files."
    echo
    echo "Options:"
    echo "  -r, --recursive : Process subdirectories recursively."
    echo "  -d, --delete    : Delete original .webp file on successful conversion."
    echo "      --av1       : Convert animated WebP to MP4 using AV1 (outputs .av1.mp4)."
    echo "      --both      : Convert animated WebP to BOTH H.264 (.mp4) and AV1 (.av1.mp4)."
    exit 1
}

# --- Argument Parsing ---
if [ "$#" -lt 1 ] || [[ "$1" == -* ]]; then
    usage
fi

TARGET_DIR="$1"
shift

RECURSIVE=false
DELETE_ORIGINAL=false
USE_AV1=false
USE_BOTH=false

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -r|--recursive) RECURSIVE=true ;;
        -d|--delete) DELETE_ORIGINAL=true ;;
        --av1) USE_AV1=true ;;
        --both) USE_BOTH=true ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
    shift
done

# --- Pre-flight Checks ---
if [ ! -d "$TARGET_DIR" ]; then
    echo "Error: Directory '$TARGET_DIR' not found."
    exit 1
fi

if ! command -v ffmpeg &> /dev/null || ! command -v webpmux &> /dev/null; then
    echo "Error: Required command not found. Please ensure ffmpeg and webp (or libwebp-tools) are installed."
    exit 1
fi

if [ "$USE_AV1" = true ] || [ "$USE_BOTH" = true ]; then
    INSTALLED_FFMPEG_VERSION=$(ffmpeg -version 2>/dev/null | head -n 1 | grep -oP 'ffmpeg version \K[0-9.]+')
    if [[ "$(printf '%s\n' "$REQUIRED_FFMPEG_VERSION_AV1" "$INSTALLED_FFMPEG_VERSION" | sort -V | head -n 1)" != "$REQUIRED_FFMPEG_VERSION_AV1" ]]; then
        echo "Warning: Your FFmpeg version is $INSTALLED_FFMPEG_VERSION. Version $REQUIRED_FFMPEG_VERSION_AV1+ is recommended for reliable AV1 encoding."
    fi
fi

# --- Helper function for logging success details ---
log_success_details() {
    local output_file="$1"
    local original_size="$2"
    
    NEW_SIZE=$(stat -c%s "$output_file")
    SIZE_CHANGE_PERCENT=$(awk "BEGIN { printf \"%.2f\", (($NEW_SIZE - $original_size) / $original_size) * 100 }")
    
    echo "   [SUCCESS] Converted to: $output_file"
    echo "   - Timestamp: $(date +'%Y-%m-%d %H:%M:%S')"
    echo "   - Original Size: $original_size bytes"
    echo "   - New Size:      $NEW_SIZE bytes"
    echo "   - Size Change:   $SIZE_CHANGE_PERCENT%"
}


# --- Logging and Main Execution Block ---
TIMESTAMP=$(date +'%Y-%m-%d_%H-%M-%S')
LOG_FILE="${LOG_DIR}/convert_webp_${TIMESTAMP}.log"
START_TIME=$(date +%s)

{
    echo "--- WebP Conversion Script Started at $(date) ---"
    echo "Target Directory: ${TARGET_DIR}"
    echo "Recursive Mode: ${RECURSIVE}"
    echo "Delete Original on Success: ${DELETE_ORIGINAL}"
    
    if [ "$USE_BOTH" = true ]; then
        echo "Conversion Mode: Dual (H.264 & AV1)"
    elif [ "$USE_AV1" = true ]; then
        echo "Video Codec: AV1 (libsvtav1)"
    else
        echo "Video Codec: H.264 (libx264) - Default"
    fi
    echo "----------------------------------------------------"

    FIND_ARGS=("$TARGET_DIR")
    [ "$RECURSIVE" = false ] && FIND_ARGS+=("-maxdepth" "1")
    readarray -d '' files < <(find "${FIND_ARGS[@]}" -type f -iname "*.webp" -print0)
    TOTAL_FILES=${#files[@]}

    if [ "$TOTAL_FILES" -eq 0 ]; then
        echo "No .webp files found to process. Exiting."
        exit 0
    fi
    
    echo "Found $TOTAL_FILES .webp file(s) to process."
    echo "----------------------------------------------------"
    
    PROCESSED_COUNT=0
    CONVERTED_COUNT=0

    for webp_file in "${files[@]}"; do
        PROCESSED_COUNT=$((PROCESSED_COUNT + 1))
        echo -e "\n($PROCESSED_COUNT/$TOTAL_FILES) Processing: $webp_file"
        
        ORIGINAL_SIZE=$(stat -c%s "$webp_file")
        WEBP_INFO=$(webpmux -info "$webp_file" 2>&1)
        
        if [ $? -ne 0 ]; then
             echo "   [FAILED] Could not get info using webpmux. Tool output:"
             echo "   > ${WEBP_INFO}"
             continue
        fi

        FRAME_COUNT=$(echo "$WEBP_INFO" | grep "Number of frames:" | awk '{print $4}')
        [[ -z "$FRAME_COUNT" ]] && FRAME_COUNT=1

        CONVERSION_SUCCESS=false
        
        # --- Animated WebP Conversion ---
        if [[ "$FRAME_COUNT" -gt 1 ]]; then
            TEMP_DIR=$(mktemp -d)
            if [ ! -d "$TEMP_DIR" ]; then
                echo "   [FAILED] Could not create temporary directory."
                continue
            fi
            
            # Step 1: Extract frames using webpmux
            echo "   - Step 1: Extracting $FRAME_COUNT frames with webpmux..."
            extraction_failed=false
            for i in $(seq 1 $FRAME_COUNT); do
                webpmux -get frame "$i" "$webp_file" -o "${TEMP_DIR}/frame_$(printf "%04d" $i).webp" >/dev/null 2>&1
                if [ $? -ne 0 ]; then
                    echo "   [FAILED] Failed to extract frame $i."
                    extraction_failed=true; break
                fi
            done
            
            # Step 2: Reassemble if extraction was successful
            if [ "$extraction_failed" = false ]; then
                echo "   - Step 2: Reassembling frames into video(s)..."
                # --both takes precedence
                if [ "$USE_BOTH" = true ]; then
                    h264_output_file="${webp_file%.*}.mp4"
                    av1_output_file="${webp_file%.*}.av1.mp4"
                    
                    ffmpeg -y -framerate $DEFAULT_FRAMERATE -i "${TEMP_DIR}/frame_%04d.webp" -c:v libx264 -crf 23 -preset medium -pix_fmt yuv420p -vf "pad=ceil(iw/2)*2:ceil(ih/2)*2" "$h264_output_file" >/dev/null 2>&1
                    h264_success=$?
                    
                    ffmpeg -y -framerate $DEFAULT_FRAMERATE -i "${TEMP_DIR}/frame_%04d.webp" -c:v libsvtav1 -crf 30 -preset 6 -g 240 -pix_fmt yuv420p10le -vf "pad=ceil(iw/2)*2:ceil(ih/2)*2" "$av1_output_file" >/dev/null 2>&1
                    av1_success=$?
                    
                    [ $h264_success -eq 0 ] && log_success_details "$h264_output_file" "$ORIGINAL_SIZE" || echo "   [FAILED] H.264 conversion failed."
                    [ $av1_success -eq 0 ] && log_success_details "$av1_output_file" "$ORIGINAL_SIZE" || echo "   [FAILED] AV1 conversion failed."
                    
                    if [ $h264_success -eq 0 ] && [ $av1_success -eq 0 ]; then
                        CONVERSION_SUCCESS=true; CONVERTED_COUNT=$((CONVERTED_COUNT + 1))
                    fi
                else # Single conversion logic
                    output_file=$([ "$USE_AV1" = true ] && echo "${webp_file%.*}.av1.mp4" || echo "${webp_file%.*}.mp4")
                    
                    if [ "$USE_AV1" = true ]; then
                         ffmpeg -y -framerate $DEFAULT_FRAMERATE -i "${TEMP_DIR}/frame_%04d.webp" -c:v libsvtav1 -crf 30 -preset 6 -g 240 -pix_fmt yuv420p10le -vf "pad=ceil(iw/2)*2:ceil(ih/2)*2" "$output_file" >/dev/null 2>&1
                    else
                         ffmpeg -y -framerate $DEFAULT_FRAMERATE -i "${TEMP_DIR}/frame_%04d.webp" -c:v libx264 -crf 23 -preset medium -pix_fmt yuv420p -vf "pad=ceil(iw/2)*2:ceil(ih/2)*2" "$output_file" >/dev/null 2>&1
                    fi
                    
                    if [ $? -eq 0 ]; then
                        log_success_details "$output_file" "$ORIGINAL_SIZE"
                        CONVERSION_SUCCESS=true; CONVERTED_COUNT=$((CONVERTED_COUNT + 1))
                    fi
                fi
            fi
            rm -rf "$TEMP_DIR" # Cleanup

        # --- Static WebP: Direct Conversion ---
        else
            output_file="${webp_file%.*}.png"
            echo "-> Static WebP detected. Converting to PNG..."
            ffmpeg -y -i "$webp_file" "$output_file" >/dev/null 2>&1
            if [ $? -eq 0 ]; then
                log_success_details "$output_file" "$ORIGINAL_SIZE"
                CONVERSION_SUCCESS=true; CONVERTED_COUNT=$((CONVERTED_COUNT + 1))
            fi
        fi

        # --- Post-Conversion Deletion ---
        if [ "$CONVERSION_SUCCESS" = true ]; then
            [ "$DELETE_ORIGINAL" = true ] && rm "$webp_file" && echo "   - Original file deleted."
        else
            echo "   [FAILED] Conversion process failed for: $webp_file"
        fi
    done

    END_TIME=$(date +%s)
    TOTAL_DURATION=$((END_TIME - START_TIME))
    
    echo "----------------------------------------------------"
    echo "Batch processing complete."
    echo "Total time taken: ${TOTAL_DURATION} seconds."
    echo "Successfully converted: ${CONVERTED_COUNT} of ${PROCESSED_COUNT} identified files."
    echo "--- Log file saved to: ${LOG_FILE} ---"

} | tee "$LOG_FILE"
