#!/usr/bin/env bash
#
# install_fonts_mac.sh
# macOS user-scoped counterpart to Windows Install-Fonts.
# Downloads and installs a curated catalog of fonts into ~/Library/Fonts.
#
# 2026 @thejjw
#

# Stop on unhandled error or unset variables
set -u

# Default target directory is user font domain ~/Library/Fonts
# Can be overridden via INSTALL_FONTS_TARGET_DIR for isolated testing
TARGET_DIR="${INSTALL_FONTS_TARGET_DIR:-$HOME/Library/Fonts}"

# CLI options defaults
NAME_FILTER=""
EXTENDED=0
FORCE=0
RETRIES=2
LIST_ONLY=0
YES=0

# Catalog parallel arrays (1:1 with $_FontInstallInternal.Packs in Microsoft.PowerShell_profile.ps1)
PACK_NAME=()
PACK_URL=()
PACK_BYTES=()
PACK_FONTS=()
PACK_KIND=()
PACK_INCLUDE=()
PACK_PROBE=()
PACK_EXTENDED=()
PACK_NOTE=()

# Registers a single font pack into the catalog
add_pack() {
  PACK_NAME+=("$1")
  PACK_URL+=("$2")
  PACK_BYTES+=("$3")
  PACK_FONTS+=("$4")
  PACK_KIND+=("$5")
  PACK_INCLUDE+=("$6")
  PACK_PROBE+=("$7")
  PACK_EXTENDED+=("$8")
  PACK_NOTE+=("$9")
}

# Populate the 33 curated packs exactly as defined in $_FontInstallInternal.Packs
add_pack "IntelOneMono" "https://github.com/intel/intel-one-mono/releases/download/V1.4.0/ttf.zip" 505443 8 "Zip" '(?i)^ttf/[^/]+\.ttf$' "IntelOneMono-Regular.ttf" 0 'Screen-optimized TTF, 4 weights with matching italics; family "Intel One Mono".'
add_pack "GoormSansCode" "https://statics.goorm.io/fonts/GoormSansCode/v1.0.1/goorm-sans-code-1.0.1.zip" 4528715 1 "Zip" '(?i)^goorm sans code 2/Public/[^/]+\.ttf$' "goorm_Sans_Code_400.ttf" 0 'Coding sans (single weight).'
add_pack "Jetendard" "https://github.com/kuskhan/jetendard/releases/download/v0.1.0/Jetendard-TTF.zip" 37427141 16 "Zip" '(?i)^ttf/[^/]+\.ttf$' "Jetendard-Regular.ttf" 0 'Static TTF weights.'
add_pack "YeomilMono" "https://github.com/taevel02/yeomil-mono/releases/download/v1.1.1/YeomilMono-TTF.zip" 3055540 3 "Zip" '(?i)^[^/]+\.ttf$' "YeomilMono-Regular.ttf" 0 'Monospace, 3 weights.'
add_pack "Pretendard" "https://github.com/orioncactus/pretendard/releases/download/v1.3.9/Pretendard-1.3.9.zip" 47304526 9 "Zip" '(?i)^public/static/alternative/[^/]+\.ttf$' "Pretendard-Regular.ttf" 0 'Static TTF: its variable build registers as family "Pretendard Variable", so static is used for a clean "Pretendard" family.'
add_pack "WantedSans" "https://github.com/wanteddev/wanted-sans/releases/download/v1.0.3/WantedSans-1.0.3.zip" 21656532 7 "Zip" '(?i)^ttf/[^/]+\.ttf$' "WantedSans-Regular.ttf" 0 'Static TTF: variable build registers as "Wanted Sans Variable"; static keeps a clean "Wanted Sans" family.'
add_pack "Galmuri" "https://github.com/quiple/galmuri/releases/download/v2.40.3/Galmuri-v2.40.3.zip" 19936233 20 "Zip" '(?i)^[^/]+\.(ttf|ttc)$' "Galmuri11.ttf" 0 'Pixel font family; all root-level ttf/ttc.'
add_pack "OpenDyslexic" "https://github.com/antijingoist/opendyslexic/releases/download/v0.91.12/opendyslexic-0.910.12-rc2-2019.10.17.zip" 3627458 4 "Zip" '(?i)^[^/]+\.otf$' "OpenDyslexic-Regular.otf" 0 'OTF; skips eot/woff web formats.'
add_pack "FiraCode" "https://github.com/tonsky/FiraCode/releases/download/6.2/Fira_Code_v6.2.zip" 2462987 6 "Zip" '(?i)^ttf/[^/]+\.ttf$' "FiraCode-Regular.ttf" 0 'Static TTF: the VF defaults to Light weight and legacy apps see "Fira Code Light"; static defaults to Regular with a clean "Fira Code" family.'
add_pack "SarasaGothicK" "https://github.com/be5invis/Sarasa-Gothic/releases/download/v1.0.40/SarasaGothicK-TTF-1.0.40.7z" 63464316 10 "7z" '(?i)^SarasaGothicK-[^/]+\.ttf$' "SarasaGothicK-Regular.ttf" 0 'Korean Sarasa Gothic, 5 hinted weights with italics. Requires 7z command.'
add_pack "SarasaMonoK" "https://github.com/be5invis/Sarasa-Gothic/releases/download/v1.0.40/SarasaMonoK-TTF-1.0.40.7z" 66316218 10 "7z" '(?i)^SarasaMonoK-[^/]+\.ttf$' "SarasaMonoK-Regular.ttf" 0 'Korean monospaced Sarasa, 5 hinted weights with italics. Requires 7z command.'
add_pack "SourceHanSans" "https://github.com/adobe-fonts/source-han-sans/releases/download/2.005R/02_SourceHanSans-VF.zip" 888816761 1 "Zip" '(?i)^Variable/OTC/SourceHanSans-VF\.ttf\.ttc$' "SourceHanSans-VF.ttf.ttc" 1 'LARGE ~848 MB. Installs only the pan-CJK OTC variable collection.'
add_pack "SourceHanSerif" "https://github.com/adobe-fonts/source-han-serif/releases/download/2.003R/02_SourceHanSerif-VF.zip" 750817685 1 "Zip" '(?i)^Variable/OTC/SourceHanSerif-VF\.ttf\.ttc$' "SourceHanSerif-VF.ttf.ttc" 1 'LARGE ~716 MB. Installs only the pan-CJK OTC variable collection.'
add_pack "SourceHanMono" "https://github.com/adobe-fonts/source-han-mono/releases/download/1.002/SourceHanMono.ttc" 122117628 1 "File" "" "SourceHanMono.ttc" 1 'LARGE ~116 MB. Direct .ttc download (no archive).'
add_pack "JetBrainsMono" "https://github.com/JetBrains/JetBrainsMono/releases/download/v2.304/JetBrainsMono-2.304.zip" 5622857 2 "Zip" '(?i)^fonts/variable/[^/]+\.ttf$' "JetBrainsMono[wght].ttf" 0 'Variable TTF (upright + italic); registers cleanly as "JetBrains Mono", so variable is kept over the static ttf/ set.'
add_pack "IBMPlexMono" "https://github.com/IBM/plex/releases/download/%40ibm%2Fplex-mono%402.5.0/ibm-plex-mono.zip" 6940652 16 "Zip" '(?i)^ibm-plex-mono/fonts/complete/otf/[^/]+\.otf$' "IBMPlexMono-Regular.otf" 0 'OTF, all 16 weights incl. italics; skips ttf/woff/woff2.'
add_pack "IBMPlexSansKR" "https://github.com/IBM/plex/releases/download/%40ibm%2Fplex-sans-kr%401.1.0/ibm-plex-sans-kr.zip" 73268731 8 "Zip" '(?i)^ibm-plex-sans-kr/fonts/complete/otf/[^/]+\.otf$' "IBMPlexSansKR-Regular.otf" 0 'LARGE ~73 MB (full zip also bundles ttf/woff/woff2); installs OTF, all 8 Korean weights.'
add_pack "MonaSans" "https://github.com/github/mona-sans/releases/download/v2.0.27/mona-sans-variable-v2.0.27.zip" 2674251 11 "Zip" '(?i)^fonts/variable/[^/]+\.ttf$' "MonaSansVF[opsz,wght].ttf" 0 'Variable-only distribution (multiple width/optical axes).'
add_pack "SUIT" "https://github.com/sun-typeface/SUIT/releases/download/v2.0.5/SUIT-Variable-ttf.zip" 812043 1 "Zip" '(?i)^[^/]+\.ttf$' "SUIT-Variable.ttf" 0 'Single variable TTF.'
add_pack "MonoplexKR" "https://github.com/y-kim/monoplex/releases/download/v0.0.2/MonoplexKR-v0.0.2.zip" 74226250 64 "Zip" '(?i)^[^/]+/[^/]+\.ttf$' "MonoplexKR-Regular.ttf" 0 'LARGE ~74 MB. Four families (base/Nerd/Wide/WideNerd), 16 weights each.'
add_pack "MinSans" "https://github.com/poposnail61/min-sans/releases/download/v1.4.2/fonts.zip" 31533194 10 "Zip" '(?i)^fonts/static/[^/]+\.otf$' "MinSans-Regular.otf" 0 'Static OTF: variable build registers as "Min Sans VF"; static keeps a clean "Min Sans" family. Skips __MACOSX.'
add_pack "Dalmoori" "https://github.com/RanolP/dalmoori-font/releases/download/v0.200/dalmoori-font.zip" 775035 1 "Zip" '(?i)^[^/]+\.ttf$' "dalmoori.ttf" 0 'Single pixel TTF.'
add_pack "NanumGothicCoding" "https://github.com/naver/nanumfont/releases/download/VER2.5/NanumGothicCoding-2.5.zip" 1707449 2 "Zip" '(?i)^[^/]+\.ttf$' "NanumGothicCoding.ttf" 0 'Regular + Bold; skips __MACOSX.'
add_pack "NanumGothic" "https://hangeul.naver.com/hangeul_static/webfont/zips/nanum-gothic.zip" 12905726 4 "Zip" '(?i)^[^/]+\.ttf$' "NanumGothic.ttf" 0 'TTF, 4 weights (Light/Regular/Bold/ExtraBold). TTF is used because the bundled OTF renames the family to "NanumGothicOTF".'
add_pack "NanumMyeongjo" "https://hangeul.naver.com/hangeul_static/webfont/zips/nanum-myeongjo.zip" 7353677 3 "Zip" '(?i)^[^/]+\.ttf$' "NanumMyeongjo.ttf" 0 'TTF, 3 weights (Regular/Bold/ExtraBold). TTF keeps a clean "NanumMyeongjo" family (OTF is "NanumMyeongjoOTF").'
add_pack "NanumBarunGothic" "https://hangeul.naver.com/hangeul_static/webfont/zips/nanum-barun-gothic.zip" 15416063 4 "Zip" '(?i)^[^/]+\.ttf$' "NanumBarunGothic.ttf" 0 'TTF, 4 weights (UltraLight/Light/Regular/Bold). TTF keeps a clean "NanumBarunGothic" family (OTF is "NanumBarunGothicOTF").'
add_pack "NanumSquare" "https://hangeul.naver.com/hangeul_static/webfont/zips/nanum-square.zip" 4203717 8 "Zip" '(?i)^[^/]+\.ttf$' "NanumSquareR.ttf" 0 'TTF, 8 files: "NanumSquare" + "NanumSquare_ac" (alphabet-matched) sub-families, 4 weights each. TTF keeps clean names (OTF appends "OTF").'
add_pack "NanumSquareNeo" "https://hangeul.naver.com/hangeul_static/webfont/zips/nanum-square-neo.zip" 9765932 5 "Zip" '(?i)^nanum-square-neo/TTF/[^/]+\.ttf$' "NanumSquareNeo-bRg.ttf" 0 'Static TTF, 5 weights (Light..Heavy). Static TTF is used because both the variable ("NanumSquare Neo variable") and OTF ("NanumSquare Neo OTF") rename the family; static keeps a clean "NanumSquare Neo".'
add_pack "NanumSquareRound" "https://hangeul.naver.com/hangeul_static/webfont/zips/nanum-square-round.zip" 2535434 4 "Zip" '(?i)^[^/]+\.ttf$' "NanumSquareRoundR.ttf" 0 'TTF, 4 weights (Light/Regular/Bold/ExtraBold). TTF keeps a clean "NanumSquareRound" family (OTF appends "OTF").'
add_pack "NanumHuman" "https://hangeul.naver.com/hangeul_static/webfont/zips/NanumHuman.zip" 6190692 6 "Zip" '(?i)^NanumHuman/[^/]+\.ttf$' "NanumHumanRegular.ttf" 0 'TTF, 6 weights (ExtraLight..Heavy); skips __MACOSX/woff. Both formats are suffixed upstream, so this registers as "NanumHuman TTF".'
add_pack "D2Coding" "https://github.com/naver/d2codingfont/releases/download/VER1.3.2/D2Coding-Ver1.3.2-20180524.zip" 21256997 1 "Zip" '(?i)^D2CodingAll/[^/]+\.ttc$' "D2Coding-Ver1.3.2-20180524-all.ttc" 0 'Installs the D2CodingAll .ttc (regular+bold+ligature in one collection).'
add_pack "KoPubWorld" "https://www.kopus.org/wp-content/uploads/2026/04/KOPUBWORLD_OTF_FONTS2026.zip" 20297063 6 "Zip" '(?i)^[^/]+\.otf$' "KoPubWorld Batang_Pro Light.otf" 0 'OTF-only (2026 release). KoPubWorld Batang (serif) + Dotum (sans), 3 weights each (Light/Medium/Bold).'
add_pack "KoPub" "https://www.kopus.org/wp-content/uploads/2022/04/KOPUB2.0_OTF_FONTS.zip" 12640328 6 "Zip" '(?i)^[^/]+\.otf$' "KoPub Batang_Pro Light.otf" 0 'OTF-only (classic KoPub 2.0). KoPub Batang (serif) + Dotum (sans), 3 weights each (Light/Medium/Bold).'

# Formats byte integer into human-readable string
format_bytes() {
  local b="$1"
  if [ "$b" -ge 1073741824 ]; then
    awk -v b="$b" 'BEGIN { printf "%.2f GB", b / 1073741824 }'
  elif [ "$b" -ge 1048576 ]; then
    awk -v b="$b" 'BEGIN { printf "%.1f MB", b / 1048576 }'
  elif [ "$b" -ge 1024 ]; then
    awk -v b="$b" 'BEGIN { printf "%.0f KB", b / 1024 }'
  else
    printf "%d B" "$b"
  fi
}

# Atomically installs staged font files into target directory.
# Returns 0 on success, 1 on any file error.
commit_pack() {
  local target="$1"
  local probe_file="$2"
  shift 2
  local files=("$@")

  # 1. If --force, remove existing probe first to invalidate partial states
  if [ "$FORCE" -eq 1 ] && [ -f "$target/$probe_file" ]; then
    rm -f -- "$target/$probe_file" || return 1
  fi

  # 2. Commit all non-probe files first using destination temp files + atomic mv
  local f font_leaf dest_tmp
  for f in "${files[@]}"; do
    font_leaf="${f##*/}"
    [ "$font_leaf" = "$probe_file" ] && continue
    dest_tmp=$(mktemp "$target/.${font_leaf}.tmp.XXXXXX") || return 1
    TRACKED_TEMP_FILES+=("$dest_tmp")
    cp "$f" "$dest_tmp" || return 1
    chmod 644 "$dest_tmp" || return 1
    mv -f "$dest_tmp" "$target/$font_leaf" || return 1
  done

  # 3. Commit probe file LAST as the transaction stamp
  local probe_tmp
  probe_tmp=$(mktemp "$target/.${probe_file}.tmp.XXXXXX") || return 1
  TRACKED_TEMP_FILES+=("$probe_tmp")
  cp "$STAGED_DIR/$probe_file" "$probe_tmp" || return 1
  chmod 644 "$probe_tmp" || return 1
  mv -f "$probe_tmp" "$target/$probe_file" || return 1

  return 0
}

# Displays usage help and exits
show_help() {
  cat <<'EOF'
Usage: install_fonts_mac.sh [OPTIONS]

Downloads and installs a curated catalog of fonts into ~/Library/Fonts.

Options:
  -n, --name <substring[,substring...]>  Filter font packs by name (case-insensitive substring).
  -e, --extended        Include extended packs (Source Han pan-CJK collections).
  -f, --force           Reinstall and overwrite existing fonts.
  -r, --retries <0-10>  Max retries for transient network/archive errors (default: 2).
  -l, --list            Print catalog summary and size estimates, then exit.
  -y, --yes             Bypass interactive confirmation prompt.
  -h, --help            Show this help message and exit.
EOF
}

# Parse CLI options
while [ "$#" -gt 0 ]; do
  case "$1" in
    -n|--name)
      [ "$#" -ge 2 ] || { echo "Error: $1 requires an argument." >&2; exit 1; }
      NAME_FILTER="$2"
      shift 2
      ;;
    -e|--extended)
      EXTENDED=1
      shift
      ;;
    -f|--force)
      FORCE=1
      shift
      ;;
    -r|--retries)
      [ "$#" -ge 2 ] || { echo "Error: $1 requires an integer argument." >&2; exit 1; }
      RETRIES="$2"
      if ! [[ "$RETRIES" =~ ^[0-9]+$ ]] || [ "$RETRIES" -lt 0 ] || [ "$RETRIES" -gt 10 ]; then
        echo "Error: --retries must be an integer between 0 and 10." >&2
        exit 1
      fi
      shift 2
      ;;
    -l|--list)
      LIST_ONLY=1
      shift
      ;;
    -y|--yes)
      YES=1
      shift
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo "" >&2
      show_help >&2
      exit 1
      ;;
  esac
done

# Filter selected pack indices based on --extended and --name
SELECTED_INDICES=()
shopt -s nocasematch 2>/dev/null || true
for i in "${!PACK_NAME[@]}"; do
  # Check extended condition
  if [ "${PACK_EXTENDED[$i]}" -eq 1 ] && [ "$EXTENDED" -eq 0 ]; then
    continue
  fi
  # Check name substring filter (case-insensitive literal substring, comma-separated tokens supported)
  if [ -n "$NAME_FILTER" ]; then
    matched_name=0
    IFS=',' read -r -a name_tokens <<< "$NAME_FILTER"
    for token in "${name_tokens[@]}"; do
      token="$(echo "$token" | tr -d '[:space:]')"
      [ -z "$token" ] && continue
      if [[ "${PACK_NAME[$i]}" == *"$token"* ]]; then
        matched_name=1
        break
      fi
    done
    if [ "$matched_name" -eq 0 ]; then
      continue
    fi
  fi
  SELECTED_INDICES+=("$i")
done
shopt -u nocasematch 2>/dev/null || true

if [ "${#SELECTED_INDICES[@]}" -eq 0 ]; then
  echo "No matching font packs to install."
  exit 0
fi

# Calculate totals for summary
TOTAL_BYTES=0
TOTAL_FONTS=0
for i in "${SELECTED_INDICES[@]}"; do
  TOTAL_BYTES=$((TOTAL_BYTES + PACK_BYTES[i]))
  TOTAL_FONTS=$((TOTAL_FONTS + PACK_FONTS[i]))
done

# Print pre-run catalog summary
TOTAL_BYTES_STR=$(format_bytes "$TOTAL_BYTES")
echo ""
printf "== Install-Fonts (macOS): %d pack(s), ~%d font file(s), ~%s to download ==\n" \
  "${#SELECTED_INDICES[@]}" "$TOTAL_FONTS" "$TOTAL_BYTES_STR"
printf "   Target: %s\n" "$TARGET_DIR"

idx=0
for i in "${SELECTED_INDICES[@]}"; do
  idx=$((idx + 1))
  name="${PACK_NAME[$i]}"
  b="${PACK_BYTES[$i]}"
  fonts="${PACK_FONTS[$i]}"
  ext="${PACK_EXTENDED[$i]}"
  note="${PACK_NOTE[$i]}"

  tag=""
  if [ "$ext" -eq 1 ]; then
    tag=" [extended]"
  elif [ "$b" -ge 52428800 ]; then
    tag=" [LARGE]"
  fi

  b_str=$(format_bytes "$b")
  printf "   %2d. %-20s %10s  ~%d fonts%s\n" "$idx" "$name" "$b_str" "$fonts" "$tag"
  if [ "$LIST_ONLY" -eq 1 ] && [ -n "$note" ]; then
    printf "       %s\n" "$note"
  fi
done

# If --list specified, exit 0 immediately before any extractor preflight or network calls
if [ "$LIST_ONLY" -eq 1 ]; then
  exit 0
fi

# Preflight: check for required inbox tools
if ! command -v curl >/dev/null 2>&1; then
  echo "Error: curl is required but was not found on PATH." >&2
  exit 1
fi

if ! command -v unzip >/dev/null 2>&1; then
  echo "Error: unzip is required but was not found on PATH." >&2
  exit 1
fi

# Preflight: check if any selected pack requires 7z extraction
NEEDS_7Z=0
for i in "${SELECTED_INDICES[@]}"; do
  if [ "${PACK_KIND[$i]}" = "7z" ]; then
    NEEDS_7Z=1
    break
  fi
done

SEVENZ=""
if [ "$NEEDS_7Z" -eq 1 ]; then
  if command -v 7zz >/dev/null 2>&1; then
    SEVENZ="7zz"
  elif command -v 7z >/dev/null 2>&1; then
    SEVENZ="7z"
  elif command -v 7za >/dev/null 2>&1; then
    SEVENZ="7za"
  else
    echo "Error: Selected pack(s) require 7z archive extraction, but '7zz', '7z', or '7za' was not found on PATH." >&2
    echo "Install with Homebrew: brew install sevenzip" >&2
    exit 1
  fi
fi

# Prompt confirmation unless -y / --yes
if [ "$YES" -eq 0 ]; then
  printf "Proceed with downloading and installing %d font pack(s)? (Y/n) " "${#SELECTED_INDICES[@]}"
  read -r choice
  case "$choice" in
    [nN]*)
      echo "Aborting. Nothing was downloaded or installed."
      exit 130
      ;;
  esac
fi

# Ensure target directory exists and is writable before starting
if ! mkdir -p "$TARGET_DIR" 2>/dev/null; then
  echo "Error: Failed to create target directory: $TARGET_DIR" >&2
  exit 1
fi

if [ ! -d "$TARGET_DIR" ] || [ ! -w "$TARGET_DIR" ]; then
  echo "Error: Target directory is not writable: $TARGET_DIR" >&2
  exit 1
fi

# Working directory and process-isolated temporary file tracking
WORK_DIR=$(mktemp -d -t install_fonts_mac.XXXXXX) || {
  echo "Error: Failed to create temporary working directory." >&2
  exit 1
}

if [ -z "$WORK_DIR" ] || [ ! -d "$WORK_DIR" ]; then
  echo "Error: Invalid temporary working directory." >&2
  exit 1
fi

TRACKED_TEMP_FILES=()

# Process cleanup handler: remove isolated workspace and any tracked destination temp files
cleanup() {
  if [ -n "${WORK_DIR:-}" ] && [ -d "$WORK_DIR" ]; then
    rm -rf -- "$WORK_DIR"
  fi
  if [ "${#TRACKED_TEMP_FILES[@]}" -gt 0 ]; then
    for f in "${TRACKED_TEMP_FILES[@]}"; do
      [ -f "$f" ] && rm -f -- "$f"
    done
  fi
}
trap cleanup EXIT
trap 'cleanup; trap - INT; kill -s INT "$$"' INT
trap 'cleanup; trap - TERM; kill -s TERM "$$"' TERM
# Execution loop state
TOTAL_INSTALLED=0
TOTAL_SKIPPED=0
FAILED_PACKS=()

item_idx=0
for i in "${SELECTED_INDICES[@]}"; do
  item_idx=$((item_idx + 1))
  name="${PACK_NAME[$i]}"
  url="${PACK_URL[$i]}"
  bytes="${PACK_BYTES[$i]}"
  fonts="${PACK_FONTS[$i]}"
  kind="${PACK_KIND[$i]}"
  include="${PACK_INCLUDE[$i]}"
  probe="${PACK_PROBE[$i]}"

  bytes_str=$(format_bytes "$bytes")
  echo ""
  printf "[%d/%d] %s (%s)\n" "$item_idx" "${#SELECTED_INDICES[@]}" "$name" "$bytes_str"

  # Pre-download probe check: skip if representative font already installed and not --force
  if [ -f "$TARGET_DIR/$probe" ] && [ "$FORCE" -eq 0 ]; then
    printf "      already installed (%s); skipping download.\n" "$probe"
    TOTAL_SKIPPED=$((TOTAL_SKIPPED + 1))
    continue
  fi

  printf "      source: %s\n" "$url"

  # Workspace staging folders for this pack
  [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ] || {
    echo "Error: Working directory lost." >&2
    exit 1
  }
  DL_DIR="$WORK_DIR/dl"
  STAGED_DIR="$WORK_DIR/staged"
  rm -rf -- "$DL_DIR" "$STAGED_DIR"
  if ! mkdir -p "$DL_DIR" "$STAGED_DIR"; then
    last_error="Failed to create staging directories"
    FAILED_PACKS+=("$name: $url")
    echo "Warning: Install FAILED for '$name': $last_error" >&2
    continue
  fi

  max_attempts=$((1 + RETRIES))
  pack_ok=0
  last_error=""

  for attempt in $(seq 1 "$max_attempts"); do
    if [ "$attempt" -gt 1 ]; then
      printf "      retry %d/%d (transient error: %s)\n" "$((attempt - 1))" "$RETRIES" "$last_error"
      sleep_sec=$(( (attempt - 1) * 2 ))
      [ "$sleep_sec" -gt 10 ] && sleep_sec=10
      sleep "$sleep_sec"
      rm -rf -- "$DL_DIR" "$STAGED_DIR"
      if ! mkdir -p "$DL_DIR" "$STAGED_DIR"; then
        last_error="Failed to recreate staging directories on retry"
        break
      fi
    fi
    # Determine filename for download
    dl_filename="${url##*/}"
    dl_file="$DL_DIR/$dl_filename"

    echo "      downloading..."
    # Download with curl. We do not use -C - after corruption because the file was purged.
    if ! curl -fLC - --connect-timeout 15 --max-time 1800 -sS -o "$dl_file" "$url"; then
      last_error="Download failed (HTTP/network error)"
      # Always remove potentially corrupt or partial download before retry
      rm -f "$dl_file"
      continue
    fi

    # Extraction step based on pack kind
    if [ "$kind" = "File" ]; then
      # Direct single font file download
      if ! cp "$dl_file" "$STAGED_DIR/$probe"; then
        last_error="Failed to stage file"
        rm -f "$dl_file"
        continue
      fi
    elif [ "$kind" = "Zip" ]; then
      # Strip leading (?i) from .NET regex for BSD grep -Ei compatibility
      norm_regex="${include#(\?i)}"

      # List entries in archive
      if ! entry_list=$(unzip -Z1 "$dl_file" 2>&1); then
        last_error="Corrupt ZIP archive ($entry_list)"
        rm -f "$dl_file"
        continue
      fi

      # Filter matching entries, rejecting __MACOSX and AppleDouble ._* sidecars
      matched_entries=()
      while IFS= read -r entry; do
        [ -z "$entry" ] && continue
        case "$entry" in
          *__MACOSX*|*/._*|._*) continue ;;
        esac
        if printf '%s\n' "$entry" | grep -Ei "$norm_regex" >/dev/null 2>&1; then
          escaped_entry=$(printf '%s\n' "$entry" | sed 's/\\/\\\\/g; s/\[/\\[/g; s/\]/\\]/g; s/\*/\\*/g; s/\?/\\?/g')
          matched_entries+=("$escaped_entry")
        fi
      done <<< "$entry_list"

      # Check for extraction match
      if [ "${#matched_entries[@]}" -gt 0 ]; then
        if ! unzip -q -j -o "$dl_file" "${matched_entries[@]}" -d "$STAGED_DIR" >/dev/null 2>&1; then
          last_error="Failed to extract matching files from ZIP"
          rm -f "$dl_file"
          continue
        fi
      fi
    elif [ "$kind" = "7z" ]; then
      # Strip leading (?i) from regex
      norm_regex="${include#(\?i)}"

      # List archive entries with 7z
      if ! listing=$("$SEVENZ" l -ba -slt "$dl_file" 2>&1); then
        last_error="Corrupt 7z archive ($listing)"
        rm -f "$dl_file"
        continue
      fi

      # Extract paths from Path = ... lines in 7z verbose listing
      matched_entries=()
      while IFS= read -r line; do
        if [[ "$line" =~ ^Path\ =\ (.*)$ ]]; then
          entry="${BASH_REMATCH[1]}"
          case "$entry" in
            *__MACOSX*|*/._*|._*) continue ;;
          esac
          if printf '%s\n' "$entry" | grep -Ei "$norm_regex" >/dev/null 2>&1; then
            matched_entries+=("$entry")
          fi
        fi
      done <<< "$listing"

      if [ "${#matched_entries[@]}" -gt 0 ]; then
        if ! "$SEVENZ" e -y -o"$STAGED_DIR" "$dl_file" "${matched_entries[@]}" >/dev/null 2>&1; then
          last_error="Failed to extract matching files from 7z"
          rm -f "$dl_file"
          continue
        fi
      fi
    else
      last_error="Unsupported font pack kind '$kind'"
      break
    fi

    # Normalize permissions: ensure extracted font files are readable and writable
    # (some archives like OpenDyslexic store files with mode 0000)
    if ! chmod -R u+rw "$STAGED_DIR" 2>/dev/null; then
      last_error="Failed to set read/write permissions on staged files"
      echo "Warning: $last_error for '$name'; aborting pack without retry." >&2
      break
    fi

    # Pre-commit validation gate
    staged_files=()
    for f in "$STAGED_DIR/"*; do
      [ -f "$f" ] && staged_files+=("$f")
    done
    staged_count="${#staged_files[@]}"

    # Hard check 1: at least one font file extracted
    if [ "$staged_count" -eq 0 ]; then
      last_error="No matching font entries found in archive (layout drift or invalid regex)"
      echo "Warning: $last_error for '$name'; aborting pack without retry." >&2
      break
    fi

    # Hard check 2: probe font exists and is non-empty
    if [ ! -s "$STAGED_DIR/$probe" ]; then
      last_error="Staged probe file '$probe' is missing or 0 bytes"
      echo "Warning: $last_error for '$name'; aborting pack without retry." >&2
      break
    fi

    # Soft check: warn if extracted file count differs from catalog estimated count
    if [ "$staged_count" -ne "$fonts" ]; then
      printf "      notice: extracted %d file(s), catalog estimated ~%d\n" "$staged_count" "$fonts"
    fi

    # Pack-level atomic commit protocol
    if ! commit_pack "$TARGET_DIR" "$probe" "${staged_files[@]}"; then
      last_error="Atomic commit failed during installation into target directory"
      # Invariant: ensure probe is absent if commit failed mid-way
      [ -f "$TARGET_DIR/$probe" ] && rm -f "$TARGET_DIR/$probe"
      echo "Warning: $last_error for '$name'; aborting pack." >&2
      break
    fi
    pack_ok=1
    TOTAL_INSTALLED=$((TOTAL_INSTALLED + staged_count))
    printf "      installed %d font file(s) (running total installed: %d)\n" "$staged_count" "$TOTAL_INSTALLED"
    break
  done

  # Record failure if pack was not successfully installed
  if [ "$pack_ok" -eq 0 ]; then
    FAILED_PACKS+=("$name: $url")
    echo "Warning: Install FAILED for '$name': $last_error" >&2
  fi

  # Cleanup download and staged directory for this pack
  [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ] && rm -rf -- "$DL_DIR" "$STAGED_DIR"
done

# Final execution summary
echo ""
printf "== Done: %d installed, %d skipped, %d failure(s). ==\n" \
  "$TOTAL_INSTALLED" "$TOTAL_SKIPPED" "${#FAILED_PACKS[@]}"

if [ "$TOTAL_INSTALLED" -gt 0 ]; then
  echo "Note: macOS activates fonts automatically. Already-running applications may need to be restarted to refresh their font list."
fi

if [ "${#FAILED_PACKS[@]}" -gt 0 ]; then
  echo "Failed packs:"
  for f in "${FAILED_PACKS[@]}"; do
    printf "  - %s\n" "$f"
  done
  exit 1
fi

exit 0
