#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/install"
sed "s|/usr/local/bin|$tmp/install|g" "$root/bin/install_ab-av1.sh" > "$tmp/installer"
export PATH="$tmp/bin:$PATH" TEST_ROOT="$tmp"

cat > "$tmp/bin/ffmpeg" <<'EOF'
#!/bin/bash
echo "--enable-libsvtav1 --enable-libvmaf --enable-libopus" | sed "s/${MISSING:-not-present}//"
EOF
cat > "$tmp/bin/curl" <<'EOF'
#!/bin/bash
[[ ${CURL_FAIL:-0} == 0 ]] || { echo 'connection failed' >&2; exit 7; }
while [[ $# -gt 0 ]]; do
  if [[ $1 == -o ]]; then output=$2; shift; fi
  shift
done
echo data > "$output"
EOF
cat > "$tmp/bin/jq" <<'EOF'
#!/bin/bash
[[ ${BAD_METADATA:-0} == 0 ]] || exit 1
if [[ $1 == -er ]]; then echo v1.2.3; else echo https://example.test/archive.tar.zst; fi
EOF
cat > "$tmp/bin/tar" <<'EOF'
#!/bin/bash
[[ ${TAR_FAIL:-0} == 0 ]] || exit 1
while [[ $# -gt 0 ]]; do
  if [[ $1 == -C ]]; then dest=$2; shift; fi
  shift
done
if [[ $dest == */ab-av1 ]]; then
  printf '#!/bin/bash\necho ab-av1 1.2.3\n' > "$dest/ab-av1"
  chmod +x "$dest/ab-av1"
else
  printf '#!/bin/bash\necho --enable-libsvtav1 --enable-libvmaf --enable-libopus\n' > "$dest/ffmpeg"
  chmod +x "$dest/ffmpeg"
fi
EOF
cat > "$tmp/bin/sudo" <<'EOF'
#!/bin/bash
"$@"
EOF
cat > "$tmp/bin/unzstd" <<'EOF'
#!/bin/bash
exit 0
EOF
chmod +x "$tmp/bin/"*

# Exercise each installer outcome without network or privileged writes.
run_case() {
  local expected=$1 pattern=$2
  shift 2
  local status=0
  env "$@" bash "$tmp/installer" > "$tmp/output" 2>&1 || status=$?
  if [[ $expected == success && $status != 0 || $expected == failure && $status == 0 ]] || ! grep -Fq "$pattern" "$tmp/output"; then
    cat "$tmp/output" >&2
    echo "FAIL: $pattern (exit $status)" >&2
    exit 1
  fi
  if [[ $expected == failure ]] && grep -Fq 'Installed and verified' "$tmp/output"; then
    echo "FAIL: success reported on failure" >&2; exit 1
  fi
  echo "PASS: $pattern"
}
run_case success 'Installed and verified ab-av1 1.2.3'
run_case failure 'ab-av1 release lookup failed' CURL_FAIL=1
run_case failure 'Invalid release metadata' BAD_METADATA=1
run_case failure 'ab-av1 extraction failed' TAR_FAIL=1
for flag in libsvtav1 libvmaf libopus; do
  run_case failure "FFmpeg missing: $flag" MISSING="--enable-$flag" CURL_FAIL=1
done
