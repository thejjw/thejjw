# Offline Terminal Browser Kit — Preparation & Test Plan

A self-contained package of terminal web browsers (Lynx + ELinks static) for air-gapped Linux targets, with a Docker-based test plan that simulates the offline environment.

**Targets:** Ubuntu 22.04 LTS (jammy), 24.04 LTS (noble), 26.04 LTS (resolute), and Rocky Linux 8, 9, and 10, all amd64/x86_64. Rocky 10's userspace is **x86-64-v3** (Intel Haswell / AMD Excavator and newer). Rocky 8/9 and the Ubuntu kits run on older x86-64.

**Kit contents:** Lynx packages (deb/rpm) + the few small dependency packages they need + the ELinks static binary (zero dependencies, runs anywhere).

---

## Quick usage (smoke checks)

These are text-mode browsers: they fetch a URL and render it as text — ideal for a quick "does it load and return content?" check before handing off to a dedicated test environment. They do **not** run JavaScript (ELinks has only partial/optional JS), so JS-heavy single-page apps may render as an empty shell; that's expected, not a failure.

**Lynx** (installed as `/usr/bin/lynx`):
```bash
lynx -dump https://example.com            # render page as text, then exit
lynx -dump -nolist https://example.com    # skip the link list at the bottom
lynx https://example.com                  # interactive: arrows move, Enter follows, q quits
lynx -dump https://example.com | grep -q "Welcome" && echo OK || echo FAIL
```

**ELinks** (from the kit — it's a static tarball, so use the full path or symlink it). The archive is rooted at `opt/elinks/` (binary, `elinks-lite`, and locale files), so extract from `/`:
```bash
sudo tar xf elinks-0.20.0-x86_64.tar.xz -C /
/opt/elinks/bin/elinks -dump https://example.com     # render as text, then exit
/opt/elinks/bin/elinks https://example.com          # interactive
sudo ln -s /opt/elinks/bin/elinks /usr/local/bin/elinks   # optional: make it `elinks`
```
`tar xf ... -C /opt` nests a second `opt/` and the binary ends up at `/opt/opt/elinks/bin/elinks`.
ELinks interactive keys: arrow keys / Tab move between links, Enter follows a link, `g` opens the goto-URL dialog, `q` quits, `d` saves/downloads. ELinks renders tables, CSS and some JavaScript better than Lynx — try it when Lynx shows a page as a jumble.

**Check an HTTP status / headers (often lighter than a browser):**
```bash
curl -sI -o /dev/null -w '%{http_code}\n' https://example.com
curl -s https://api.example.com/health | head      # raw JSON/HTML
```

**Handy flags:** `lynx -useragent="Mozilla/5.0"` if a site blocks the default agent; `lynx -accept_all_cookies` to skip cookie prompts in scripts; `elinks -source https://example.com` to print raw HTML.

**Which to use:** **Lynx** for documents and server-rendered pages (simplest, most stable); **ELinks** for messier modern pages (CSS, tables, some JS); **curl** for non-HTML checks (APIs, status codes, headers).

**Remember:** this is a smoke check — it confirms a URL loads and returns content. It can't verify JavaScript behaviour, layout, or full functionality; that's what the dedicated test environments are for.

---

## 1. Validated kit inventory

Total size ≈ **25 MB**. (Versions below are what the scripts pulled at validation time; re-running pulls the then-current versions.)

| Target | Files | Size |
|---|---|---|
| Ubuntu 22.04 | `libbsd0_0.11.5-1_amd64.deb`, `libmd0_1.0.4-1build1_amd64.deb`, `lynx-common_2.9.0dev.10-1_all.deb`, `lynx_2.9.0dev.10-1_amd64.deb` | 1.8 MB |
| Ubuntu 24.04 | `libbrotli1_1.1.0-2ubuntu0.1_amd64.deb`, `lynx-common_2.9.0rel.0-2build2_all.deb`, `lynx_2.9.0rel.0-2build2_amd64.deb` | 2.0 MB |
| Ubuntu 26.04 | `libbrotli1_1.2.0-3ubuntu0.1_amd64.deb`, `libffi8_3.5.2-4_amd64.deb`, `libgnutls30t64_3.8.12-2ubuntu1.1_amd64.deb`, `libhogweed6t64_3.10.2-1_amd64.deb`, `libidn2-0_2.3.8-4build1_amd64.deb`, `libnettle8t64_3.10.2-1_amd64.deb`, `libp11-kit0_0.26.2-2_amd64.deb`, `libtasn1-6_4.21.0-1_amd64.deb`, `libunistring5_1.3-2build1_amd64.deb`, `lynx-common_2.9.2-2_all.deb`, `lynx_2.9.2-2_amd64.deb` | 4.3 MB |
| EL8 (Rocky) | `rocky-indexhtml-8.0-0.el8.noarch.rpm`, `bzip2-libs-1.0.6-26.el8.x86_64.rpm`, `libidn2-2.2.0-1.el8.x86_64.rpm`, `lynx-2.8.9-4.el8.x86_64.rpm` | 2.0 MB |
| EL9 (Rocky) | `rocky-indexhtml-9.0-3.el9.noarch.rpm`, `bzip2-libs-1.0.8-11.el9.x86_64.rpm`, `libidn2-2.3.0-7.el9.x86_64.rpm`, `lynx-2.8.9-20.el9.x86_64.rpm` | 1.9 MB |
| EL10 (Rocky) | `rocky-indexhtml-10.0-1.el10.noarch.rpm`, `bzip2-libs-1.0.8-25.el10.x86_64.rpm`, `libbrotli-1.1.0-8.el10_2.1.x86_64.rpm`, `libidn2-2.3.7-3.el10.x86_64.rpm`, `lynx-2.9.0-6.el10.x86_64.rpm` | 2.3 MB |
| Any x64 | `elinks-0.20.0-x86_64.tar.xz` (static, no deps) | 10.5 MB |

`prep.sh` writes `SHA256SUMS` with paths relative to the kit root. Run `sha256sum -c` from that directory.

The v0.20.0 x86_64 asset is 10,521,720 bytes. Its ELF has no interpreter segment (`ldd` reports `not a dynamic executable`). Members start with `opt/elinks/`, and the tree also contains `opt/elinks/bin/elinks-lite`.

The EL8 and EL9 file lists above are the 2026-11-12 kit. `prep.sh` no longer downloads EL8 `bzip2-libs` and `libidn2`, or EL9 `bzip2-libs`: those libraries are already in the Rocky images, and those Lynx builds do not link them (see §7). The next prep run will be slightly smaller than the sizes in the table. The 7/7 result was for the larger set.

---

## 2. Preparation (online machine with Docker)

### 2.1 Prerequisites
- Docker Desktop on Windows (WSL2 backend) or any Linux host with Docker.
- Internet access **during preparation only**.
- A bash shell: WSL2 Ubuntu is the easiest on Windows (see §5).

### 2.2 Directory layout
```
offline-browsers/
├── prep.sh                 # download the kit
├── test.sh                 # offline test plan
├── check-updates.sh        # optional: report candidate versions, no downloads (see §8.3)
├── SHA256SUMS              # generated by prep.sh
├── ubuntu/{22-jammy,24-noble,26-resolute}/
├── el/{el8,el9,el10}/
├── elinks/elinks-0.20.0-x86_64.tar.xz
└── tests/test.html         # generated by test.sh
```

### 2.3 `prep.sh`
```bash
#!/usr/bin/env bash
# Prepare offline terminal-browser packages (Lynx debs/RPMs + ELinks static).
# Run on any Linux host / WSL2 with Docker and internet access.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$ROOT"/ubuntu/{22-jammy,24-noble,26-resolute} "$ROOT"/el/{el8,el9,el10} "$ROOT"/elinks "$ROOT"/tests

echo "=== [1/4] ELinks static binary ==="
curl -fL --retry 3 -o "$ROOT/elinks/elinks-0.20.0-x86_64.tar.xz" \
  https://github.com/rkd77/elinks/releases/download/v0.20.0/elinks-0.20.0-x86_64.tar.xz
tar tf "$ROOT/elinks/elinks-0.20.0-x86_64.tar.xz" > /dev/null && echo "ELinks tarball OK"

echo "=== [2/4] Ubuntu debs (lynx + lynx-common + missing deps) ==="
for rel in 22-jammy:22.04 24-noble:24.04 26-resolute:26.04; do
  dirname="${rel%%:*}"; tag="${rel##*:}"
  echo "-- ubuntu:$tag --"
  docker run --rm -v "$ROOT/ubuntu/$dirname:/out" "ubuntu:$tag" bash -c '
    set -e
    apt-get update -qq
    apt-get install -y -qq --download-only --no-install-recommends lynx
    cp /var/cache/apt/archives/*.deb /out/
  '
done

echo "=== [3/4] EL RPMs (lynx + extras) ==="
echo "-- el8 --"
# lynx is in PowerTools, not BaseOS/AppStream. It links OpenSSL 1.1, ncurses, zlib.
docker run --rm -v "$ROOT/el/el8:/out" rockylinux/rockylinux:8 bash -c '
  set -e
  dnf install -y -q --downloadonly --downloaddir=/out --enablerepo=powertools --setopt=install_weak_deps=False lynx rocky-indexhtml
'
echo "-- el9 --"
# libidn2 is already in the image, so a plain --downloadonly would skip it.
docker run --rm -v "$ROOT/el/el9:/out" rockylinux/rockylinux:9 bash -c '
  set -e
  dnf install -y -q --downloadonly --downloaddir=/out --setopt=install_weak_deps=False lynx rocky-indexhtml
  dnf reinstall -y -q --downloadonly --downloaddir=/out libidn2
'
echo "-- el10 --"
docker run --rm -v "$ROOT/el/el10:/out" rockylinux/rockylinux:10 bash -c '
  set -e
  dnf install -y -q --downloadonly --downloaddir=/out --setopt=install_weak_deps=False lynx rocky-indexhtml libbrotli
  dnf reinstall -y -q --downloadonly --downloaddir=/out bzip2-libs libidn2
'

echo "=== [4/4] Checksums + inventory ==="
# Relative paths, so `sha256sum -c SHA256SUMS` works on another machine.
(
  cd "$ROOT"
  find . -type f \( -name '*.deb' -o -name '*.rpm' -o -name '*.tar.xz' \) -print0 \
    | sort -z | xargs -0 sha256sum > SHA256SUMS
)
cat "$ROOT/SHA256SUMS"
echo
echo "--- files ---"
find "$ROOT" -type f | sort
```

### 2.4 What it does
- **ELinks:** downloads the official static x86_64 tarball from GitHub releases. The v0.20.0 binary has no dynamic interpreter. The archive is a prefix tree (`opt/elinks/...`), not a single file.
- **Ubuntu:** in a clean `ubuntu:<release>` container, `apt-get install --download-only --no-install-recommends lynx` fetches `lynx`, `lynx-common`, and every dependency not already in the base image. Recommends such as `mailcap` are left out. This is why jammy pulls `libbsd0`/`libmd0` (its amd64 lynx package depends on `libbsd0`), noble pulls `libbrotli1`, and resolute pulls the gnutls chain. `libgmp10` is already in all three Ubuntu images, so it is not in the kit even though `libgnutls30t64` depends on it.
- **EL (Rocky):** `dnf install --downloadonly` fetches `lynx` + `rocky-indexhtml` (`redhat-indexhtml`). On EL8, `lynx` is in **PowerTools**, not BaseOS or AppStream, so `--enablerepo=powertools` is required. The same NEVRA is also in the disabled Devel repo; do not enable Devel. `dnf reinstall --downloadonly` force-fetches libraries the image already has and that Lynx actually links: `libidn2` on EL9, and `bzip2-libs` plus `libidn2` on EL10. EL8 Lynx does not link either. EL10 also fetches `libbrotli`, which the image does not have.
- **Checksums:** `SHA256SUMS` covers every deb/rpm/tarball, with paths relative to the kit root.

> **Why `rockylinux/rockylinux` and not `rockylinux`?** The Docker Official Library `rockylinux` image is still frozen at the 2023-11-19 tags `8.9` and `9.3`, and it has no `:10`. Rocky's maintainers said in January 2026 that they cannot publish updates there. Use the Rocky-maintained `rockylinux/rockylinux` repository, which has 8, 9, and 10.

---

## 3. Test plan (Docker, simulated air-gap)

### 3.1 Principles
- `--network none` removes all network access from the container — a faithful air-gap simulation.
- Install **only** from the mounted local kit directory.
- After install, run `lynx -version`, check `ldd` for missing libraries, and render a local HTML file (`-dump`).
- The ELinks test extracts the tarball and runs the binary directly — no install step at all. The Rocky images lack the `xz` binary, so the test uses `python3`'s `tarfile`/`lzma` on Rocky 9, which has `/usr/bin/python3`. Rocky 8 has `/usr/libexec/platform-python` and no `python3` on `PATH`, so the test is not run there. The static binary was confirmed separately: the v0.20.0 x86_64 ELF has no `PT_INTERP` segment.

### 3.2 `test.sh`
```bash
#!/usr/bin/env bash
# Test the offline package set in clean containers with NO network.
# Simulates the air-gapped target: install only from the mounted local dir.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$ROOT/tests"

# Local HTML file for the functional smoke test (no network required).
cat > "$ROOT/tests/test.html" <<'HTML'
<!DOCTYPE html>
<html><head><title>Offline render test</title></head>
<body><h1>Offline render test</h1><p>If you can read this, the browser works.</p></body></html>
HTML

pass=0; fail=0
report() { if [ "$1" -eq 0 ]; then echo "PASS: $2"; pass=$((pass+1)); else echo "FAIL: $2"; fail=$((fail+1)); fi; }

echo "===== [1/7] Ubuntu 22.04 (jammy) ====="
docker run --rm --network none \
  -v "$ROOT/ubuntu/22-jammy:/pkgs:ro" -v "$ROOT/tests:/tests:ro" \
  ubuntu:22.04 bash -c '
    set -e
    dpkg -i /pkgs/*.deb
    lynx -version
    ldd /usr/bin/lynx | grep "not found" && exit 1 || true
    lynx -dump /tests/test.html | grep -q "Offline render test"
  ' > "$ROOT/tests/jammy.log" 2>&1; report $? "ubuntu:22.04 deb offline install"; tail -4 "$ROOT/tests/jammy.log"

echo "===== [2/7] Ubuntu 24.04 (noble) ====="
docker run --rm --network none \
  -v "$ROOT/ubuntu/24-noble:/pkgs:ro" -v "$ROOT/tests:/tests:ro" \
  ubuntu:24.04 bash -c '
    set -e
    dpkg -i /pkgs/*.deb
    lynx -version
    ldd /usr/bin/lynx | grep "not found" && exit 1 || true
    lynx -dump /tests/test.html | grep -q "Offline render test"
  ' > "$ROOT/tests/noble.log" 2>&1; report $? "ubuntu:24.04 deb offline install"; tail -4 "$ROOT/tests/noble.log"

echo "===== [3/7] Ubuntu 26.04 (resolute) ====="
docker run --rm --network none \
  -v "$ROOT/ubuntu/26-resolute:/pkgs:ro" -v "$ROOT/tests:/tests:ro" \
  ubuntu:26.04 bash -c '
    set -e
    dpkg -i /pkgs/*.deb
    lynx -version
    ldd /usr/bin/lynx | grep "not found" && exit 1 || true
    lynx -dump /tests/test.html | grep -q "Offline render test"
  ' > "$ROOT/tests/resolute.log" 2>&1; report $? "ubuntu:26.04 deb offline install"; tail -4 "$ROOT/tests/resolute.log"

echo "===== [4/7] EL8 ====="
docker run --rm --network none \
  -v "$ROOT/el/el8:/pkgs:ro" -v "$ROOT/tests:/tests:ro" \
  rockylinux/rockylinux:8 bash -c '
    set -e
    dnf install -y --disablerepo="*" /pkgs/*.rpm
    lynx -version
    ldd /usr/bin/lynx | grep "not found" && exit 1 || true
    lynx -dump /tests/test.html | grep -q "Offline render test"
  ' > "$ROOT/tests/el8.log" 2>&1; report $? "rockylinux:8 rpm offline install"; tail -4 "$ROOT/tests/el8.log"

echo "===== [5/7] EL9 ====="
docker run --rm --network none \
  -v "$ROOT/el/el9:/pkgs:ro" -v "$ROOT/tests:/tests:ro" \
  rockylinux/rockylinux:9 bash -c '
    set -e
    dnf install -y --disablerepo="*" /pkgs/*.rpm
    lynx -version
    ldd /usr/bin/lynx | grep "not found" && exit 1 || true
    lynx -dump /tests/test.html | grep -q "Offline render test"
  ' > "$ROOT/tests/el9.log" 2>&1; report $? "rockylinux:9 rpm offline install"; tail -4 "$ROOT/tests/el9.log"

echo "===== [6/7] EL10 ====="
docker run --rm --network none \
  -v "$ROOT/el/el10:/pkgs:ro" -v "$ROOT/tests:/tests:ro" \
  rockylinux/rockylinux:10 bash -c '
    set -e
    dnf install -y --disablerepo="*" /pkgs/*.rpm
    lynx -version
    ldd /usr/bin/lynx | grep "not found" && exit 1 || true
    lynx -dump /tests/test.html | grep -q "Offline render test"
  ' > "$ROOT/tests/el10.log" 2>&1; report $? "rockylinux:10 rpm offline install"; tail -4 "$ROOT/tests/el10.log"

echo "===== [7/7] ELinks static (no install) ====="
docker run --rm --network none \
  -v "$ROOT/elinks:/pkgs:ro" -v "$ROOT/tests:/tests:ro" \
  rockylinux/rockylinux:9 bash -c '
    set -e
    python3 -c "import tarfile; tarfile.open(\"/pkgs/elinks-0.20.0-x86_64.tar.xz\").extractall(\"/tmp\")"
    # Archive members are opt/elinks/..., so this path is /tmp/opt/elinks, not /tmp/elinks.
    ldd /tmp/opt/elinks/bin/elinks 2>&1 | grep -q "not a dynamic executable"
    /tmp/opt/elinks/bin/elinks -version
    /tmp/opt/elinks/bin/elinks -dump /tests/test.html | grep -q "Offline render test"
  ' > "$ROOT/tests/elinks.log" 2>&1; report $? "elinks static offline run"; tail -4 "$ROOT/tests/elinks.log"

echo
echo "===== SUMMARY: $pass passed, $fail failed ====="
[ "$fail" -eq 0 ]
```

### 3.3 Validated result
Ran end-to-end on a 2 GB Linux host with Docker 29.9.3:

```
[1/7] ubuntu:22.04    PASS
[2/7] ubuntu:24.04    PASS
[3/7] ubuntu:26.04    PASS
[4/7] rockylinux:8    PASS
[5/7] rockylinux:9    PASS
[6/7] rockylinux:10   PASS
[7/7] elinks static   PASS
SUMMARY: 7 passed, 0 failed
```

---

## 4. Deployment to the air-gapped target

Copy the whole `offline-browsers/` directory to the target (USB, internal share, etc.).

**Ubuntu**
```bash
sudo dpkg -i /path/to/ubuntu/22-jammy/*.deb      # or 24-noble/ or 26-resolute/
lynx -version
lynx -dump https://example.com                  # needs network on the target
```

**Rocky Linux**
```bash
sudo dnf install -y --disablerepo='*' /path/to/el/el9/*.rpm   # or el8/ or el10/
lynx -version
```
If `dnf` is unavailable, use `sudo rpm -ivh --replacepkgs /path/to/el/el9/*.rpm`.

**ELinks (any x64 Linux, no install, no shared libraries)**
```bash
sudo tar xf /path/to/elinks/elinks-0.20.0-x86_64.tar.xz -C /
/opt/elinks/bin/elinks -version
/opt/elinks/bin/elinks -dump https://example.com
```
The tarball already contains the `opt/elinks/` prefix. `-C /opt` writes `/opt/opt/elinks/bin/elinks`.

---

## 5. Windows notes

- Install **Docker Desktop** and enable *Settings → General → Use the WSL 2 based engine*.
- Install WSL2 if needed: `wsl --install` (then reboot). Open the Ubuntu app.
- Do the prep/test in a **WSL2 bash shell** — the scripts are bash and Docker Desktop's Linux containers work directly from WSL2.
- Put the kit inside the WSL2 filesystem (e.g. `~/offline-browsers`), not under `/mnt/c/...`, for speed.
- If you edit the `.sh` files on Windows, keep **LF** line endings (VS Code: bottom-right `CRLF` → `LF`; or run `sed -i 's/\r$//' prep.sh test.sh`).
- PowerShell-only alternative for a single test:
  ```powershell
  docker run --rm --network none -v "${PWD}\ubuntu\24-noble:/pkgs:ro" ubuntu:24.04 bash -c "dpkg -i /pkgs/*.deb && lynx -version"
  ```
- Verify Docker is working: `docker info`.

---

## 6. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `rpm -ivh` exits 4, "package ... is already installed" | Target already has `libidn2` (EL9/EL10) or `bzip2-libs` (EL10) | Use `dnf install -y --disablerepo='*' ...` or `rpm -ivh --replacepkgs ...` |
| `lynx: error while loading shared libraries: libgmp.so.10` on Ubuntu 26.04 | `libgmp10` is not in the kit; the `ubuntu:26.04` image already has it | Install the distro `libgmp10` package. A normal Ubuntu install has it |
| `dpkg -i` fails: `libbsd.so.0: cannot open shared object file` (jammy) | `libbsd0` missing | Install the carried `libbsd0` deb |
| `dpkg -i` fails: `libbrotli.so.1: cannot open shared object file` (noble/resolute) | `libbrotli1` missing | Install the carried `libbrotli1` deb |
| `rpm` fails: `redhat-indexhtml is needed by lynx` | virtual provide missing | Install the carried `rocky-indexhtml` rpm (provides `redhat-indexhtml`) |
| `rpm` fails: `libbrotlidec.so.1: cannot open shared object file` (EL10) | brotli missing | Install the carried `libbrotli` rpm |
| `tar: xz: Cannot exec` in a minimal image | image lacks xz | Use a normal server image, or extract with `python3 -c "import tarfile; tarfile.open('...').extractall(...)"`; a real Rocky server has `xz` |
| EL8 rpm won't run on EL9/10 | OpenSSL 1.1 vs 3 soname | Use the RPM matching the target major version |
| jammy deb won't install on noble/resolute | `libgnutls30` vs `libgnutls30t64` package name | Use the deb matching the target release |
| Targets are AlmaLinux, not Rocky | Swap `rockylinux/rockylinux:X` → `almalinux:X` and `rocky-indexhtml` → `almalinux-indexhtml`; both provide `redhat-indexhtml` |

---

## 7. Why these extras (dependency notes)

Lynx's declared dependencies are mostly libraries the base image already has. `apt-get --download-only` / `dnf --downloadonly` skip those, so the kit is complete relative to that image, not relative to an empty rootfs. Confirmed against `ubuntu:22.04`, `ubuntu:24.04`, `ubuntu:26.04`, and `rockylinux/rockylinux:8/9/10` on 2026-11-13, and against `dnf repoquery --requires lynx`.

| Target | Already in the base image, and required | Carried because they are missing or would be skipped |
|---|---|---|
| Ubuntu 22.04 | libc6, libncursesw6, libtinfo6, libgnutls30, libidn2-0, libbz2-1.0, zlib1g, libgmp10 | `libbsd0` and `libmd0` (jammy's amd64 lynx depends on `libbsd0`; the image has neither) |
| Ubuntu 24.04 | libc6, libncursesw6, libtinfo6, libgnutls30t64, libidn2-0, libbz2-1.0, zlib1g, libgmp10, libmd0 | `libbrotli1`. amd64 noble lynx does not depend on `libbsd0` |
| Ubuntu 26.04 | libc6, libncursesw6, libtinfo6, libbz2-1.0, zlib1g, libgmp10, libbsd0, libmd0 | `libbrotli1`, `libgnutls30t64`, `libidn2-0`, and the gnutls chain (`libffi8`, hogweed, nettle, p11-kit, tasn1, unistring). amd64 resolute lynx does not link `libbsd0`; the image happens to contain it. `libgmp10` is a real gnutls dependency and is **not** in the kit |
| EL8 (Rocky) | glibc, openssl-libs 1.1, ncurses-libs, zlib. Image also has `bzip2-libs` and `libidn2`, which this lynx does not link | `lynx` (PowerTools) and `rocky-indexhtml` |
| EL9 (Rocky) | glibc, openssl-libs 3, ncurses-libs, zlib, `libidn2` (linked, so it is force-fetched), `bzip2-libs` (not linked) | `lynx`, `rocky-indexhtml`, `libidn2` |
| EL10 (Rocky) | glibc, openssl-libs 3, ncurses-libs, zlib, `libidn2`, `bzip2-libs` (both linked, so both are force-fetched) | `lynx`, `rocky-indexhtml`, `libbrotli`, `libidn2`, `bzip2-libs` |

`dnf install --downloadonly` does not download a package the container already has. `dnf reinstall --downloadonly` is what puts `libidn2` (EL9/EL10) and `bzip2-libs` (EL10) into the kit. A target that lacks a library listed as "already in the base image" (`libgmp10` on Ubuntu 26.04, `openssl-libs`, ncurses, zlib) still fails `ldd` after a clean package install.

---

## 8. Maintenance / recurring update guide

Refresh the kit periodically (quarterly is a good cadence) and whenever a target distro ships a security update for Lynx or a new upstream release appears. The scripts are idempotent: re-running them pulls the current versions.

### 8.1 When to update
- **Quarterly**, or when any of these changes:
  - A distro security update for `lynx` (Ubuntu security notices / Rocky advisories).
  - A new upstream Lynx release (lynx.invisible-island.net) or ELinks release (github.com/rkd77/elinks/releases).
  - A target release is added (e.g. Ubuntu 28.04, Rocky 11) or an old one reaches EOL.
  - A dependency transition (OpenSSL soname bump, `t64` package rename, glibc bump).

### 8.2 Update procedure
1. **Snapshot the current kit**: copy `offline-browsers/` to `offline-browsers-<YYYY-MM-DD>/` (rollback point).
2. **Check for new versions** (optional, no downloads): `bash check-updates.sh`.
3. **Re-run prep**: `bash prep.sh` — pulls current versions, regenerates `SHA256SUMS`.
4. **Diff the inventory**: compare file list / versions / sizes against the snapshot; investigate any added or removed dependency package.
5. **Re-run the offline tests**: `bash test.sh` — require 7/7 pass.
6. **Update the records**: refresh the §1 inventory and add a changelog line (§8.4).
7. **Deploy**: replace the kit on the target; keep the previous snapshot until the new kit is confirmed.

### 8.3 `check-updates.sh` (optional helper)
```bash
#!/usr/bin/env bash
# Report the latest available versions per target without downloading anything.
set -uo pipefail

echo "== Ubuntu (apt candidate) =="
for rel in jammy:22.04 noble:24.04 resolute:26.04; do
  tag="${rel##*:}"
  printf '  ubuntu:%s  ' "$tag"
  docker run --rm "ubuntu:$tag" bash -c \
    'apt-get update -qq >/dev/null 2>&1; apt-cache policy lynx | awk "/Candidate:/{print \$2}"'
done

echo "== EL (dnf available) =="
for v in 8 9 10; do
  printf '  rockylinux:%s  ' "$v"
  # EL8 lynx is in PowerTools. BaseOS and AppStream have no lynx package.
  extra=""; [ "$v" = "8" ] && extra="--enablerepo=powertools"
  docker run --rm "rockylinux/rockylinux:$v" bash -c \
    "dnf -q -y $extra list available lynx 2>/dev/null | awk '/lynx.x86_64/{print \$2}' | head -1"
done

echo "== ELinks (GitHub latest release) =="
curl -fsSL https://api.github.com/repos/rkd77/elinks/releases/latest \
  | sed -n 's/.*"tag_name": *"\([^"]*\)".*/  \1/p'
```

### 8.4 Changelog
| Date | Trigger | Ubuntu 22.04 | Ubuntu 24.04 | Ubuntu 26.04 | EL8 | EL9 | EL10 | ELinks | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 2026-11-12 | Initial build (AlmaLinux) | 2.9.0dev.10-1 | 2.9.0rel.0-2build2 | 2.9.2-2 | 2.8.9-4 | 2.8.9-20 | 2.9.0-6 | 0.20.0 | Validated 7/7 offline |
| 2026-11-12 | Switched EL to Rocky Linux | 2.9.0dev.10-1 | 2.9.0rel.0-2build2 | 2.9.2-2 | 2.8.9-4 | 2.8.9-20 | 2.9.0-6 | 0.20.0 | `rocky-indexhtml`; validated 7/7 offline |
| 2026-11-13 | Image and repoquery check; kit not rebuilt | 2.9.0dev.10-1 | 2.9.0rel.0-2build2 | 2.9.2-2 | 2.8.9-4 | 2.8.9-20 | 2.9.0-6 | 0.20.0 | ELinks extract is `-C /`. Drop unused EL8 `bzip2-libs`/`libidn2` and EL9 `bzip2-libs` from `prep.sh`. Relative `SHA256SUMS`. Rocky 10 is x86-64-v3 |

### 8.5 EOL / transition watch list
- Ubuntu standard support: 22.04 → 2027-04, 24.04 → 2029-04, 26.04 → 2031-04 (ESM extends each by ~5 years).
- Rocky Linux: 8 security updates through 2029-05 (active support ended 2024-05-31), 9 through 2032-05, 10 through 2035-05. Rocky 10 is x86-64-v3.
- Dependency transitions to watch: `t64` package renames (Ubuntu 24.04+), OpenSSL soname bumps (Lynx 2.9.3 already supports OpenSSL 3 and 4), glibc bumps (older-built packages still run on newer glibc, not vice versa).

### 8.6 Maintenance checklist
- [ ] Snapshot current kit (`offline-browsers-<date>/`)
- [ ] Run `check-updates.sh`; note new versions
- [ ] Run `prep.sh`
- [ ] Diff inventory vs snapshot
- [ ] Run `test.sh` — require 7/7
- [ ] Update §1 inventory + changelog
- [ ] Deploy new kit, keep the old snapshot
- [ ] Prune Docker images/scratch (§9)

---

## 9. Cleanup after testing (validation host)

```bash
docker system prune -af --volumes   # remove all images, containers, volumes, build cache
rm -rf ~/offline-browsers            # remove scratch kit (keep the runbook + scripts if needed)
```
