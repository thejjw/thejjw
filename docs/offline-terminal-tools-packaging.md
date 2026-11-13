# Offline Terminal Tools Kit for Rocky EL8/9/10

Preparation and test plan for carrying common **terminal (CLI) tools** onto air-gapped
Rocky Linux 8/9/10 systems installed from a minimal image.

This is a separate document from the browser kit (`offline-browser-packaging.md`).

---

## 1. Purpose and scope

- **Goal**: a self-contained RPM kit that adds the terminal tools a minimal Rocky install
  lacks, small enough to carry on a CD-ROM (< 700 MB).
- **Baseline**: the default tags `rockylinux/rockylinux:8`, `:9`, and `:10`. These are not
  the `-minimal` tags. Checked 2026-11-13: `:8` is 8.10
  (`sha256:e8a49c5403b687db05d4d67333fa45808fbe74f36e683cec7abb1f7d0f2338c6`), `:9` is 9.8
  (`sha256:8101994123cf3d0a8fee517bee7f39e555c7d92bd2d9eb3303cc988a0eeed00f`), `:10` is 10.2
  (`sha256:827d37bc128288ccf160ee318bb3cb92d591164cb217e92f8bc61e3982ae1834`).
  Rocky 10 userspace is x86-64-v3.
- **Not a development machine**: the compiler toolchain and the other language runtimes are
  deliberately **excluded**. `subversion`, `ruby`, and the `gcc` toolchain are not in
  the kit. `git` is not in the base image either; the kit carries it (see §3). `perl` is
  not in the base image; the kit carries `perl-interpreter` (see §3), which is also what
  `perf` and `git` require.
  EL10 `perf` also links `libpython3.12`, which the EL10 image already has via `python3`.
- **Measured size** of the 2026-11-12 kit, dependencies included. §5 has since dropped `iputils` and `hostname` on every release, dropped `findutils` on EL9/EL10, and added the `openssl` CLI package on EL8 and EL10, `git` and `sqlite` on every release, and `age` on EL9/EL10. `perl-interpreter` was already in that measurement because `perf` requires it. The other size changes have not been re-measured:

  | Distro | Size | RPMs |
  |--------|------|------|
  | EL8    | 82 MB | 161 |
  | EL9    | 86 MB | 190 |
  | EL10   | 128 MB | 198 |

---

## 2. What the base image already has

Present on all three default images (no RPM is downloaded for these, because
`dnf --downloadonly` skips installed packages):

`gzip`, `tar`, `less`, `more`, `curl`, `ping`, `tracepath`, `lsblk`, `fsck`,
`timeout`, `nohup`, `setsid`, `flock`, `ldd`, `rpm`, `dnf`, `vi`, `hostname`, `sed`.

`ping` and `tracepath` are both from the installed `iputils` package. `vi` is present
and `vim` is not. `hostname` is the `hostname` package. `xz-libs`, `bzip2-libs`, and
`libidn2` are installed; the `xz` and `bzip2` commands are not, so those CLI packages
stay in the kit.

| | EL8 (8.10) | EL9 (9.8) | EL10 (10.2) |
|---|---|---|---|
| `gpg` | yes (`gnupg2`) | yes (`gnupg2`) | no |
| `openssl` command | no (`openssl-libs` only) | yes | no (`openssl-libs` only) |
| `python3` on `PATH` | no; `/usr/libexec/platform-python` is 3.6 | yes (3.9) | yes (3.12) |
| `find` | no | yes (`findutils`) | yes (`findutils`) |
| `dbus-libs` | installed | not installed | not installed |
| `libevent` | not installed | installed | installed |
| `systemd` package | installed | not installed | not installed |

`command -v` after install cannot tell an image-provided tool from a kit-provided one.
§7 checks RPM names for the packages the kit is supposed to carry.

Keep this kit in its own directory. It uses the same `el/el8` layout as the browser kit,
and mixing the RPM sets makes `dnf install /pkgs/*.rpm` install both.

---

## 3. sed, perl, git, sqlite, and age

Checked on the same three images as §2. `sed` is already installed. `perl`, `git`, `sqlite3`, and `age` are not. A normal Rocky minimal install does not include `git` either: it is an AppStream package, not part of the base image.

`sed` comes from the `sed` package in BaseOS. Nothing to add to the kit.

| Release | Package | RPM size | Installed size |
|---|---|---|---|
| EL8 | `sed-4.5-5.el8` | 773 KB | 765 KB |
| EL9 | `sed-4.8-10.el9_8` | 821 KB | 812 KB |
| EL10 | `sed-4.9-5.el10` | 886 KB | 878 KB |

`/usr/bin/perl` is the `perl-interpreter` package. It is not on any of the three images. `dnf install --downloadonly --setopt=install_weak_deps=False perl-interpreter` pulls the interpreter, `perl-libs`, the small dual-life modules those require, `groff-base`, and the `ncurses` package (used by `perldoc`). On EL8 that closure also pulls the `openssl` CLI, which the kit already carries for EL8. Sizes below are that closure, measured 2026-11-13.

| Release | perl | RPMs | Kit (compressed RPMs) | Installed |
|---|---|---|---|---|
| EL8 | 5.26.3 | 44 | 14.9 MB | 42.8 MB |
| EL9 | 5.32.1 | 59 | 8.6 MB | — |
| EL10 | 5.40.2 | 60 | 8.3 MB | — |

Installed size for EL9 and EL10 was not measured. The kit column is the sum of the RPM files.

`perf` requires `/usr/bin/perl`, so a kit that still contains `perf` already downloads this closure. Listing `perl-interpreter` in §5 keeps `perl` when `perf` is removed, and it does not add a second copy while `perf` stays. The EL10 size jump in §1 is `llvm-libs` from `perf`, not perl.

The `perl` metapackage is the distro's packaged module set, still with weak dependencies off:

| Release | RPMs | Kit (compressed RPMs) | Installed |
|---|---|---|---|
| EL8 | 162 | 28.3 MB | 81.6 MB |
| EL9 | 263 | 125 MB | — |
| EL10 | 263 | 109 MB | — |

The kit does not carry that metapackage. `perl-interpreter` is enough for one-liners, for `perf`, and for `git`.

`git` is AppStream. On these images `dnf --downloadonly --setopt=install_weak_deps=False git` resolves to:

| Release | git | RPMs | Kit (compressed RPMs) | Installed |
|---|---|---|---|---|
| EL8 | 2.43.7 | 54 | 31.4 MB | 95.9 MB |
| EL9 | 2.52.0 | 72 | 18.5 MB | 81.2 MB |
| EL10 | 2.52.0 | 72 | 18.6 MB | 74.0 MB |

Most of that closure is `perl-interpreter` and `openssh-clients`, which the kit already carries, so those RPMs are not stored twice. The packages added by naming `git` are `git`, `git-core` (EL8 11.6 MB, EL9 5.2 MB, EL10 5.4 MB), `git-core-doc` (about 3 MB), `libedit`, and the OpenSSH server package `openssh`. EL8 also pulls `emacs-filesystem` (72 KB).

`sqlite3` is the `sqlite` package. The images already have an older `sqlite-libs`, and the command package requires the matching library release, so `dnf --downloadonly sqlite` fetches both RPMs. Measured 2026-11-13:

| Release | sqlite | Repo | Added RPMs | Kit | Installed command |
|---|---|---|---|---|---|
| EL8 | 3.26.0-21.el8_10 | BaseOS | `sqlite` 684 KB + `sqlite-libs` 594 KB | 1.28 MB | 1.35 MB |
| EL9 | 3.34.1-11.el9_8 | AppStream | `sqlite` 776 KB + `sqlite-libs` 659 KB | 1.44 MB | 1.61 MB |
| EL10 | 3.46.1-6.el10_2 | AppStream | `sqlite` 911 KB + `sqlite-libs` 762 KB | 1.67 MB | 1.88 MB |

`age` is one EPEL package, version 1.3.1, with no further dependencies. EL8 has no `age` package in Rocky or EPEL. The upstream `age-v1.3.1-linux-amd64.tar.gz` is 10.3 MB if an EL8 binary is needed later; the kit does not carry it.

| Release | Kit | Installed |
|---|---|---|
| EL9 | 2.57 MB | 11.2 MB |
| EL10 | 2.43 MB | 10.2 MB |

---

## 4. Notable missing tools

Package names and sizes are from EL9 unless the row names a release. "Repo" is the repository
the package comes from (`baseos`/`appstream` are always enabled; `epel` needs EPEL).

### Compression and archives

| Command(s) | Package | Size | Repo |
|-------------|---------|------|------|
| `xz`, `unxz`, `xzcat` | `xz` | 219 KB | baseos |
| `bzip2`, `bunzip2` | `bzip2` | 52 KB | baseos |
| `zstd`, `unzstd` | `zstd` | 473 KB | baseos |
| `lz4` | `lz4` | 59 KB | baseos |
| `zip` | `zip` | 269 KB | baseos |
| `unzip` | `unzip` | 184 KB | baseos |
| `cpio` | `cpio` | 277 KB | baseos |
| `7z` (`7za` on EL8 only) | `7zip` (EL9/10) / `p7zip-plugins` (EL8) | 1.25 MB | epel |

EPEL 9 and EPEL 10 `7zip` (currently `7zip-26.04`) installs `/usr/bin/7z` and provides `p7zip-plugins`. It does not install `7za`. On EL8, `p7zip-plugins` pulls `p7zip`, which does install `7za`.

### Editors

| Command(s) | Package | Size | Repo |
|-------------|---------|------|------|
| `vim` | `vim-enhanced` | 1.83 MB | appstream |
| `nano` | `nano` | 708 KB | baseos |
| `ed` | `ed` | 75 KB | baseos |

### Text and data

| Command(s) | Package | Size | Repo |
|-------------|---------|------|------|
| `jq` | `jq` | 191 KB | baseos |
| `tree` | `tree` | 56 KB | baseos |
| `yq` | `yq` | 5.0 MB | epel (EL9/10 only) |
| `most` | `most` | 65 KB | epel |

### Networking

| Command(s) | Package | Size | Repo |
|-------------|---------|------|------|
| `wget` | `wget` | 785 KB | appstream |
| `ssh`, `scp`, `sftp`, `ssh-keygen`, `ssh-agent`, `ssh-add` | `openssh-clients` | 787 KB | baseos |
| `rsync` | `rsync` | 419 KB | baseos |
| `nc` | `nmap-ncat` | 227 KB | appstream |
| `nmap` | `nmap` | 5.7 MB | appstream |
| `telnet` | `telnet` | 65 KB | appstream |
| `socat` | `socat` | 306 KB | appstream |
| `netstat`, `arp`, `route` | `net-tools` | 301 KB | baseos |
| `ip`, `ss` | `iproute` | 858 KB | baseos |
| `dig`, `host`, `nslookup` | `bind-utils` | 204 KB | appstream |
| `traceroute` | `traceroute` | 58 KB | baseos |
| `mtr` | `mtr` | 88 KB | baseos |
| `iperf3` | `iperf3` | 109 KB | appstream |
| `tcpdump` | `tcpdump` | 555 KB | appstream |
| `ftp` | `ftp` | 63 KB | appstream |
| `lftp` | `lftp` | 931 KB | appstream |
| `aria2c` | `aria2` | 1.30 MB | epel |
| `whois` | `whois` | 77 KB | appstream |
| `iftop` | `iftop` | 53 KB | epel |
| `mosh` | `mosh` | 253 KB | epel |

### Monitoring and processes

| Command(s) | Package | Size | Repo |
|-------------|---------|------|------|
| `top`, `ps`, `free`, `vmstat`, `watch`, `pgrep`, `pkill`, `pidof`, `uptime`, `w` | `procps-ng` | 340 KB | baseos |
| `iostat`, `mpstat`, `sar` | `sysstat` | 474 KB | appstream |
| `htop` | `htop` | 202 KB | epel |
| `iotop` | `iotop-c` | 90 KB | epel; BaseOS on EL10 |
| `lsof` | `lsof` | 244 KB | baseos |
| `pstree`, `fuser` | `psmisc` | 232 KB | baseos |
| `screen` | `screen` | 665 KB | epel |
| `tmux` | `tmux` | 486 KB | baseos |
| `at` | `at` | 61 KB | baseos |

### Diagnostics and hardware

| Command(s) | Package | Size | Repo |
|-------------|---------|------|------|
| `strace` | `strace` | 1.57 MB | baseos |
| `ltrace` | `ltrace` | 140 KB | appstream |
| `gdb` | `gdb` (+ `gdb-headless`) | 143 KB + 5.28 MB | appstream |
| `perf` | `perf` | 3.42 MB | appstream |
| `dmidecode` | `dmidecode` | 103 KB | baseos |
| `lshw` | `lshw` | 336 KB | baseos |
| `hdparm` | `hdparm` | 98 KB | baseos |
| `smartctl` | `smartmontools` | 563 KB | baseos |
| `mdadm` | `mdadm` | 446 KB | baseos |
| `parted` | `parted` | 589 KB | baseos |
| `gdisk` | `gdisk` | 248 KB | appstream |

### Miscellaneous

| Command(s) | Package | Size | Repo |
|-------------|---------|------|------|
| `sudo` | `sudo` | 1.37 MB | baseos |
| `man` | `man-db` | 1.17 MB | baseos |
| `info` | `info` | 229 KB | baseos |
| `which` | `which` | 41 KB | baseos |
| `file` | `file` | 49 KB | baseos |
| `bc` | `bc` | 121 KB | baseos |
| `units` | `units` | 288 KB | baseos |
| `getfacl`, `setfacl` | `acl` | 71 KB | baseos |
| `dos2unix` | `dos2unix` | 241 KB | baseos |
| `expect` | `expect` | 251 KB | appstream |
| `dialog` | `dialog` | 245 KB | appstream |
| `pv` | `pv` | 67 KB | epel |
| `parallel` | `parallel` | 465 KB | epel |
| `gpg` (EL10 only) | `gnupg2` | 2.60 MB | baseos |
| `openssl` (EL8 and EL10) | `openssl` | — | baseos |
| `find` (EL8 only) | `findutils` | 549 KB | baseos |

---

## 5. Recommended kit

The kit is the union of the packages above plus their dependencies. The full package list
used by `prep.sh`:

```
procps-ng sysstat psmisc iproute net-tools bind-utils
xz bzip2 zip unzip cpio zstd lz4
vim-enhanced nano jq tree
wget rsync openssh-clients sudo man-db which file lsof strace
bc acl dos2unix traceroute mtr telnet ftp socat tcpdump nmap-ncat iperf3 tmux at dmidecode hdparm parted gdisk whois ltrace expect dialog units
htop iotop-c screen smartmontools lshw mdadm gdb perf nmap lftp pv parallel aria2 most mosh iftop
perl-interpreter git sqlite
```

Not in this list, because the base image already has them: `iputils` (`ping`, `tracepath`), `hostname`, and on EL9/EL10 `findutils`. `dbus-libs` is not named either; on current EL9 and EL10 it arrives as a `sysstat` dependency.

Per-distro additions:

- **EL8**: `p7zip-plugins` (no `7zip` or `yq` package), `findutils`, `openssl` (CLI; `openssl-libs` is already installed), and `--enablerepo=powertools`.
- **EL9/EL10**: `yq`, `7zip`, `age`. EL8 has no `age` package.
- **EL10**: `gnupg2` and `openssl`.

### Why these packages

- **EPEL** provides: `7zip`, `yq`, `most`, `aria2`, `iftop`, `mosh`, `htop`,
  `screen`, `pv`, `parallel`, and on EL9/EL10 `age`. `iotop-c` is EPEL on EL8/EL9 and BaseOS on EL10.
- **PowerTools** on EL8 is disabled by default. The prep script enables it so a
  dependency that lives there still resolves. EL8 `lynx` is in PowerTools too, but
  Lynx is the browser kit, not this one.
- **`sysstat` on EL8** does not link PCP. A `--downloadonly` of `sysstat` on the 8.10
  image fetched `sysstat`, `findutils`, `lm_sensors-libs`, and `xz`.
- **`sysstat` on EL9** does link PCP. The same command on the 9.8 image fetched
  `sysstat`, `pcp-libs`, `pcp-conf`, `avahi-libs`, `dbus`, `dbus-libs`, `dbus-broker`,
  `dbus-common`, `systemd`, `systemd-pam`, `systemd-rpm-macros`, `libuv`,
  `libseccomp`, `kmod-libs`, `lm_sensors-libs`, `acl`, and `xz`. `dbus-libs` was in
  that set. A second download pass is not required, and it can drop a second NEVRA
  of the same package if the mirror moves between the two containers.
- **`sysstat` on EL10** fetched `sysstat`, `pcp-libs`, `pcp-conf`, `avahi-libs`,
  `dbus-libs`, `libuv`, `lm_sensors-libs`, and `xz`. It did not pull the `systemd`
  package. `libevent`, which `avahi-libs` also requires, is already in the EL9 and
  EL10 images, so it is not in the kit.
- **`perf`** requires `/usr/bin/perl`. That dependency is the `perl-interpreter` closure in §3, about 8–15 MB of RPMs depending on the release, not the `perl` metapackage. Drop `perf` to remove `llvm-libs` on EL10; leave `perl-interpreter` in the list if perl should stay. On EL10, `perf` also requires `libLLVM.so.19.1` (the `llvm-libs` package, the main reason that kit is larger) plus babeltrace, libbpf, numactl, slang, and elfutils. EL10 `perf` links `libpython3.12`, which the image already provides.

---

## 6. Preparation

Run on a host with Docker and internet access. It downloads the RPMs into
`el/el8`, `el/el9`, `el/el10`.

```bash
#!/usr/bin/env bash
# Prepare an offline terminal-tools kit for minimal Rocky EL8/9/10.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$ROOT"/el/{el8,el9,el10} "$ROOT/tests"

# Common terminal tools (package names). Compiler/dev tools are deliberately excluded.
# iputils, hostname, and (on EL9/EL10) findutils are already in the base image.
common="procps-ng sysstat psmisc iproute net-tools bind-utils xz bzip2 zip unzip cpio zstd lz4 vim-enhanced nano jq tree wget rsync openssh-clients sudo man-db which file lsof strace bc acl dos2unix traceroute mtr telnet ftp socat tcpdump nmap-ncat iperf3 tmux at dmidecode hdparm parted gdisk whois ltrace expect dialog units htop iotop-c screen smartmontools lshw mdadm gdb perf nmap lftp pv parallel aria2 most mosh iftop perl-interpreter git sqlite"

for v in 8 9 10; do
  extra=""
  repo_opt=""
  if [ "$v" = "8" ]; then
    extra="p7zip-plugins findutils openssl"   # no 7zip/yq; image lacks find and the openssl CLI
    repo_opt="--enablerepo=powertools"
  else
    extra="yq 7zip age"
  fi
  [ "$v" = "10" ] && extra="$extra gnupg2 openssl"   # EL10 image lacks gpg and the openssl CLI
  echo "-- downloading el$v --"
  docker run --rm -v "$ROOT/el/el$v:/out" "rockylinux/rockylinux:$v" bash -c "
    set -e
    dnf install -y -q https://dl.fedoraproject.org/pub/epel/epel-release-latest-$v.noarch.rpm >/dev/null 2>&1
    dnf install -y -q $repo_opt --downloadonly --downloaddir=/out --setopt=install_weak_deps=False $common $extra
  "
done

echo "=== checksums + inventory ==="
# Relative paths, so sha256sum -c works from the kit root on the target.
(
  cd "$ROOT"
  find . -type f -name '*.rpm' -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)
for v in 8 9 10; do
  printf 'el%s: %s, %s files\n' "$v" "$(du -sh "$ROOT/el/el$v" | cut -f1)" "$(ls "$ROOT/el/el$v"/*.rpm | wc -l)"
done
```

### Notes

- **EPEL is required** at prepare time (not at install time). The RPMs are self-contained.
- **`--setopt=install_weak_deps=False`** keeps recommended packages out of the kit.
- **`dbus-libs`**: on the 9.8 and 10.2 images it is not installed, and the `sysstat`
  transaction downloads it. On the 8.10 image it is already installed, and EL8
  `sysstat` does not need Avahi, so the EL8 kit will not contain `dbus-libs`.
  Do not add a second `dnf install --downloadonly dbus-libs` pass. On EL8 that
  pass downloads nothing; if the repo changes between two passes it can leave two
  versions of one package, which `dnf install /pkgs/*.rpm` then refuses.
- **`SHA256SUMS`** uses paths relative to the kit root. Run `sha256sum -c` from that directory.

---

## 7. Test plan

Run on the prepare host. It installs the kit into clean containers with **no network**
(`--network none`) and verifies every tool is present.

```bash
#!/usr/bin/env bash
# Test the offline terminal-tools kit in clean containers with NO network.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$ROOT/tests"
pass=0; fail=0
report() { if [ "$1" -eq 0 ]; then echo "PASS: $2"; pass=$((pass+1)); else echo "FAIL: $2"; fail=$((fail+1)); fi; }

# Install-check script, mounted into the container (avoids nested-quoting issues).
cat > "$ROOT/tests/install-check.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -e
v="$1"
dnf install -y --disablerepo='*' /pkgs/*.rpm
# command -v cannot see that ping, hostname, and (on EL9/EL10) find come from the
# image rather than from /pkgs. Require the RPMs this kit claims to add.
names=$(rpm -qp --queryformat '%{NAME}\n' /pkgs/*.rpm)
require_rpm() { echo "$names" | grep -qx "$1" || { echo "RPM NOT IN KIT: $1"; exit 1; }; }
for p in xz bzip2 vim-enhanced jq wget htop nmap gdb procps-ng perl-interpreter git sqlite; do require_rpm "$p"; done
[ "$v" = "8" ] && for p in findutils openssl p7zip-plugins; do require_rpm "$p"; done
[ "$v" != "8" ] && for p in yq 7zip dbus-libs age; do require_rpm "$p"; done
[ "$v" = "10" ] && for p in gnupg2 openssl; do require_rpm "$p"; done
common_cmds="xz bzip2 zstd zip unzip cpio vim nano jq tree wget rsync ssh scp sudo man which file lsof strace bc dos2unix find hostname traceroute mtr telnet ftp socat tcpdump nc iperf3 tmux at dmidecode hdparm parted gdisk whois ltrace expect dialog units htop iotop screen smartctl lshw mdadm gdb perf nmap lftp pv parallel aria2c most mosh iftop gpg top ps free iostat sar ss ip netstat dig ping openssl perl sed git sqlite3"
extra=""
[ "$v" = "8" ] && extra="7z"
[ "$v" != "8" ] && extra="7z yq age"
for c in $common_cmds $extra; do
  command -v "$c" >/dev/null 2>&1 || { echo "MISSING: $c"; exit 1; }
done
echo "all tools present"
SCRIPT

for v in 8 9 10; do
  echo "===== EL$v ====="
  docker run --rm --network none \
    -v "$ROOT/el/el$v:/pkgs:ro" -v "$ROOT/tests:/tests:ro" \
    "rockylinux/rockylinux:$v" bash /tests/install-check.sh "$v" \
    > "$ROOT/tests/el$v.log" 2>&1
  report $? "rockylinux:$v offline install"
  tail -3 "$ROOT/tests/el$v.log"
done

echo
echo "===== SUMMARY: $pass passed, $fail failed ====="
[ "$fail" -eq 0 ]
```

### Expected result

```
===== EL8 =====
PASS: rockylinux:8 offline install
all tools present
===== EL9 =====
PASS: rockylinux:9 offline install
all tools present
===== EL10 =====
PASS: rockylinux:10 offline install
all tools present
===== SUMMARY: 3 passed, 0 failed =====
```

### What the test proves

1. The kit is **self-contained** for this image: `dnf install --disablerepo='*'` resolves every dependency from the local RPMs plus what that image already has.
2. The install works with **no network** (`--network none`).
3. Every notable tool's binary is on `PATH` after install.
4. Named RPMs are actually in `/pkgs`. `ping`, `tracepath`, `hostname`, and on EL9/EL10 `find` are on `PATH` because the image already has them. `dbus-libs` must be in the EL9 and EL10 kits. `libevent` is not in the kit; EL9 and EL10 images already have it, and `avahi-libs` needs it.

---

## 8. Deployment on the target

Copy the RPM directory for the target's major version to the air-gapped host, then:

```bash
# from the kit root; SHA256SUMS paths are relative
sha256sum -c SHA256SUMS

# install everything from the local RPMs only
dnf install -y --disablerepo='*' /path/to/el9/*.rpm
```

If the target already has some packages, `dnf` will skip them. To force a clean install,
boot a rescue environment or use `rpm -Uvh --force` (not recommended on a live system).

---

## 9. Maintenance

To refresh the kit when new package versions are released:

1. Re-run `prep.sh` (it always downloads the latest versions from the enabled repos).
2. Re-run `test.sh` to confirm the new kit still installs cleanly offline.
3. Copy the new `SHA256SUMS` and RPM directories to the air-gapped host.

Notes for recurring updates:

- **EPEL version**: `prep.sh` installs `epel-release-latest-$v` automatically, so it always
  targets the current EPEL for that major version.
- **Repo state**: the kit contents depend on the image digest and on the repos enabled at prepare time (`baseos`, `appstream`, `epel`, and `powertools` on EL8). Record the date, the image digest, and the repo state with each kit.
- **Size drift**: EL10's `perf` -> `llvm-libs` (~32 MB) is the main size driver. If the kit
  grows past the media budget, drop `perf` (and note that `perf` is unavailable).

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `nothing provides libdbus-1.so.3 needed by avahi-libs` | `dbus-libs` missing. On 9.8 and 10.2 the `sysstat` transaction already downloads it. An older resolver, or a second pass that was deleted, can omit it | `dnf download --downloaddir=/out dbus-libs`, and delete any older `dbus-libs-*.rpm` first |
| `nothing provides libevent-2.1.so.7 needed by avahi-libs` | EL9/EL10 images already have `libevent`, so the kit does not carry it | Install the distro `libevent` package, or add it with `dnf reinstall --downloadonly libevent` if the target lacks it |
| `cannot install both xz-...el9_0 and xz-...el9_8.1` | two NEVRAs of one package, often from a second download pass | Keep one file per package name. `prep.sh` now does a single download pass |
| `No match to arguments: yq` / `7zip` on EL8 | those package names do not exist on EL8 | use `p7zip-plugins`; `yq` is EL9/10 only |
| `MISSING: gpg` or `MISSING: openssl` on EL8/EL10 | those images have no `gpg` (EL10) or `openssl` CLI (EL8 and EL10) | the kit adds `gnupg2` on EL10 and `openssl` on EL8 and EL10 |
| `find` missing on an EL9/EL10 target that is thinner than the container | `findutils` is already in those images, so `dnf --downloadonly` does not put it in the kit | Add `findutils` to that release's `extra` list, or `dnf reinstall --downloadonly findutils` |
| `Unable to find a match` for an EPEL package | EPEL not enabled at prepare time | install `epel-release-latest-$v` first (done by `prep.sh`) |
| Kit too large for media | `perf` / `llvm-libs` on EL10 | drop `perf` from the `common` list |
