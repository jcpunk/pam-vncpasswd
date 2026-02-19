# pam-vncpasswd

PAM module and password management tool for VNC authentication using
proper crypt(3) hashing.

## Motivation

RHEL10 drops X.org; VNC servers must use Wayland. Weston + NeatVNC
authenticates via PAM, but many site accounts are Kerberos-only group
accounts with no local password hash (`/etc/shadow` entry is `!` or `*`).

This project provides:

- **`pam_fnal_vncpasswd.so`** — a PAM module that authenticates against a
  per-user VNC password file (`~/.config/vnc/fnal_vncpasswd`)
- **`fnal-vncpasswd`** — a CLI tool for users to set their VNC-specific
  password

The approach is inspired by [art-daq/artdaq#275](https://github.com/art-daq/artdaq/pull/275)
but uses proper `crypt(3)` hashing instead of TigerVNC's 8-byte
bit-reversal obfuscation.

## Algorithm Support

| ENCRYPT_METHOD | Salt prefix | Cost parameter |
|---|---|---|
| `YESCRYPT` (RHEL default) | `$y$` | `YESCRYPT_COST_FACTOR` (default 5) |
| `SHA512` | `$6$` | `SHA_CRYPT_MAX_ROUNDS` (default 65536) |
| `SHA256` | `$5$` | `SHA_CRYPT_MAX_ROUNDS` (default 65536) |
| `BLOWFISH`/`BCRYPT` | `$2b$` | log₂(rounds)=12 |
| `MD5` | `$1$` | — |

**Important**: yescrypt uses a *cost factor* (default 5, configured via
`YESCRYPT_COST_FACTOR`), not a round count. The cost is encoded by
`crypt_gensalt_ra(3)` into a parameter string (e.g., `j9T` for cost=5).
This is fundamentally different from SHA-crypt's `rounds=N$` syntax.
Do not set `YESCRYPT_COST_FACTOR` to 65536 — that is a SHA-crypt value.

The module reads `/etc/login.defs` at runtime, so no rebuild is needed
when changing the algorithm.

## Security Design

1. **`crypt_gensalt_ra(3)`** for algorithm-aware, secure salt generation
2. **`crypt_r(3)`** for thread-safe hashing
3. **`O_NOFOLLOW` + `fstat(2)`** for TOCTOU-safe file validation:
   - Prevents symlink attacks
   - Verifies file ownership (must match user's UID)
   - Rejects world/group-readable files (must be 0600 or stricter)
4. **Constant-time XOR comparison** to prevent timing side-channels
5. **`explicit_bzero(3)`** on all sensitive buffers (passwords, hashes, salts)
6. **Atomic writes**: `mkstemp` → `fchmod(0600)` → write → `fsync` → `rename`
7. **`mlock(2)`** to prevent password pages from swapping to disk
   (non-fatal if unsupported)

## Build

Requirements: `cmake >= 3.21`, `gcc`, `libpam-devel`, `libxcrypt-devel`,
`asciidoctor` (or `asciidoc`), optionally `lcov`.

```sh
git clone https://github.com/jcpunk/pam-vncpasswd
cd pam-vncpasswd
mkdir build && cd build
cmake -DBUILD_TESTING=ON ..
make
ctest --output-on-failure
```

### Configuration Variables

| Variable | Default | Description |
|---|---|---|
| `LOGIN_DEFS_PATH` | `/etc/login.defs` | Path to login.defs |
| `DEFAULT_ENCRYPT_METHOD` | `SHA512` | Fallback if login.defs unset |
| `DEFAULT_YESCRYPT_COST` | `5` | Fallback yescrypt cost factor |
| `DEFAULT_SHA_CRYPT_ROUNDS` | `65536` | Fallback SHA-crypt rounds |
| `VNC_PASSWD_DIR` | `.config/vnc` | Subdirectory under `$HOME` |
| `VNC_PASSWD_FILE` | `fnal_vncpasswd` | Password filename in `VNC_PASSWD_DIR` |
| `MIN_PASSWORD_LENGTH` | `8` | Minimum password length in fnal-vncpasswd |
| `PAM_MODULE_DIR` | system default | Where to install `pam_fnal_vncpasswd.so` |

## Usage

### Setting a VNC Password

```sh
# Interactive (prompts twice)
fnal-vncpasswd

# Non-interactive (from script or Ansible)
echo 'MyVNCpassword' | fnal-vncpasswd -n

# Write to custom location
fnal-vncpasswd -f /etc/vnc/myaccount.passwd
```

### PAM Configuration

PAM control flags determine how modules are combined:

- `sufficient` — if this module succeeds (and no earlier `required` has
  failed) authentication is immediately granted; if it fails, the next
  module is tried.
- `required` — the module must succeed; a failure is remembered but
  processing continues to the end before the overall result is returned.
- `pam_deny.so required` — used as a final safety net: if every
  `sufficient` module above it has failed the stack ends in denial.

#### Either system password OR VNC password (most common)

Add to `/etc/pam.d/vncserver-virtual` (or equivalent):

```
# /etc/pam.d/vncserver-virtual
auth    sufficient  pam_unix.so
auth    sufficient  pam_fnal_vncpasswd.so
auth    required    pam_deny.so
account required    pam_unix.so
session required    pam_unix.so
```

System auth (`pam_unix.so`) is tried first.  If it succeeds, auth is
granted immediately.  If it fails (e.g. Kerberos-only accounts with no
local password hash), the VNC password file is tried next.  If both
fail, `pam_deny.so` ensures the overall result is a denial.

#### Allow VNC login before a VNC password has been set

```
# /etc/pam.d/vncserver-virtual
auth    sufficient  pam_unix.so
auth    sufficient  pam_fnal_vncpasswd.so nullok
auth    required    pam_deny.so
account required    pam_unix.so
session required    pam_unix.so
```

With `nullok`, a missing VNC password file is treated as success by
`pam_fnal_vncpasswd.so`, so users who have not yet run `fnal-vncpasswd`
can still log in via their system password.

#### Shared / service-account password file

```
# /etc/pam.d/vncserver-virtual
auth    sufficient  pam_unix.so
auth    sufficient  pam_fnal_vncpasswd.so file=/etc/vnc/shared_passwd
auth    required    pam_deny.so
account required    pam_unix.so
session required    pam_unix.so
```

### Weston + NeatVNC Configuration

In your Weston compositor config:

```ini
[libinput]

[vnc]
enabled=true
port=5900
```

In `/etc/pam.d/weston-vnc` (or as configured by NeatVNC):

```
# /etc/pam.d/weston-vnc
auth    sufficient  pam_unix.so
auth    sufficient  pam_fnal_vncpasswd.so
auth    required    pam_deny.so
account required    pam_unix.so
session required    pam_unix.so
```

## RPM Build

```sh
# Get source tarball
spectool -g pam-vncpasswd.spec

# Build RPM
rpmbuild -ba pam-vncpasswd.spec
```

Or with mock:

```sh
mock -r rhel-10-x86_64 --rebuild pam-vncpasswd-*.src.rpm
```
