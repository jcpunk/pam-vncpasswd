/**
 * pam_fnal_vncpasswd.h - Shared declarations for pam_fnal_vncpasswd
 *
 * This header declares the core functions shared between:
 * - pam_fnal_vncpasswd.c  (PAM module implementation)
 * - vncpasswd.c           (fnal-vncpasswd CLI tool)
 * - test/                 (unit tests)
 *
 * DESIGN NOTE:
 * Core functions do NOT depend on PAM headers. The PAM entry points
 * (pam_sm_authenticate, etc.) are thin wrappers in pam_entry.c that
 * extract username/password from the PAM handle and pass them to
 * authenticate_vnc_user(), which is fully testable without PAM.
 *
 * PASSWORD FILE LOCATION:
 * By default: ~/.config/vnc/fnal_vncpasswd
 * Configured at build time via VNC_PASSWD_DIR and VNC_PASSWD_FILE.
 * Uses the XDG config directory convention (~/.config) rather than a
 * bare dotfile (~/.vnc) to follow modern filesystem standards.
 *
 * YESCRYPT SUPPORT:
 * yescrypt is the default ENCRYPT_METHOD on modern RHEL/Fedora.
 * It uses a fundamentally different cost encoding from SHA-crypt:
 * - SHA-512/SHA-256: cost = number of rounds (e.g., 65536), embedded as
 *   "rounds=N$" in the salt string
 * - yescrypt: cost = cost factor (e.g., 5), encoded by crypt_gensalt_ra
 *   as a parameter string (e.g., "j9T"), NOT "rounds=N"
 * - bcrypt: cost = log2(rounds) (e.g., 12)
 *
 * The generate_salt() function uses crypt_gensalt_ra() for all algorithms,
 * which handles the algorithm-specific encoding automatically.
 */

#ifndef PAM_FNAL_VNCPASSWD_H
#define PAM_FNAL_VNCPASSWD_H

#include <crypt.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "syscall_ops.h"

/* ============================================================================
 * Constants
 * ============================================================================
 */

/**
 * ENCRYPT_METHOD_MAX - Maximum length of an encrypt method string
 */
enum { ENCRYPT_METHOD_MAX = 64 };

/**
 * SALT_BUF_SIZE - Buffer for generated salt string
 *
 * CRYPT_GENSALT_OUTPUT_SIZE (192) from <crypt.h> is the maximum length
 * of any salt string returned by crypt_gensalt_ra.
 */
enum { SALT_BUF_SIZE = CRYPT_GENSALT_OUTPUT_SIZE };

/**
 * HASH_BUF_SIZE - Buffer for a complete hash string
 *
 * CRYPT_OUTPUT_SIZE (384) from <crypt.h> is the maximum length
 * of any hash string returned by crypt_r.
 */
enum { HASH_BUF_SIZE = CRYPT_OUTPUT_SIZE };

/**
 * LOGIN_DEFS_LINE_MAX - Maximum line length in login.defs
 */
enum { LOGIN_DEFS_LINE_MAX = 1024 };

/**
 * PAM_ARGS_FILE_MAX - Maximum path length for 'file=' PAM argument
 */
enum { PAM_ARGS_FILE_MAX = 4096 };

/* ============================================================================
 * Structures
 * ============================================================================
 */

/**
 * struct encrypt_settings - Parsed encryption settings from login.defs
 *
 * Holds both the algorithm name and the algorithm-specific cost parameter.
 *
 * WHY TWO COST FIELDS:
 * SHA-crypt and yescrypt use fundamentally different cost metrics:
 * - sha_rounds: number of hash iterations (65536 is a good default)
 * - yescrypt_cost: cost factor N (5 is the shadow-utils default,
 *   maps to N=32768, r=32, p=1 via crypt_gensalt_ra)
 * These are kept separate to avoid confusion between the two scales.
 */
struct encrypt_settings {
  char method[ENCRYPT_METHOD_MAX]; /* e.g. "SHA512", "YESCRYPT", "SHA256" */
  unsigned long sha_rounds;        /* SHA-crypt rounds (SHA256/SHA512) */
  unsigned long yescrypt_cost;     /* yescrypt cost factor (YESCRYPT) */
};

/**
 * struct pam_args - Parsed PAM module arguments
 */
struct pam_args {
  const char *file; /* 'file=/path' override, or NULL for default */
  bool nullok;      /* 'nullok': missing password file passes auth */
};

/* ============================================================================
 * login.defs Parsing
 * ============================================================================
 */

/**
 * get_encrypt_settings - Read encryption settings from login.defs
 * @ops: Syscall operations (fopen, fclose, fgets)
 * @login_defs_path: Path to login.defs (typically "/etc/login.defs")
 * @settings: Output: populated with method and cost parameters
 *
 * Parses ENCRYPT_METHOD, YESCRYPT_COST_FACTOR, and SHA_CRYPT_MAX_ROUNDS.
 * Falls back to compiled-in defaults if the file is missing or a directive
 * is absent.
 *
 * Returns: 0 on success (settings filled), -1 on invalid args (errno set)
 */
int get_encrypt_settings(const struct syscall_ops *ops,
                         const char *login_defs_path,
                         struct encrypt_settings *settings);

/* ============================================================================
 * Salt Generation
 * ============================================================================
 */

/**
 * generate_salt - Generate a cryptographically secure salt string
 * @ops: Syscall operations (getrandom, crypt_gensalt_ra)
 * @settings: Encryption settings (method and cost)
 * @salt_buf: Output buffer for the salt string
 * @salt_len: Size of salt_buf (use SALT_BUF_SIZE)
 *
 * Uses crypt_gensalt_ra(), which correctly handles each algorithm:
 * - SHA-512 ($6$): "rounds=N$" prefix in salt, count = sha_rounds
 * - SHA-256 ($5$): "rounds=N$" prefix in salt, count = sha_rounds
 * - yescrypt ($y$): cost encoded as param string, count = yescrypt_cost
 * - bcrypt ($2b$): cost encoded as log2 rounds
 *
 * Returns: 0 on success, -1 on failure (errno set)
 */
int generate_salt(const struct syscall_ops *ops,
                  const struct encrypt_settings *settings, char *salt_buf,
                  size_t salt_len);

/* ============================================================================
 * Password Hashing and Verification
 * ============================================================================
 */

/**
 * hash_password - Hash a password using crypt_r
 * @ops: Syscall operations (getrandom, crypt_gensalt_ra, crypt_r)
 * @password: Plaintext password to hash
 * @settings: Encryption settings (method and cost)
 * @hash_buf: Output buffer for the hash string
 * @hash_len: Size of hash_buf (use HASH_BUF_SIZE)
 *
 * Returns: 0 on success, -1 on failure (errno set)
 */
int hash_password(const struct syscall_ops *ops, const char *password,
                  const struct encrypt_settings *settings, char *hash_buf,
                  size_t hash_len);

/**
 * verify_password - Constant-time password verification
 * @ops: Syscall operations (crypt_r)
 * @password: Plaintext password to verify
 * @stored_hash: Complete crypt(3) hash from the password file
 *
 * Compares using a constant-time XOR accumulator to prevent timing attacks.
 *
 * Returns: 0 if password matches, -1 if mismatch or error (errno set)
 */
int verify_password(const struct syscall_ops *ops, const char *password,
                    const char *stored_hash);

/* ============================================================================
 * Password File Operations
 * ============================================================================
 */

/**
 * validate_passwd_file - TOCTOU-safe password file validation
 * @ops: Syscall operations (open, fstat, lstat, close)
 * @path: Path to the password file
 * @expected_uid: UID that must own the file
 *
 * Opens with O_NOFOLLOW (prevents symlink attacks), then fstat() verifies:
 * - File is owned by expected_uid
 * - Mode is 0600 or stricter (no group/world read)
 * - File is a regular file
 *
 * Returns: open fd on success (caller must close), -1 on failure (errno set)
 */
int validate_passwd_file(const struct syscall_ops *ops, const char *path,
                         uid_t expected_uid);

/**
 * read_passwd_hash - Read the hash from a validated password file fd
 * @ops: Syscall operations (close)
 * @fd: Open file descriptor (from validate_passwd_file, consumed by this fn)
 * @hash_buf: Output buffer for the stored hash
 * @hash_len: Size of hash_buf (use HASH_BUF_SIZE)
 *
 * Returns: 0 on success, -1 on failure
 */
int read_passwd_hash(const struct syscall_ops *ops, int fd, char *hash_buf,
                     size_t hash_len);

/* ============================================================================
 * PAM Argument Parsing
 * ============================================================================
 */

/**
 * parse_pam_args - Parse PAM module arguments
 * @argc: Argument count from pam_sm_authenticate
 * @argv: Argument vector from pam_sm_authenticate
 * @args: Output: filled with parsed argument values
 *
 * Recognized arguments:
 * - "file=/path/to/file"  Override the default password file path
 * - "nullok"              Allow missing password file (auth passes)
 *
 * Unknown arguments are silently ignored for forward compatibility.
 */
void parse_pam_args(int argc, const char **argv, struct pam_args *args);

/* ============================================================================
 * Core Authentication Logic
 * ============================================================================
 */

/**
 * authenticate_vnc_user - Testable core authentication function
 * @ops: Syscall operations
 * @username: PAM username (from pam_get_user)
 * @password: Supplied password (from pam_get_authtok)
 * @file_override: Path override from 'file=' arg, or NULL for default
 * @nullok: If true, missing password file returns success
 *
 * Full authentication logic without PAM dependency:
 * 1. Look up user home directory via getpwnam_r
 * 2. Build password file path (~/.config/vnc/fnal_vncpasswd or file_override)
 * 3. Open and validate the password file (TOCTOU-safe)
 * 4. Read stored hash from file
 * 5. mlock password buffer in RAM
 * 6. Verify password (constant-time comparison)
 * 7. explicit_bzero sensitive buffers
 *
 * Returns: PAM return code (PAM_SUCCESS, PAM_AUTH_ERR, etc.)
 */
int authenticate_vnc_user(const struct syscall_ops *ops, const char *username,
                          const char *password, const char *file_override,
                          bool nullok);

/* ============================================================================
 * Directory Management (shared with vncpasswd CLI)
 * ============================================================================
 */

/**
 * ensure_dir - Create a directory (and its parents) if it does not exist
 * @ops: Syscall operations (lstat, mkdir)
 * @path: Full path to create (e.g., "/home/user/.config/vnc")
 *
 * Creates each component of path with mode 0700 if it does not already
 * exist. Existing directories are silently accepted (like mkdir -p).
 * Fails if any path component exists but is not a directory.
 *
 * Returns: 0 on success, -1 on failure (errno set)
 */
int ensure_dir(const struct syscall_ops *ops, const char *path);

/**
 * atomic_write_passwd - Atomically write a hash to the password file
 * @ops: Syscall operations (mkstemp, fchmod, write, fsync, rename, unlink)
 * @path: Destination path for the password file
 * @hash: The crypt(3) hash string to write
 *
 * Write sequence:
 * 1. mkstemp() in the same directory
 * 2. fchmod(0600) before writing data
 * 3. write hash + newline
 * 4. fsync() to flush to disk
 * 5. rename() into place (atomic on POSIX filesystems)
 *
 * Returns: 0 on success, -1 on failure (errno set)
 */
int atomic_write_passwd(const struct syscall_ops *ops, const char *path,
                        const char *hash);

/* ============================================================================
 * Password Reading (fnal-vncpasswd CLI)
 * ============================================================================
 */

/**
 * read_password_interactive - Read password interactively with confirmation
 * @buf: Output buffer
 * @buflen: Size of output buffer
 *
 * Prompts twice; returns -1 if the entries do not match or are too short.
 *
 * Returns: 0 on success, -1 on failure (errno set)
 */
int read_password_interactive(char *buf, size_t buflen);

/**
 * read_password_noninteractive - Read password from stdin (single line)
 * @buf: Output buffer
 * @buflen: Size of output buffer
 *
 * Returns: 0 on success, -1 on failure (errno set)
 */
int read_password_noninteractive(char *buf, size_t buflen);

#endif /* PAM_FNAL_VNCPASSWD_H */
