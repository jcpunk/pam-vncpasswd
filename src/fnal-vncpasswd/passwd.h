/**
 * passwd.h - VNC password management declarations for fnal-vncpasswd
 *
 * Declares the password hashing and file-management functions used by the
 * fnal-vncpasswd CLI tool.
 *
 * WHAT BELONGS HERE:
 * Functions that are part of setting a VNC password: reading encryption
 * policy from login.defs, hashing a plaintext password, creating the
 * password file directory, writing the hash atomically, and reading a
 * password interactively or from stdin.
 *
 * WHAT DOES NOT BELONG HERE:
 * Password verification and file reading for authentication are exclusive
 * to the PAM module and live in pam/auth.h.
 *
 * YESCRYPT SUPPORT:
 * yescrypt is the default ENCRYPT_METHOD on modern RHEL/Fedora.
 * It uses a fundamentally different cost encoding from SHA-crypt:
 * - SHA-512/SHA-256: cost = number of rounds (e.g., 65536), embedded as
 *   "rounds=N$" in the salt string
 * - yescrypt: cost = cost factor (e.g., 5), encoded by crypt_gensalt_ra
 *   as a parameter string (e.g., "j9T"), NOT "rounds=N"
 * - bcrypt: cost = log2(rounds) (e.g., 12)
 */

#ifndef PASSWD_H
#define PASSWD_H

#include <crypt.h>
#include <stddef.h>

#include "syscall_ops.h"
#include "vnc_crypto.h"
#include "vnc_path.h"

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
 * LOGIN_DEFS_LINE_MAX - Maximum line length in login.defs
 */
enum { LOGIN_DEFS_LINE_MAX = 1024 };

/* ============================================================================
 * Structures
 * ============================================================================
 */

/**
 * struct encrypt_settings - Parsed encryption settings from login.defs
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

/* ============================================================================
 * login.defs Parsing
 * ============================================================================
 */

/**
 * get_encrypt_settings - Read encryption settings from login.defs
 * @ops:             Syscall operations (fopen, fclose, fgets)
 * @login_defs_path: Path to login.defs (typically "/etc/login.defs")
 * @settings:        Output: populated with method and cost parameters
 *
 * Parses ENCRYPT_METHOD, YESCRYPT_COST_FACTOR, and SHA_CRYPT_MAX_ROUNDS.
 * Falls back to compiled-in defaults if the file is missing or a directive
 * is absent.
 *
 * Returns: 0 on success, -1 on invalid args (errno set)
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
 * @ops:      Syscall operations (getrandom, crypt_gensalt_ra, free)
 * @settings: Encryption settings (method and cost)
 * @salt_buf: Output buffer for the salt string
 * @salt_len: Size of salt_buf (use SALT_BUF_SIZE)
 *
 * Uses crypt_gensalt_ra(), which handles each algorithm correctly:
 * - SHA-512 ($6$): "rounds=N$" prefix, count = sha_rounds
 * - SHA-256 ($5$): "rounds=N$" prefix, count = sha_rounds
 * - yescrypt ($y$): cost encoded as param string, count = yescrypt_cost
 * - bcrypt ($2b$): cost encoded as log2 rounds
 *
 * Returns: 0 on success, -1 on failure (errno set)
 */
int generate_salt(const struct syscall_ops *ops,
                  const struct encrypt_settings *settings, char *salt_buf,
                  size_t salt_len);

/* ============================================================================
 * Password Hashing
 * ============================================================================
 */

/**
 * hash_password - Hash a plaintext password using crypt_r
 * @ops:      Syscall operations (getrandom, crypt_gensalt_ra, crypt_r, free)
 * @password: Plaintext password to hash
 * @settings: Encryption settings (method and cost)
 * @hash_buf: Output buffer for the hash string
 * @hash_len: Size of hash_buf (use VNC_HASH_BUF_SIZE)
 *
 * Returns: 0 on success, -1 on failure (errno set)
 */
int hash_password(const struct syscall_ops *ops, const char *password,
                  const struct encrypt_settings *settings, char *hash_buf,
                  size_t hash_len);

/* ============================================================================
 * Directory Management
 * ============================================================================
 */

/**
 * ensure_dir - Create a directory (and its parents) if it does not exist
 * @ops:  Syscall operations (lstat, mkdir)
 * @path: Full path to create (e.g., "/home/user/.config/vnc")
 *
 * Creates each component of path with mode 0700 if it does not already
 * exist.  Existing directories are silently accepted (like mkdir -p).
 * Fails if any path component exists but is not a directory.
 * Rejects paths containing ".." as a defence-in-depth measure.
 *
 * Returns: 0 on success, -1 on failure (errno set)
 */
int ensure_dir(const struct syscall_ops *ops, const char *path);

/* ============================================================================
 * Atomic Password File Write
 * ============================================================================
 */

/**
 * atomic_write_passwd - Atomically write a hash to the password file
 * @ops:  Syscall operations (mkstemp, fchmod, write, fsync, rename, unlink)
 * @path: Destination path for the password file
 * @hash: The crypt(3) hash string to write
 *
 * Write sequence:
 * 1. mkstemp() in the same directory (inherits correct SELinux label)
 * 2. fchmod(0600) before writing any data
 * 3. write hash + newline
 * 4. fsync() to flush to disk
 * 5. rename() into place (atomic on POSIX filesystems)
 * 6. selinux_restorecon() if available (non-fatal)
 *
 * Returns: 0 on success, -1 on failure (errno set)
 */
int atomic_write_passwd(const struct syscall_ops *ops, const char *path,
                        const char *hash);

/* ============================================================================
 * Password Reading
 * ============================================================================
 */

/**
 * read_password_interactive - Read password interactively with confirmation
 * @buf:    Output buffer
 * @buflen: Size of output buffer
 *
 * Prompts twice with terminal echo disabled; returns -1 if entries do not
 * match, if either is below MIN_PASSWORD_LENGTH, or above MAX_PASSWORD_LENGTH.
 *
 * Returns: 0 on success, -1 on failure (errno set)
 */
int read_password_interactive(char *buf, size_t buflen);

/**
 * read_password_noninteractive - Read password from stdin (single line)
 * @buf:    Output buffer
 * @buflen: Size of output buffer
 *
 * Reads one line, enforces MIN_PASSWORD_LENGTH and MAX_PASSWORD_LENGTH.
 *
 * Returns: 0 on success, -1 on failure (errno set)
 */
int read_password_noninteractive(char *buf, size_t buflen);

#endif /* PASSWD_H */
