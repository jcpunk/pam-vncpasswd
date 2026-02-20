/**
 * pam/auth.h - PAM VNC authentication core declarations
 *
 * WHAT BELONGS HERE:
 * Password file validation, hash reading, password verification, PAM argument
 * parsing, and the authenticate_vnc_user() entry point.
 */

#ifndef AUTH_H
#define AUTH_H

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdbool.h>
#include <sys/types.h>

#include "syscall_ops.h"
#include "vnc_path.h"

/* ============================================================================
 * Structures
 * ============================================================================
 */

/**
 * struct pam_args - Parsed PAM module arguments
 */
struct pam_args {
  bool nullok; /* 'nullok': missing password file passes auth */
};

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
 *   nullok   Allow missing password file (auth passes)
 *
 * Unknown arguments are silently ignored for forward compatibility.
 */
void parse_pam_args(int argc, const char **argv, struct pam_args *args);

/* ============================================================================
 * Password File Operations
 * ============================================================================
 */

/**
 * validate_passwd_file - TOCTOU-safe password file validation
 * @ops:          Syscall operations (open, fstat, close)
 * @path:         Path to the password file
 * @expected_uid: UID that must own the file
 *
 * Opens with O_NOFOLLOW | O_NONBLOCK (prevents symlink attacks and FIFO
 * blocking), then fstat() verifies:
 *   - Regular file (rejects FIFOs, symlinks, devices)
 *   - Owned by expected_uid
 *   - Mode 0600 or stricter (no group/world read or write bits)
 *
 * Returns: open fd on success (caller must close), -1 on failure (errno set)
 */
int validate_passwd_file(const struct syscall_ops *ops, const char *path,
                         uid_t expected_uid);

/**
 * read_passwd_hash - Read the stored hash from a validated password file fd
 * @ops:      Syscall operations (fdopen, fgets, fclose)
 * @fd:       Open file descriptor from validate_passwd_file; consumed here
 * @hash_buf: Output buffer for the stored hash string
 * @hash_len: Size of hash_buf; VNC_HASH_BUF_SIZE is always sufficient
 *
 * fd ownership is transferred unconditionally; the caller must not close it.
 *
 * Returns: 0 on success, -1 on failure (errno set)
 */
int read_passwd_hash(const struct syscall_ops *ops, int fd, char *hash_buf,
                     size_t hash_len);

/* ============================================================================
 * Password Verification
 * ============================================================================
 */

/**
 * verify_password - Constant-time password verification
 * @ops:         Syscall operations (crypt_r)
 * @password:    Plaintext password to verify
 * @stored_hash: Complete crypt(3) hash string from the password file
 *
 * Hashes password against stored_hash using crypt_r (the stored hash encodes
 * the algorithm and salt), then compares using a constant-time XOR accumulator
 * to prevent timing attacks.
 *
 * Iterates to max(computed_len, stored_len), padding the shorter string with
 * zero bytes, to prevent a length-based timing side-channel.
 *
 * Returns: 0 if password matches, -1 if mismatch or error (errno set)
 */
int verify_password(const struct syscall_ops *ops, const char *password,
                    const char *stored_hash);

/* ============================================================================
 * Core Authentication Logic
 * ============================================================================
 */

/**
 * authenticate_vnc_user - Core authentication entry point
 * @ops:      Syscall operations
 * @username: PAM username (from pam_get_user)
 * @password: Supplied password (from pam_get_authtok)
 * @nullok:   If true, a missing password file returns PAM_SUCCESS
 *
 * Authentication sequence:
 *   1. mlock() password buffer in RAM (non-fatal if it fails)
 *   2. Look up home directory via getpwnam_r
 *   3. Build canonical path via build_vnc_passwd_path()
 *   4. Open and validate the password file (TOCTOU-safe)
 *   5. Read stored hash from file
 *   6. Verify password (constant-time comparison)
 *   7. explicit_bzero() all sensitive buffers
 *
 * Returns: PAM return code (PAM_SUCCESS, PAM_AUTH_ERR, PAM_USER_UNKNOWN, etc.)
 */
int authenticate_vnc_user(const struct syscall_ops *ops, const char *username,
                          const char *password, bool nullok);

#endif /* AUTH_H */
