/**
 * auth.h - PAM VNC authentication core declarations
 *
 * Declares the authentication logic for pam_fnal_vncpasswd.so.
 *
 * NO PAM HEADER DEPENDENCY:
 * These functions have no dependency on <security/pam_modules.h>.
 * pam_entry.c is the only file in this component that includes PAM headers;
 * it extracts the username and password from the PAM handle and passes them
 * to authenticate_vnc_user(), which is fully testable without a PAM stack.
 *
 * WHAT BELONGS HERE:
 * Only functions that are part of PAM authentication: reading and validating
 * the password file, verifying a supplied password against the stored hash,
 * parsing PAM module arguments, and the top-level authenticate_vnc_user()
 * entry point used by pam_entry.c.
 *
 * WHAT DOES NOT BELONG HERE:
 * Password hashing, salt generation, login.defs parsing, and directory/file
 * creation are exclusive to fnal-vncpasswd (the password-setting tool) and
 * live in fnal-vncpasswd/passwd.h.
 */

#ifndef AUTH_H
#define AUTH_H

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
  const char *file; /* 'file=/path' override, or NULL for default */
  bool nullok;      /* 'nullok': missing password file passes auth */
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
 * - "file=/path/to/file"  Override the default password file path
 * - "nullok"              Allow missing password file (auth passes)
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
 * - File is a regular file (rejects FIFOs, symlinks, devices)
 * - Owned by expected_uid
 * - Mode 0600 or stricter (no group/world read or write bits)
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
 * Wraps fd in a FILE* via fdopen so the same fgets abstraction used
 * elsewhere in the codebase handles line reading consistently.
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
 * Hashes password against the stored_hash using crypt_r (the stored hash
 * encodes the algorithm and salt), then compares the result using a
 * constant-time XOR accumulator to prevent timing attacks.
 *
 * The comparison iterates to max(computed_len, stored_len) rather than the
 * minimum, padding the shorter string with zero bytes.  This prevents a
 * length-based timing side-channel that would otherwise reveal whether the
 * supplied password produced a hash of the same length as the stored one.
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
 * authenticate_vnc_user - Testable core authentication function
 * @ops:           Syscall operations
 * @username:      PAM username (from pam_get_user)
 * @password:      Supplied password (from pam_get_authtok)
 * @file_override: Path override from 'file=' PAM argument, or NULL
 * @nullok:        If true, a missing password file returns PAM_SUCCESS
 *
 * Full authentication sequence without PAM header dependency:
 * 1. mlock password buffer in RAM (non-fatal if it fails)
 * 2. If file_override: build path from it directly (skip home directory
 * lookup) Otherwise: look up home directory via getpwnam_r, build canonical
 * path via build_vnc_passwd_path()
 * 3. Open and validate the password file (TOCTOU-safe)
 * 4. Read stored hash from file
 * 5. Verify password (constant-time comparison)
 * 6. explicit_bzero all sensitive buffers
 *
 * Returns: PAM return code (PAM_SUCCESS, PAM_AUTH_ERR, PAM_USER_UNKNOWN, etc.)
 */
int authenticate_vnc_user(const struct syscall_ops *ops, const char *username,
                          const char *password, const char *file_override,
                          bool nullok);

#endif /* AUTH_H */
