/**
 * pam/auth.h - PAM VNC authentication core declarations
 *
 * WHAT BELONGS HERE:
 * PAM argument parsing and the authenticate_vnc_user() entry point.
 *
 * Password file validation, hash reading, and password verification are
 * internal implementation details of auth.c.
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
  bool debug; /* 'debug':  log non-sensitive decision points via syslog */
};

/* ============================================================================
 * PAM Argument Parsing
 * ============================================================================
 */

/**
 * make_pam_args - Construct a pam_args struct with defaults applied
 *
 * Returns an initialized pam_args with all fields set to their defaults.
 */
struct pam_args make_pam_args(void);
struct pam_args make_pam_args(void) {
  return (struct pam_args){
      .debug = false,
  };
}

/**
 * parse_pam_args - Parse PAM module arguments
 * @argc: Argument count from pam_sm_authenticate
 * @argv: Argument vector from pam_sm_authenticate
 * @args: Output: filled with parsed argument values
 *
 * Recognized arguments:
 *   debug    Emit non-sensitive decision-point messages via pam_syslog(3)
 *            at LOG_DEBUG.
 *            No passwords, hashes, or raw file contents are ever logged.
 *
 * Unknown arguments are silently ignored for forward compatibility.
 */
void parse_pam_args(int argc, const char **argv, struct pam_args *args);

/* ============================================================================
 * Core Authentication Logic
 * ============================================================================
 */

/**
 * authenticate_vnc_user - Core authentication entry point
 * @ops:      Syscall operations
 * @pamh:     PAM handle used for debug logging via pam_syslog(3); may be NULL
 *            When NULL, debug messages are suppressed regardless of @debug.
 * @username: PAM username (from pam_get_user)
 * @password: Supplied password (from pam_get_authtok)
 * @debug:    If true, emit non-sensitive decision-point messages at LOG_DEBUG
 *
 * ARCHITECTURAL CONSTRAINT — SESSION BINDING:
 * This module is designed to be loaded exclusively into a single-user VNC
 * session process (e.g. neatvnc running under a weston compositor).  That
 * process runs as the session owner, so getuid() at auth time IS the
 * session owner's uid.
 *
 * The supplied @username is resolved via getpwnam_r and its uid is compared
 * against getuid().  If they do not match, PAM_AUTH_ERR is returned
 * immediately, before any password file is opened.  This prevents an attacker
 * from supplying a different username (one whose ~/.vnc/passwd they know) to
 * authenticate into a foreign session.
 *
 * This check is in addition to validate_passwd_file()'s st_uid == pw.pw_uid
 * ownership check, which guards against file-level substitution but does not
 * by itself prevent the wrong user's password file from being consulted.
 *
 * This module must NOT be deployed in a multi-user PAM service (e.g. sshd,
 * login) where the authenticating process runs as root; getuid() == 0 in that
 * context and the uid binding check would reject all users.
 *
 * Authentication sequence:
 *   1. Look up home directory via getpwnam_r
 *   2. Reject if resolved uid != getuid() (session binding)
 *   3. Build canonical path via build_vnc_passwd_path()
 *   4. Open and validate the password file (TOCTOU-safe)
 *   5. Read stored hash from file
 *   6. Verify password (constant-time comparison)
 *   7. explicit_bzero() all sensitive buffers
 *
 * Debug messages (emitted only when @debug && @pamh != NULL):
 *   - getpwnam_r outcome (uid logged, not username; see NOTE below)
 *   - Session binding check result
 *   - Password file open/validation outcome (errno logged on failure)
 *   - Hash read outcome
 *   - Final verify result (success or failure only; no hash or password)
 *
 * NOTE — username in logs:
 *   pam_syslog() prepends the PAM service, the calling process, and (on
 *   Linux-PAM) the username that was passed to pam_start().  We therefore
 *   do not repeat the username in our own debug messages to avoid redundancy
 *   and to keep the logging surface minimal.
 *
 * Returns: PAM return code (PAM_SUCCESS, PAM_AUTH_ERR, PAM_USER_UNKNOWN, etc.)
 */
int authenticate_vnc_user(const struct syscall_ops *ops,
                          const pam_handle_t *pamh, const char *username,
                          const char *password, bool debug);

#endif /* AUTH_H */
