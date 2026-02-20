/**
 * fnal-vncpasswd/vncpasswd_io.h - CLI password-reading helpers for
 * fnal-vncpasswd
 *
 * Declares read_password_interactive and read_password_noninteractive.
 * Both functions are implemented in vncpasswd.c and are specific to the
 * CLI tool; they depend on terminal I/O and must not be linked into the
 * PAM module or other library consumers.
 *
 * INCLUDE POLICY:
 * Include this header only from:
 *   - vncpasswd.c (implementation + main)
 *   - unit tests that exercise the CLI I/O paths directly
 *
 * All other password-management declarations (hashing, file writing,
 * login.defs parsing) belong in passwd.h.
 */

#ifndef VNCPASSWD_IO_H
#define VNCPASSWD_IO_H

#include <stddef.h>

#include "vnc_crypto.h" /* MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH */

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

#endif /* VNCPASSWD_IO_H */
