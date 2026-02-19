/**
 * vnc_path.h - VNC password file path construction
 *
 * Shared between pam_fnal_vncpasswd.so and fnal-vncpasswd.  Both tools operate
 * on the same per-user password file; this module encapsulates path
 * construction so the canonical location is defined exactly once.
 *
 * Only path construction is shared here.  Home directory lookup is
 * intentionally left to each caller: PAM uses getpwnam_r() (keyed by the
 * username supplied to the PAM stack) while fnal-vncpasswd uses getpwuid_r()
 * (keyed by the calling process's UID).  The two lookups differ in key, error
 * semantics, and privilege level; a shared wrapper would add complexity for
 * no gain.
 *
 * Path structure (constants from autoconf.h, set at build time)::
 *
 *   directory : <home_dir>/<VNC_PASSWD_DIR>
 *               e.g. /home/user/.config/vnc
 *
 *   file      : <home_dir>/<VNC_PASSWD_DIR>/<VNC_PASSWD_FILE>
 *               e.g. /home/user/.config/vnc/fnal-vncpasswd
 */

#ifndef VNC_PATH_H
#define VNC_PATH_H

#include <stddef.h>

/**
 * build_vnc_dir_path - Construct the VNC configuration directory path
 * @home_dir: Absolute path to the user's home directory (from passwd entry).
 *            Must be non-NULL and non-empty.
 * @buf:      Output buffer to receive the constructed path.
 * @buflen:   Size of @buf in bytes.  PATH_MAX is always sufficient.
 *
 * Constructs: <home_dir>/<VNC_PASSWD_DIR>
 *
 * Return: 0 on success, -1 on error with errno set to:
 *         - EINVAL if @home_dir is NULL or empty, or @buf is NULL, or
 *           @buflen is 0.
 *         - ERANGE if the constructed path exceeds @buflen.
 */
int build_vnc_dir_path(const char *home_dir, char *buf, size_t buflen);

/**
 * build_vnc_passwd_path - Construct the VNC password file path
 * @home_dir: Absolute path to the user's home directory (from passwd entry).
 *            Must be non-NULL and non-empty.
 * @buf:      Output buffer to receive the constructed path.
 * @buflen:   Size of @buf in bytes.  PATH_MAX is always sufficient.
 *
 * Constructs: <home_dir>/<VNC_PASSWD_DIR>/<VNC_PASSWD_FILE>
 *
 * Return: 0 on success, -1 on error with errno set to:
 *         - EINVAL if @home_dir is NULL or empty, or @buf is NULL, or
 *           @buflen is 0.
 *         - ERANGE if the constructed path exceeds @buflen.
 */
int build_vnc_passwd_path(const char *home_dir, char *buf, size_t buflen);

#endif /* VNC_PATH_H */
