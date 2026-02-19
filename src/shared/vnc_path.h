/**
 * vnc_path.h - VNC password file path construction
 *
 * Shared between pam_fnal_vncpasswd.so and fnal-vncpasswd.  Both tools
 * operate on the same per-user password file; this module encapsulates the
 * path construction so the location is defined exactly once.
 *
 * WHY ONLY PATH CONSTRUCTION IS SHARED:
 * The home directory lookup is NOT shared here.  PAM uses getpwnam_r (lookup
 * by username supplied to the PAM stack), while fnal-vncpasswd uses
 * getpwuid_r (lookup by the calling process's uid).  The two lookups use
 * different keys, different error semantics, and run at different privilege
 * levels; merging them into a shared function would require threading in
 * syscall_ops and union-ing the two lookup modes for no gain.  Only the
 * snprintf pattern that converts a home directory into the canonical VNC
 * password directory or file path is genuinely duplicated.
 *
 * PATH STRUCTURE (constants from autoconf.h, set at build time):
 *   directory : home_dir / VNC_PASSWD_DIR
 *               e.g. /home/user/.config/vnc
 *   file      : home_dir / VNC_PASSWD_DIR / VNC_PASSWD_FILE
 *               e.g. /home/user/.config/vnc/fnal-vncpasswd
 *
 * CRYPTO BUFFER SIZES:
 * VNC_HASH_BUF_SIZE is defined in vnc_crypto.h, not here.
 */

#ifndef VNC_PATH_H
#define VNC_PATH_H

#include <stddef.h>

/**
 * VNC_PATH_MAX - maximum buffer size for VNC password file paths
 *
 * PATH_MAX is 4096 on Linux.  We use our own name to avoid pulling in
 * <linux/limits.h> and to make the intent explicit.
 */
enum { VNC_PATH_MAX = 4096 };

/**
 * build_vnc_dir_path - Construct the VNC configuration directory path
 * @home_dir: User's home directory (from passwd entry)
 * @buf:      Output buffer
 * @buflen:   Size of output buffer; VNC_PATH_MAX is always sufficient
 *
 * Constructs: home_dir / VNC_PASSWD_DIR
 *
 * Returns: 0 on success, -1 on failure (EINVAL: bad args; ERANGE: truncated)
 */
int build_vnc_dir_path(const char *home_dir, char *buf, size_t buflen);

/**
 * build_vnc_passwd_path - Construct the VNC password file path
 * @home_dir:      User's home directory; ignored when file_override is set
 * @file_override: If non-NULL, copied verbatim into buf
 * @buf:           Output buffer
 * @buflen:        Size of output buffer; VNC_PATH_MAX is always sufficient
 *
 * When file_override is non-NULL, copies it as-is (path validation is
 * the caller's responsibility).  Otherwise constructs:
 *   home_dir / VNC_PASSWD_DIR / VNC_PASSWD_FILE
 *
 * Returns: 0 on success, -1 on failure (EINVAL: bad args; ERANGE: truncated)
 */
int build_vnc_passwd_path(const char *home_dir, const char *file_override,
                          char *buf, size_t buflen);

#endif /* VNC_PATH_H */
