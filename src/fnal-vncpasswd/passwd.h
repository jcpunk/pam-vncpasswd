/**
 * fnal-vncpasswd/passwd.h - VNC password file operations
 *
 * Declares the testable core: algorithm selection, hashing, directory
 * creation, and atomic file write.  Terminal I/O and argument parsing
 * are private to main.c and are not declared here.
 */

#ifndef FNAL_VNCPASSWD_PASSWD_H
#define FNAL_VNCPASSWD_PASSWD_H

#include <crypt.h>
#include <stddef.h>

#include "syscall_ops.h"
#include "vnc_crypto.h"

/* ============================================================================
 * Password file path resolution
 * ============================================================================
 */

/**
 * get_passwd_path - Build the VNC password file path for a given UID
 * @ops:    Syscall operations (getpwuid_r, lstat, mkdir)
 * @uid:    UID to look up; callers pass getuid()
 * @buf:    Output buffer; PATH_MAX bytes is always sufficient
 * @buflen: Size of @buf
 *
 * Looks up the home directory for @uid via getpwuid_r, creates the VNC
 * configuration directory if absent, then constructs the full password
 * file path.
 *
 * Returns: 0 on success, -1 on error (errno set)
 */
int get_passwd_path(const struct syscall_ops *ops, uid_t uid, char *buf,
                    size_t buflen);

/* ============================================================================
 * Password hashing
 * ============================================================================
 */

/**
 * hash_password - Hash a plaintext password using crypt_r(3)
 * @ops:      Syscall operations (getrandom, crypt_gensalt_ra, crypt_r)
 * @password: Plaintext password (NUL-terminated, non-empty)
 * @hash_buf: Output buffer; VNC_HASH_BUF_SIZE bytes is always sufficient
 * @hash_len: Size of @hash_buf
 *
 * The algorithm is libxcrypt's compiled-in default. Thus NULL is passed as the
 * prefix to crypt_gensalt_ra(3), which the library documents as "use the
 * preferred algorithm".
 *
 * Returns: 0 on success, -1 on error (errno set)
 */
int hash_password(const struct syscall_ops *ops, const char *password,
                  char *hash_buf, size_t hash_len);

/* ============================================================================
 * Directory management
 * ============================================================================
 */

/**
 * ensure_vnc_dir - Create the VNC configuration directory if absent
 * @ops:  Syscall operations (lstat, mkdir)
 * @path: Full path to create (e.g. /home/user/.config/vnc)
 *
 * Creates each path component with mode 0700 (like mkdir -p).
 * Silently accepts existing directories.  Rejects components that are
 * not directories or paths that contain "..".
 *
 * Returns: 0 on success, -1 on error (errno set)
 */
int ensure_vnc_dir(const struct syscall_ops *ops, const char *path);

/* ============================================================================
 * Atomic password file write
 * ============================================================================
 */

/**
 * atomic_write_passwd_file - Atomically replace the VNC password file
 * @ops:  Syscall operations (mkstemp, fchmod, write, fsync, rename, unlink)
 * @path: Destination path for the password file
 * @hash: crypt(3) hash string to write
 *
 * Write sequence:
 *   1. mkstemp() in the same directory (inherits SELinux default transition)
 *   2. fchmod(0600) before writing any data
 *   3. write(hash + "\n")
 *   4. fsync()
 *   5. rename() into place (atomic on POSIX filesystems)
 *   6. selinux_restorecon() — unconditional when HAVE_SELINUX, non-fatal
 *
 * Returns: 0 on success, -1 on error (errno set)
 */
int atomic_write_passwd_file(const struct syscall_ops *ops, const char *path,
                             const char *hash);

#endif /* FNAL_VNCPASSWD_PASSWD_H */
