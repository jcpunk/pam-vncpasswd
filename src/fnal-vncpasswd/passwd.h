/**
 * fnal-vncpasswd/passwd.h - VNC password file operations
 *
 * Declares the testable core: algorithm selection, hashing, directory
 * creation, and atomic file write.  Terminal I/O and argument parsing
 * are private to main.c and are not declared here.
 *
 * COST PARAMETERS:
 * crypt_gensalt_ra(prefix, 0, ...) selects libxcrypt's compiled-in
 * defaults for each algorithm.  These match the values shadow-utils
 * applies when YESCRYPT_COST_FACTOR / SHA_CRYPT_MAX_ROUNDS are absent
 * from login.defs, so there is no need to re-parse those directives here.
 * ENCRYPT_METHOD is still honoured via get_crypt_prefix().
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
 * Algorithm selection
 * ============================================================================
 */

/**
 * get_crypt_prefix - Resolve crypt(3) algorithm prefix from login.defs
 * @ops:             Syscall operations (fopen, fgets, fclose)
 * @login_defs_path: Path to login.defs (typically LOGIN_DEFS_PATH)
 * @out:             Output buffer; 16 bytes is always sufficient
 * @outlen:          Size of @out
 *
 * Reads ENCRYPT_METHOD from @login_defs_path and maps it to the
 * corresponding crypt(3) prefix string.  Falls back to "$y$" (yescrypt)
 * if the file is missing or the directive is absent — yescrypt is the
 * default on all supported RHEL/AlmaLinux releases.
 *
 * DES and MD5 are explicitly rejected: both are cryptographically broken
 * and unsuitable for new password hashing.
 *
 * Returns: 0 on success
 *          -1, errno=EINVAL  if ENCRYPT_METHOD names DES or MD5
 *          -1, errno=ERANGE  if @outlen is too small for the prefix
 */
int get_crypt_prefix(const struct syscall_ops *ops, const char *login_defs_path,
                     char *out, size_t outlen);

/* ============================================================================
 * Password hashing
 * ============================================================================
 */

/**
 * hash_password - Hash a plaintext password using crypt_r(3)
 * @ops:      Syscall operations (getrandom, crypt_gensalt_ra, crypt_r)
 * @password: Plaintext password (NUL-terminated, non-empty)
 * @prefix:   crypt(3) algorithm prefix from get_crypt_prefix()
 * @hash_buf: Output buffer; VNC_HASH_BUF_SIZE bytes is always sufficient
 * @hash_len: Size of @hash_buf
 *
 * Passes count=0 to crypt_gensalt_ra so libxcrypt selects the
 * algorithm-specific default cost (yescrypt: N=32768, r=32, p=1;
 * SHA-512: 5000 rounds).  These defaults are the same as shadow-utils
 * uses when login.defs carries no explicit cost directive.
 *
 * Returns: 0 on success, -1 on error (errno set)
 */
int hash_password(const struct syscall_ops *ops, const char *password,
                  const char *prefix, char *hash_buf, size_t hash_len);

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
 * atomic_write_passwd - Atomically replace the VNC password file
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
int atomic_write_passwd(const struct syscall_ops *ops, const char *path,
                        const char *hash);

#endif /* FNAL_VNCPASSWD_PASSWD_H */
