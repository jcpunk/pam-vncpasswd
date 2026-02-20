/**
 * pam/auth.c - PAM VNC authentication core implementation
 *
 * Implements authentication against a per-user VNC password file using
 * crypt(3).
 *
 * SECURITY MODEL:
 * - O_NOFOLLOW + O_NONBLOCK + fstat() for TOCTOU-safe file access
 * - Constant-time XOR comparison to prevent timing attacks
 * - explicit_bzero() on all sensitive buffers
 * - Session binding: supplied username must resolve to getuid() to prevent
 *   cross-user authentication into a foreign VNC session
 *
 * DEBUG LOGGING:
 * - Enabled by the 'debug' PAM argument; always uses pam_syslog() at LOG_DEBUG
 * - Never logs passwords, hashes, or raw file content
 * - Username is not repeated in messages; Linux-PAM prefixes it automatically
 * - All log sites are open-coded (if (debug && pamh) pam_syslog(...)) for
 *   readability; no logging macros are used
 */

#include "auth.h"

#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include "autoconf.h"
#include "syscall_ops.h"
#include "vnc_crypto.h"
#include "vnc_path.h"

/* ============================================================================
 * Forward declarations for static functions
 * ============================================================================
 *
 * We can use nonnull on static functions because they can only be called
 * from inside here and we're careful to check the pointers in our visible
 * function(s).
 */

static int validate_passwd_file(const struct syscall_ops *ops, const char *path,
                                uid_t expected_uid)
    __attribute__((nonnull(1, 2)));

static int verify_password(const struct syscall_ops *ops, const char *password,
                           const char *stored_hash)
    __attribute__((nonnull(1, 2, 3)));

static int open_and_read_passwd_hash(const struct syscall_ops *ops,
                                     const pam_handle_t *pamh, int *ret_pam,
                                     const char *username, char *hash_buf,
                                     size_t hash_len, bool debug)
    __attribute__((nonnull(1, 3, 4, 5)));

static int vnc_const_memcmp(const void *a, const void *b, size_t len)
    __attribute__((nonnull(1, 2)));

/* ============================================================================
 * PAM Argument Parsing
 * ============================================================================
 */
void parse_pam_args(int argc, const char **argv, struct pam_args *args) {
  if (args == NULL) {
    return;
  }

  /* Unknown args are silently ignored for forward compatibility */
  for (int i = 0; i < argc; i++) {
    if (argv[i] == NULL) {
      continue;
    }
    if (strcmp(argv[i], "debug") == 0) {
      args->debug = true;
    }
  }
}

/* ============================================================================
 * Password File Operations
 * ============================================================================
 */

static int validate_passwd_file(const struct syscall_ops *ops, const char *path,
                                uid_t expected_uid) {
  struct stat st;
  int fd;

  /*
   * O_NOFOLLOW: refuse to open symlinks (prevents symlink-swap TOCTOU attack).
   * O_NONBLOCK: prevents blocking on a FIFO at the target path.  Opening a
   * FIFO for reading without O_NONBLOCK blocks until a writer appears, which
   * is a denial-of-service vector.  The subsequent S_ISREG check rejects
   * FIFOs regardless, but we must not block before we can reach that check.
   */
  fd = ops->open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0) {
    return -1;
  }

  if (ops->fstat(fd, &st) < 0) {
    int saved_errno = errno;
    ops->close(fd);
    errno = saved_errno;
    return -1;
  }

  /*
   * Reject non-regular files, wrong owner, any executable bit, or
   * group/world read-write access.
   */
  if (!S_ISREG(st.st_mode) || st.st_uid != expected_uid ||
      (st.st_mode &
       (S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH))) {
    ops->close(fd);
    errno = EPERM;
    return -1;
  }

  return fd;
}

/* ============================================================================
 * Password Verification
 * ============================================================================
 */

#if defined(HAVE_OPENSSL) || defined(HAVE_LIBRESSL)
#include <openssl/crypto.h>
/* All both expose the same header and symbol */
static int vnc_const_memcmp(const void *a, const void *b, size_t len) {
  return CRYPTO_memcmp(a, b, len);
}
#elif defined(HAVE_GNUTLS)
#include <gnutls/gnutls.h>
static int vnc_const_memcmp(const void *a, const void *b, size_t len) {
  return gnutls_memcmp(a, b, len);
}
#endif

static int verify_password(const struct syscall_ops *ops, const char *password,
                           const char *stored_hash) {
  struct crypt_data cd;
  char *computed;
  int result;

  memset(&cd, 0, sizeof(cd));
  computed = ops->crypt_r(password, stored_hash, &cd);
  if (!computed || computed[0] == '*') {
    explicit_bzero(&cd, sizeof(cd));
    errno = EINVAL;
    return PAM_AUTH_ERR;
  }

  /* compared with a crypto safe method */
  result = vnc_const_memcmp(computed, stored_hash, VNC_HASH_BUF_SIZE);

  /* computed points into cd.output; explicit_bzero(&cd) covers it */
  explicit_bzero(&cd, sizeof(cd));
  if (result == 0) {
    return PAM_SUCCESS;
  }
  errno = EINVAL;
  return PAM_AUTH_ERR;
}

/* ============================================================================
 * Core Authentication Logic
 * ============================================================================
 */

/*
 * open_and_read_passwd_hash - resolve, open, validate, and read the per-user
 * VNC password file into hash_buf, or return -1 with *ret_pam set on failure.
 *
 * Session binding: the resolved pw_uid must equal getuid(). This module runs
 * inside a process owned by the session user; accepting a username that
 * resolves to a different uid would let an attacker authenticate into a
 * foreign session using credentials they control.
 *
 * getuid() (real uid) is used rather than geteuid() so that any temporarily
 * elevated effective uid does not widen the acceptable identity set.
 */
static int open_and_read_passwd_hash(const struct syscall_ops *ops,
                                     const pam_handle_t *pamh, int *ret_pam,
                                     const char *username, char *hash_buf,
                                     size_t hash_len, bool debug) {
  struct passwd pw, *pwresult;
  char pwbuf[4096]; /* conventional fixed size; see pam_unix and glibc docs */
  char passwd_path[PATH_MAX];
  FILE *fp;
  size_t len;
  int fd, saved_errno;

  if (hash_len == 0) {
    errno = EINVAL;
    *ret_pam = PAM_AUTH_ERR;
    return -1;
  }

  if (ops->getpwnam_r(username, &pw, pwbuf, sizeof(pwbuf), &pwresult) != 0 ||
      !pwresult) {
    /*
     * PAM_USER_UNKNOWN rather than PAM_AUTH_ERR is standard behaviour
     * (cf. pam_unix): it lets stacked modules gate access early without
     * leaking information beyond what getent/LDAP/SSH banners already show
     */
    if (debug && pamh) {
      saved_errno = errno;
      pam_syslog((pam_handle_t *)(uintptr_t)(pamh), LOG_DEBUG,
                 "pam_fnal_vncpasswd: getpwnam_r: user not found");
      errno = saved_errno;
    }
    *ret_pam = PAM_USER_UNKNOWN;
    return -1;
  }
  if (debug && pamh) {
    pam_syslog((pam_handle_t *)(uintptr_t)(pamh), LOG_DEBUG,
               "pam_fnal_vncpasswd: getpwnam_r: resolved uid=%lu",
               (unsigned long)pw.pw_uid);
  }

  if (pw.pw_uid != getuid()) {
    if (debug && pamh) {
      saved_errno = errno;
      pam_syslog((pam_handle_t *)(uintptr_t)(pamh), LOG_DEBUG,
                 "pam_fnal_vncpasswd: session binding failed: "
                 "resolved uid=%lu != process uid=%lu",
                 (unsigned long)pw.pw_uid, (unsigned long)getuid());
      errno = saved_errno;
    }
    *ret_pam = PAM_AUTH_ERR;
    return -1;
  }

  /* for our purposes "/" is also an invalid homdir */
  if (!pw.pw_dir || pw.pw_dir[0] == '\0' || pw.pw_dir[0] != "/" ||
      (pw.pw_dir[0] == "/" && pw.pw_dir[1] == '\0')) {
    if (debug && pamh) {
      saved_errno = errno;
      pam_syslog((pam_handle_t *)(uintptr_t)(pamh), LOG_DEBUG,
                 "pam_fnal_vncpasswd: no home directory in passwd entry");
      errno = saved_errno;
    }
    *ret_pam = PAM_USER_UNKNOWN;
    return -1;
  }

  if (build_vnc_passwd_path(pw.pw_dir, passwd_path, sizeof(passwd_path)) < 0) {
    if (debug && pamh) {
      saved_errno = errno;
      pam_syslog((pam_handle_t *)(uintptr_t)(pamh), LOG_DEBUG,
                 "pam_fnal_vncpasswd: build_vnc_passwd_path failed: errno=%d",
                 saved_errno);
      errno = saved_errno;
    }
    *ret_pam = PAM_AUTH_ERR;
    return -1;
  }

  fd = validate_passwd_file(ops, passwd_path, pw.pw_uid);
  if (fd < 0) {
    if (debug && pamh) {
      saved_errno = errno;
      pam_syslog((pam_handle_t *)(uintptr_t)(pamh), LOG_DEBUG,
                 "pam_fnal_vncpasswd: password file validation failed: "
                 "errno=%d",
                 saved_errno);
      errno = saved_errno;
    }
    *ret_pam = PAM_AUTHINFO_UNAVAIL;
    return -1;
  }

  if (debug && pamh) {
    pam_syslog((pam_handle_t *)(uintptr_t)(pamh), LOG_DEBUG,
               "pam_fnal_vncpasswd: password file opened and validated");
  }

  /*
   * fdopen transfers fd ownership to fp on success.
   * On failure, fdopen does NOT close fd, so we close it ourselves.
   */
  fp = ops->fdopen(fd, "r");
  if (fp == NULL) {
    int saved_errno = errno;
    ops->close(fd);
    errno = saved_errno;
    *ret_pam = PAM_AUTHINFO_UNAVAIL;
    return -1;
  }

  if (ops->fgets(hash_buf, (int)hash_len, fp) == NULL) {
    ops->fclose(fp);
    errno = ENODATA;
    *ret_pam = PAM_AUTHINFO_UNAVAIL;
    return -1;
  }
  ops->fclose(fp);

  /* Strip trailing CR, LF, and space.  Intentionally not isspace() to
   * avoid locale-dependent matching on a crypt(3) hash string. */
  len = strlen(hash_buf);
  while (len > 0 && (hash_buf[len - 1] == '\r' || hash_buf[len - 1] == '\n' ||
                     hash_buf[len - 1] == ' ')) {
    hash_buf[--len] = '\0';
  }

  if (hash_buf[0] == '\0') {
    errno = ENODATA;
    *ret_pam = PAM_AUTHINFO_UNAVAIL;
    return -1;
  }

  if (debug && pamh) {
    pam_syslog((pam_handle_t *)(uintptr_t)(pamh), LOG_DEBUG,
               "pam_fnal_vncpasswd: stored hash read successfully");
  }

  return 0;
}

int authenticate_vnc_user(const struct syscall_ops *ops,
                          const pam_handle_t *pamh, const char *username,
                          const char *password, bool debug) {
  char hash[VNC_HASH_BUF_SIZE] = {0};
  int result;

  if (ops == NULL || pamh == NULL || username == NULL || password == NULL) {
    errno = EINVAL;
    return PAM_AUTH_ERR;
  }

  /* need to pass at least something in - obviously "" is invalid*/
  if (username[0] == '\0' || password[0] == '\0') {
    errno = EINVAL;
    return PAM_AUTH_ERR;
  }

  /*
   * No password length check required: a password too long to have been
   * set by fnal-vncpasswd will produce a mismatched hash and fail naturally.
   *
   * Policy belongs in the password-setting tool, not here!
   */
  if (open_and_read_passwd_hash(ops, pamh, &result, username, hash,
                                sizeof(hash), debug) < 0) {
    explicit_bzero(hash, sizeof(hash));
    return result;
  }

  result = verify_password(ops, password, hash) == 0;
  explicit_bzero(hash, sizeof(hash));

  if (debug && pamh) {
    if (result == PAM_SUCCESS) {
      pam_syslog((pam_handle_t *)(uintptr_t)(pamh), LOG_DEBUG,
                 "pam_fnal_vncpasswd: password verification: success");
    } else {
      pam_syslog((pam_handle_t *)(uintptr_t)(pamh), LOG_DEBUG,
                 "pam_fnal_vncpasswd: password verification: failed");
    }
  }

  return result;
}
