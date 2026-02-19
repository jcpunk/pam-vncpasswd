/**
 * auth.c - PAM VNC authentication core implementation
 *
 * Implements authentication against a per-user VNC password file using
 * crypt(3).  No PAM header dependency; see auth.h for the design rationale.
 *
 * SECURITY MODEL:
 * - O_NOFOLLOW + O_NONBLOCK + fstat() for TOCTOU-safe file access
 * - Constant-time XOR comparison to prevent timing attacks
 * - explicit_bzero() on all sensitive buffers
 * - mlock() to prevent password pages from being swapped to disk
 */

#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "auth.h"
#include "autoconf.h"
#include "syscall_ops.h"
#include "vnc_crypto.h"
#include "vnc_path.h"

/*
 * Minimal PAM return codes used by authenticate_vnc_user().
 * These match the integer values defined by the PAM standard.
 * pam_entry.c (which includes the real PAM headers) uses the real constants.
 *
 * WHY DEFINE THEM HERE:
 * authenticate_vnc_user() returns PAM codes but must not include
 * <security/pam_modules.h>, which is not available in test environments and
 * would create a PAM dependency in the OBJECT library.  The numeric values
 * are stable constants defined by the PAM specification (Linux-PAM, OpenPAM)
 * and do not change between versions.
 */
#define PAM_SUCCESS          0
#define PAM_AUTH_ERR         7
#define PAM_AUTHINFO_UNAVAIL 9
#define PAM_USER_UNKNOWN    10

/* ============================================================================
 * PAM Argument Parsing
 * ============================================================================
 */

void parse_pam_args(int argc, const char **argv, struct pam_args *args) {
  if (!args)
    return;

  args->file = NULL;
  args->nullok = false;

  for (int i = 0; i < argc; i++) {
    if (!argv[i])
      continue;
    if (strncmp(argv[i], "file=", 5) == 0) {
      args->file = argv[i] + 5;
    } else if (strcmp(argv[i], "nullok") == 0) {
      args->nullok = true;
    }
    /* Unknown args are silently ignored for forward compatibility */
  }
}

/* ============================================================================
 * Password File Operations
 * ============================================================================
 */

int validate_passwd_file(const struct syscall_ops *ops, const char *path,
                         uid_t expected_uid) {
  int fd;
  struct stat st;

  if (!ops || !path) {
    errno = EINVAL;
    return -1;
  }

  /*
   * O_NOFOLLOW: refuse to open symlinks (prevents symlink-swap TOCTOU attack).
   * O_NONBLOCK: prevents blocking on a FIFO at the target path.  Opening a
   * FIFO for reading without O_NONBLOCK blocks until a writer appears, which
   * is a denial-of-service vector.  The subsequent S_ISREG check rejects
   * FIFOs regardless, but we must not block before we can reach that check.
   */
  fd = ops->open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0)
    return -1;

  if (ops->fstat(fd, &st) < 0) {
    ops->close(fd);
    return -1;
  }

  if (!S_ISREG(st.st_mode)) {
    ops->close(fd);
    errno = EACCES;
    return -1;
  }

  if (st.st_uid != expected_uid) {
    ops->close(fd);
    errno = EACCES;
    return -1;
  }

  /* Reject group- or world-readable/writable files */
  if (st.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) {
    ops->close(fd);
    errno = EACCES;
    return -1;
  }

  return fd;
}

int read_passwd_hash(const struct syscall_ops *ops, int fd, char *hash_buf,
                     size_t hash_len) {
  FILE *fp;
  char *result;
  char *p;
  size_t len;

  if (!ops || fd < 0 || !hash_buf || hash_len == 0) {
    /*
     * Close fd even when ops is NULL to avoid leaking the descriptor.
     * When ops is unavailable we fall back to the bare close(2) syscall
     * because we own the fd regardless of which abstraction layer is used.
     */
    if (fd >= 0) {
      if (ops)
        ops->close(fd);
      else
        close(fd);
    }
    errno = EINVAL;
    return -1;
  }

  /*
   * Wrap the security-validated fd in a buffered FILE* so we can use
   * ops->fgets() — the same abstraction used to read /etc/login.defs.
   *
   * OWNERSHIP: fdopen(3) takes ownership of fd.  Do NOT call ops->close(fd)
   * after a successful fdopen; ops->fclose() will close the underlying fd
   * as part of stream teardown.
   *
   * On fdopen failure the C library does NOT close fd, so we must.
   */
  fp = ops->fdopen(fd, "r");
  if (!fp) {
    ops->close(fd);
    return -1;
  }

  /* Read the single line containing the stored hash */
  result = ops->fgets(hash_buf, (int)hash_len, fp);
  ops->fclose(fp); /* also closes the underlying fd */

  if (!result) {
    errno = ENODATA;
    return -1;
  }

  /*
   * Check for zero length before pointer arithmetic.
   *
   * Without this check, `hash_buf + strlen(hash_buf) - 1` underflows to
   * a pointer before hash_buf when the buffer is empty, producing undefined
   * behaviour in the trimming loop that follows.
   */
  len = strlen(hash_buf);
  if (len == 0) {
    errno = ENODATA;
    return -1;
  }

  /* Strip trailing whitespace and newline */
  p = hash_buf + len - 1;
  while (p >= hash_buf && (*p == '\r' || *p == '\n' || *p == ' '))
    *p-- = '\0';

  if (*hash_buf == '\0') {
    errno = ENODATA;
    return -1;
  }

  return 0;
}

/* ============================================================================
 * Password Verification
 * ============================================================================
 */

int verify_password(const struct syscall_ops *ops, const char *password,
                    const char *stored_hash) {
  struct crypt_data cd;
  char *computed;
  unsigned char diff;
  size_t i;
  size_t computed_len;
  size_t stored_len;

  if (!ops || !password || !stored_hash) {
    errno = EINVAL;
    return -1;
  }

  memset(&cd, 0, sizeof(cd));
  computed = ops->crypt_r(password, stored_hash, &cd);
  if (!computed || computed[0] == '*') {
    explicit_bzero(&cd, sizeof(cd));
    errno = EINVAL;
    return -1;
  }

  /*
   * Constant-time comparison using XOR accumulator.
   *
   * We iterate to max(computed_len, stored_len) rather than the minimum,
   * using zero as a "padding" byte for the shorter string.  This ensures
   * the loop runs for a fixed number of iterations regardless of how many
   * characters match, preventing a length-based timing side-channel.
   *
   * Without this, iterating only to min() would leak whether the supplied
   * password produced a hash of the same length as the stored one, giving
   * an attacker partial information about the stored hash format or algorithm.
   */
  computed_len = strlen(computed);
  stored_len = strlen(stored_hash);
  diff = (unsigned char)(computed_len != stored_len);

  {
    size_t max_len = computed_len > stored_len ? computed_len : stored_len;
    for (i = 0; i < max_len; i++) {
      unsigned char c = (i < computed_len) ? (unsigned char)computed[i] : 0;
      unsigned char s = (i < stored_len) ? (unsigned char)stored_hash[i] : 0;
      diff |= c ^ s;
    }
  }

  explicit_bzero(&cd, sizeof(cd));
  return (diff == 0) ? 0 : -1;
}

/* ============================================================================
 * Core Authentication Logic
 * ============================================================================
 */

/*
 * open_passwd_file - resolve the password file path and return an open fd
 *
 * Extracted from authenticate_vnc_user to keep error handling flat without
 * requiring goto.  Returns an open fd on success, -1 on failure.
 * On failure, *ret_pam is set to the appropriate PAM return code.
 */
static int open_passwd_file(const struct syscall_ops *ops,
                             const char *username, const char *file_override,
                             bool nullok, int *ret_pam) {
  char passwd_path[VNC_PATH_MAX];
  struct passwd pw;
  struct passwd *pwresult;
  char pwbuf[4096];
  struct stat st;
  int fd;

  if (file_override) {
    if (build_vnc_passwd_path(NULL, file_override, passwd_path,
                              sizeof(passwd_path)) < 0) {
      *ret_pam = PAM_AUTH_ERR;
      return -1;
    }
    fd = ops->open(passwd_path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
      *ret_pam = (errno == ENOENT && nullok) ? PAM_SUCCESS
                                             : PAM_AUTHINFO_UNAVAIL;
      return -1;
    }
    /*
     * Validate that the override path is a regular file.  Without this
     * check a FIFO at the override path would block on read indefinitely.
     * An attacker who can create a FIFO at a predictable path could cause
     * an auth hang; the S_ISREG guard closes that window.
     */
    if (ops->fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
      ops->close(fd);
      *ret_pam = PAM_AUTH_ERR;
      return -1;
    }
    return fd;
  }

  if (ops->getpwnam_r(username, &pw, pwbuf, sizeof(pwbuf), &pwresult) != 0 ||
      pwresult == NULL) {
    /*
     * USER ENUMERATION NOTE:
     * We intentionally return PAM_USER_UNKNOWN (not PAM_AUTH_ERR) for
     * users absent from the system password database.  This is standard
     * PAM module behaviour (cf. pam_unix) and lets PAM stacks use
     * pam_succeed_if/pam_listfile to gate access early.  An attacker
     * who can enumerate system users via other means (e.g., getent,
     * LDAP, SSH banners) gains no additional information from this
     * return code.  If concealment is required, wrap the auth stack with
     * a pam_faildelay and set 'nullok' so that missing-file paths also
     * collapse into a uniform delay before responding.
     */
    *ret_pam = PAM_USER_UNKNOWN;
    return -1;
  }

  if (!pw.pw_dir || pw.pw_dir[0] == '\0') {
    *ret_pam = PAM_USER_UNKNOWN;
    return -1;
  }

  if (build_vnc_passwd_path(pw.pw_dir, NULL, passwd_path,
                            sizeof(passwd_path)) < 0) {
    *ret_pam = PAM_AUTH_ERR;
    return -1;
  }

  fd = validate_passwd_file(ops, passwd_path, pw.pw_uid);
  if (fd < 0) {
    *ret_pam = (errno == ENOENT && nullok) ? PAM_SUCCESS
                                           : PAM_AUTHINFO_UNAVAIL;
    return -1;
  }

  return fd;
}

int authenticate_vnc_user(const struct syscall_ops *ops, const char *username,
                          const char *password, const char *file_override,
                          bool nullok) {
  char hash[VNC_HASH_BUF_SIZE];
  bool mlocked = false;
  int pam_err = PAM_AUTH_ERR;
  int fd;
  int result;

  if (!ops || !username || !password)
    return PAM_AUTH_ERR;

  /*
   * No password length check here — a password that is too long to have
   * been set by fnal-vncpasswd (> MAX_PASSWORD_LENGTH) is simply treated
   * as a wrong password.  crypt_r() will produce a different hash, and
   * verify_password() will return -1, yielding PAM_AUTH_ERR.
   * This keeps the authentication path free of policy decisions that
   * belong in the password-setting tool.
   *
   * mlock is called first, before any path resolution, so the password
   * is locked in RAM for the entire duration of the authentication.
   */
  if (ops->mlock(password, strlen(password) + 1) == 0)
    mlocked = true;

  fd = open_passwd_file(ops, username, file_override, nullok, &pam_err);
  if (fd < 0) {
    if (mlocked)
      ops->munlock(password, strlen(password) + 1);
    return pam_err;
  }

  /*
   * Mark fd consumed BEFORE calling read_passwd_hash.
   *
   * read_passwd_hash always closes fd (via fdopen + fclose), whether it
   * succeeds or fails.  Zeroing our local copy before the call ensures we
   * never attempt a second close on that descriptor.
   */
  {
    int consumed_fd = fd;
    fd = -1;
    if (read_passwd_hash(ops, consumed_fd, hash, sizeof(hash)) < 0) {
      explicit_bzero(hash, sizeof(hash));
      if (mlocked)
        ops->munlock(password, strlen(password) + 1);
      return PAM_AUTHINFO_UNAVAIL;
    }
  }

  result = (verify_password(ops, password, hash) == 0) ? PAM_SUCCESS
                                                        : PAM_AUTH_ERR;
  explicit_bzero(hash, sizeof(hash));
  if (mlocked)
    ops->munlock(password, strlen(password) + 1);
  return result;
}
