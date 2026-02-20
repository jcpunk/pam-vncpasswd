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
 * - mlock() to prevent password pages from being swapped to disk
 */

#include "auth.h"

#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "autoconf.h"
#include "syscall_ops.h"
#include "vnc_crypto.h"
#include "vnc_path.h"

/* ============================================================================
 * PAM Argument Parsing
 * ============================================================================
 */

void parse_pam_args(int argc, const char **argv, struct pam_args *args) {
  if (!args)
    return;

  args->nullok = false;

  for (int i = 0; i < argc; i++) {
    if (!argv[i])
      continue;
    if (strcmp(argv[i], "nullok") == 0)
      args->nullok = true;
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
  int saved_errno;
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
    saved_errno = errno;
    ops->close(fd);
    errno = saved_errno;
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

  /*
   * Reject any executable bit or group/world read/write access.
   * A password file has no business being executable by anyone, and must
   * not be readable or writable by anyone other than the owning user.
   */
  if (st.st_mode &
      (S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH)) {
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
  int saved_errno;

  /*
   * Take unconditional ownership of fd on entry: every exit path below must
   * release it exactly once, either via ops->close() (before fdopen) or via
   * ops->fclose() (after fdopen, which transfers fd ownership to the stream).
   *
   * When ops is NULL we cannot call through the abstraction layer, so fall
   * back to bare close(2).  This is the only branch where ops is unavailable;
   * all subsequent ops calls below are safe.
   */
  if (!ops || !hash_buf || hash_len == 0) {
    if (fd >= 0) {
      if (ops)
        ops->close(fd);
      // LCOV_EXCL_START
      else
        /* should be impossible to get here */
        close(fd);
      // LCOV_EXCL_STOP
    }
    errno = EINVAL;
    return -1;
  }

  /*
   * Wrap the validated fd in a buffered FILE* for line reading.
   * On failure, fdopen(3) does NOT close fd, so we must close it ourselves.
   * On success, fd ownership transfers to fp; use only ops->fclose() from
   * here.
   */
  fp = ops->fdopen(fd, "r");
  if (!fp) {
    saved_errno = errno;
    ops->close(fd);
    errno = saved_errno;
    return -1;
  }

  result = ops->fgets(hash_buf, (int)hash_len, fp);
  ops->fclose(fp); /* closes the underlying fd regardless of fgets result */

  if (!result) {
    errno = ENODATA;
    return -1;
  }

  /*
   * Guard against empty buffer before pointer arithmetic: without this,
   * `hash_buf + strlen(hash_buf) - 1` underflows when the buffer is empty,
   * producing undefined behaviour in the trimming loop below.
   */
  len = strlen(hash_buf);
  if (len == 0) {
    errno = ENODATA;
    return -1;
  }

  /* Strip trailing CR, LF, and space; intentionally not isspace() to
   * avoid locale-dependent matching on a crypt(3) hash string. */
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
   * using zero as a padding byte for the shorter string.  This ensures the
   * loop runs for a fixed number of iterations regardless of how many
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
    size_t max_len = computed_len;
    if (stored_len > max_len)
      max_len = stored_len;
    for (i = 0; i < max_len; i++) {
      unsigned char c = 0;
      unsigned char s = 0;
      if (i < computed_len)
        c = (unsigned char)computed[i];
      if (i < stored_len)
        s = (unsigned char)stored_hash[i];
      diff |= c ^ s;
    }
  }

  explicit_bzero(&cd, sizeof(cd));
  if (diff == 0) {
    return 0;
  } else {
    errno = EINVAL;
    return -1;
  }
}

/* ============================================================================
 * Core Authentication Logic
 * ============================================================================
 */

/*
 * open_passwd_file - resolve the per-user password file path and return an
 * open fd.
 *
 * Extracted from authenticate_vnc_user() to keep error handling flat without
 * requiring goto.  Returns an open fd on success, -1 on failure.
 * On failure, *ret_pam is set to the appropriate PAM return code.
 */
static int open_passwd_file(const struct syscall_ops *ops, const char *username,
                            bool nullok, int *ret_pam) {
  char passwd_path[PATH_MAX];
  struct passwd pw;
  struct passwd *pwresult;
  /*
   * Buffer for getpwnam_r string fields (home dir, shell, GECOS, etc.).
   * PATH_MAX is wrong here: this is not a single path but the aggregate of
   * all passwd string fields.  sysconf(_SC_GETPW_R_SIZE_MAX) is the correct
   * runtime query but returns -1 on Linux (indeterminate), requiring a heap
   * fallback that adds allocation complexity for no practical gain.  4096 is
   * the conventional portable fixed size used by glibc's own documentation
   * and pam_unix; it is sufficient for all realistic passwd entries.
   */
  char pwbuf[4096];
  int fd;

  if (ops->getpwnam_r(username, &pw, pwbuf, sizeof(pwbuf), &pwresult) != 0 ||
      pwresult == NULL) {
    /*
     * USER ENUMERATION NOTE:
     * PAM_USER_UNKNOWN is intentional here (not PAM_AUTH_ERR).  This is
     * standard PAM module behaviour (cf. pam_unix) and lets PAM stacks use
     * pam_succeed_if/pam_listfile to gate access early.  An attacker who can
     * enumerate system users via other means (getent, LDAP, SSH banners)
     * gains no additional information from this return code.  If concealment
     * is required, wrap the auth stack with pam_faildelay.
     */
    *ret_pam = PAM_USER_UNKNOWN;
    return -1;
  }

  if (!pw.pw_dir || pw.pw_dir[0] == '\0') {
    *ret_pam = PAM_USER_UNKNOWN;
    return -1;
  }

  if (build_vnc_passwd_path(pw.pw_dir, passwd_path, sizeof(passwd_path)) < 0) {
    *ret_pam = PAM_AUTH_ERR;
    return -1;
  }

  if (fd < 0) {
    if (errno == ENOENT && nullok) {
      *ret_pam = PAM_SUCCESS;
    } else {
      *ret_pam = PAM_AUTHINFO_UNAVAIL;
    }
    return -1;
  }

  return fd;
}

int authenticate_vnc_user(const struct syscall_ops *ops, const char *username,
                          const char *password, bool nullok) {
  char hash[VNC_HASH_BUF_SIZE];
  bool mlocked = false;
  int pam_err = PAM_AUTH_ERR;
  int fd;
  int result;

  if (!ops || !username || !password)
    return PAM_AUTH_ERR;

  /*
   * No password length check here — a password too long to have been set by
   * fnal-vncpasswd (> MAX_PASSWORD_LENGTH) is treated as a wrong password.
   * crypt_r() will produce a different hash and verify_password() will return
   * -1.  Policy decisions belong in the password-setting tool, not here.
   *
   * mlock() is called before path resolution so the password is locked in RAM
   * for the entire duration of authentication.
   */
  if (ops->mlock(password, strlen(password) + 1) == 0)
    mlocked = true;

  fd = open_passwd_file(ops, username, nullok, &pam_err);
  if (fd < 0) {
    if (mlocked)
      ops->munlock(password, strlen(password) + 1);
    return pam_err;
  }

  /*
   * Transfer fd ownership to read_passwd_hash before the call.
   *
   * read_passwd_hash always closes fd (via fdopen + fclose) whether it
   * succeeds or fails.  Zeroing our local copy first ensures we never attempt
   * a second close on the same descriptor.
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

  if (verify_password(ops, password, hash) == 0) {
    result = PAM_SUCCESS;
  } else {
    result = PAM_AUTH_ERR;
  }
  explicit_bzero(hash, sizeof(hash));
  if (mlocked)
    ops->munlock(password, strlen(password) + 1);
  return result;
}
