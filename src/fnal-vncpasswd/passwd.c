/**
 * fnal-vncpasswd/passwd.c - VNC password file operations
 *
 * Implements algorithm selection, password hashing, directory creation,
 * and atomic file write.  All helpers are static; only the four functions
 * declared in passwd.h are visible to other translation units.
 */

#include "passwd.h"

#include <crypt.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef HAVE_SELINUX
#include <selinux/restorecon.h>
#endif

#include "syscall_ops.h"
#include "vnc_path.h"

/* ============================================================================
 * Password file path resolution
 * ============================================================================
 */

int get_passwd_path(const struct syscall_ops *ops, uid_t uid, char *buf,
                    size_t buflen) {
  struct passwd pw;
  struct passwd *pwresult;
  char *pwbuf;
  char vnc_dir[PATH_MAX];
  long pw_bufsz;
  int rc;

  if (!ops || !buf || buflen == 0) {
    errno = EINVAL;
    return -1;
  }

  pw_bufsz = sysconf(_SC_GETPW_R_SIZE_MAX);
  // LCOV_EXCL_START
  if (pw_bufsz <= 0) {
    /*
     * Your system is too messed up to run on with any confidence
     */
    return -1;
  }
  // LCOV_EXCL_STOP

  pwbuf = ops->calloc(1, (size_t)pw_bufsz);
  if (!pwbuf) {
    errno = ENOMEM;
    return -1;
  }

  rc = ops->getpwuid_r(uid, &pw, pwbuf, (size_t)pw_bufsz, &pwresult);
  if (rc != 0 || pwresult == NULL) {
    free(pwbuf);
    errno = (rc != 0) ? rc : ENOENT;
    return -1;
  }

  if (build_vnc_dir_path(pw.pw_dir, vnc_dir, sizeof(vnc_dir)) < 0) {
    free(pwbuf);
    return -1;
  }

  if (ensure_vnc_dir(ops, vnc_dir) < 0) {
    free(pwbuf);
    return -1;
  }

  rc = build_vnc_passwd_path(pw.pw_dir, buf, buflen);
  free(pwbuf);
  return rc;
}

/* ============================================================================
 * Password hashing
 * ============================================================================
 */

/*
 * generate_salt - Fill a salt buffer for the given prefix
 *
 * Passing count=0 to crypt_gensalt_ra() signals libxcrypt to use the
 * algorithm’s compiled-in default cost.
 *
 * getrandom(2) may return fewer bytes than requested when the kernel
 * entropy pool is not yet fully seeded.  Loop until the full 32-byte
 * buffer is filled.
 *
 * Returns: 0 on success, -1 on error (errno set)
 */
static int generate_salt(const struct syscall_ops *ops, char *salt_buf,
                         size_t salt_len) {
  char rbytes[32];
  size_t total;
  char *salt;
  int n;

  total = 0;
  while (total < sizeof(rbytes)) {
    ssize_t got = ops->getrandom(rbytes + total, sizeof(rbytes) - total, 0);
    if (got < 0) {
      errno = EIO;
      return -1;
    }
    total += (size_t)got;
  }

  salt = ops->crypt_gensalt_ra(NULL, 0, rbytes, (int)sizeof(rbytes));
  memset(rbytes, 0, sizeof(rbytes));

  if (!salt) {
    errno = EINVAL;
    return -1;
  }

  n = snprintf(salt_buf, salt_len, "%s", salt);
  free(salt);

  if (n < 0 || (size_t)n >= salt_len) {
    errno = ERANGE;
    return -1;
  }

  return 0;
}

int hash_password(const struct syscall_ops *ops, const char *password,
                  char *hash_buf, size_t hash_len) {
  char salt[CRYPT_GENSALT_OUTPUT_SIZE];
  struct crypt_data cd;
  char *result;
  int n;

  if (!ops || !password || password[0] == '\0' || !prefix || !hash_buf ||
      hash_len == 0) {
    errno = EINVAL;
    return -1;
  }

  if (generate_salt(ops, salt, sizeof(salt)) < 0)
    return -1;

  memset(&cd, 0, sizeof(cd));
  result = ops->crypt_r(password, salt, &cd);

  /*
   * crypt_r signals failure in two ways:
   * - returns NULL (hard error: unsupported algorithm, internal fault)
   * - returns a string starting with '*' (invalid setting)
   * Both mean the hash is unusable and must not be written to disk.
   */
  if (!result || result[0] == '*') {
    memset(salt, 0, sizeof(salt));
    memset(&cd, 0, sizeof(cd));
    errno = EINVAL;
    return -1;
  }

  n = snprintf(hash_buf, hash_len, "%s", result);
  memset(salt, 0, sizeof(salt));
  memset(&cd, 0, sizeof(cd));

  if (n < 0 || (size_t)n >= hash_len) {
    errno = ERANGE;
    return -1;
  }

  return 0;
}

/* ============================================================================
 * Directory management
 * ============================================================================
 */

int ensure_vnc_dir(const struct syscall_ops *ops, const char *path) {
  char tmp[PATH_MAX];
  char *p;
  size_t plen;
  int n;

  if (!ops || !path || path[0] == '\0') {
    errno = EINVAL;
    return -1;
  }

  /*
   * Reject paths containing ".." as defence-in-depth.  VNC paths are
   * assembled from pw_dir (system password database) and VNC_PASSWD_DIR
   * (build-time constant); neither should contain ".." in normal operation.
   */
  plen = strlen(path);
  if (strstr(path, "/../") != NULL || strncmp(path, "../", 3) == 0 ||
      (plen >= 3 && strcmp(path + plen - 3, "/..") == 0) ||
      strcmp(path, "..") == 0) {
    errno = EINVAL;
    return -1;
  }

  n = snprintf(tmp, sizeof(tmp), "%s", path);
  if (n < 0 || (size_t)n >= sizeof(tmp)) {
    errno = ERANGE;
    return -1;
  }

  /*
   * Walk each intermediate component.  If a segment doesn't exist,
   * create it.  If it exists but is not a directory, fail.
   */
  for (p = tmp + 1; *p != '\0'; p++) {
    struct stat st;

    if (*p != '/')
      continue;

    *p = '\0';

    if (ops->lstat(tmp, &st) == 0) {
      if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        return -1;
      }
    } else if (errno == ENOENT) {
      if (ops->mkdir(tmp, 0700) < 0) {
        /*
         * EEXIST: another process created the directory between our
         * lstat() and mkdir().  Verify it is actually a directory.
         */
        if (errno != EEXIST)
          return -1;
        if (ops->lstat(tmp, &st) < 0 || !S_ISDIR(st.st_mode))
          return -1;
      }
    } else {
      return -1;
    }

    *p = '/';
  }

  /* Final component */
  {
    struct stat st;

    if (ops->lstat(tmp, &st) == 0)
      return S_ISDIR(st.st_mode) ? 0 : (errno = ENOTDIR, -1);

    if (errno != ENOENT)
      return -1;

    if (ops->mkdir(tmp, 0700) < 0) {
      if (errno != EEXIST)
        return -1;
      if (ops->lstat(tmp, &st) < 0 || !S_ISDIR(st.st_mode))
        return -1;
    }
  }

  return 0;
}

/* ============================================================================
 * Atomic password file write
 * ============================================================================
 */

int atomic_write_passwd(const struct syscall_ops *ops, const char *path,
                        const char *hash) {
  char tmp_path[PATH_MAX];
  int fd;
  ssize_t written;
  size_t hash_len;
  int saved_errno;
  int n;

  if (!ops || !path || !hash) {
    errno = EINVAL;
    return -1;
  }

  n = snprintf(tmp_path, sizeof(tmp_path), "%s.XXXXXX", path);
  if (n < 0 || (size_t)n >= sizeof(tmp_path)) {
    errno = ERANGE;
    return -1;
  }

  fd = ops->mkstemp(tmp_path);
  if (fd < 0)
    return -1;

  /*
   * Set permissions before writing any data.  If we wrote first and
   * fchmod failed, a window would exist where the file is readable.
   */
  if (ops->fchmod(fd, 0600) < 0) {
    saved_errno = errno;
    ops->close(fd);
    ops->unlink(tmp_path);
    errno = saved_errno;
    return -1;
  }

  hash_len = strlen(hash);
  written = ops->write(fd, hash, hash_len);
  if (written < 0 || (size_t)written != hash_len) {
    saved_errno = errno;
    ops->close(fd);
    ops->unlink(tmp_path);
    errno = saved_errno;
    return -1;
  }

  written = ops->write(fd, "\n", 1);
  if (written != 1) {
    saved_errno = errno;
    ops->close(fd);
    ops->unlink(tmp_path);
    errno = saved_errno;
    return -1;
  }

  if (ops->fsync(fd) < 0) {
    saved_errno = errno;
    ops->close(fd);
    ops->unlink(tmp_path);
    errno = saved_errno;
    return -1;
  }

  if (ops->close(fd) < 0) {
    saved_errno = errno;
    ops->unlink(tmp_path);
    errno = saved_errno;
    return -1;
  }

  /*
   * The temp file was created in the same directory as the destination
   * (path.XXXXXX alongside path), so it inherits the directory's SELinux
   * default type transition.  rename(2) never changes SELinux labels.
   * selinux_restorecon() corrects any label drift on the final path;
   * this is unconditional — non-fatal if it fails.
   */
  if (ops->rename(tmp_path, path) < 0) {
    saved_errno = errno;
    ops->unlink(tmp_path);
    errno = saved_errno;
    return -1;
  }

#ifdef HAVE_SELINUX
  (void)selinux_restorecon(path, 0);
#endif

  return 0;
}
