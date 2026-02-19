/**
 * passwd.c - VNC password management implementation
 *
 * Implements password hashing and file management for fnal-vncpasswd.
 * See passwd.h for the design rationale.
 *
 * YESCRYPT SUPPORT:
 * yescrypt is the default on modern RHEL/Fedora.  Unlike SHA-crypt,
 * yescrypt uses a cost factor (not a round count) that is encoded by
 * crypt_gensalt_ra() into a parameter string (e.g., "j9T") rather than
 * the "rounds=N$" prefix used by SHA-512/SHA-256.  We read
 * YESCRYPT_COST_FACTOR from login.defs (default: DEFAULT_YESCRYPT_COST).
 */

#include <crypt.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#include "autoconf.h"
#include "passwd.h"
#include "syscall_ops.h"
#include "vnc_crypto.h"
#include "vnc_path.h"

/* ============================================================================
 * login.defs Parsing
 * ============================================================================
 */

/**
 * parse_login_defs_line - Parse a single login.defs directive
 * @line:      Input line (modified in place by whitespace stripping)
 * @key:       Directive name to match
 * @value_out: Output buffer for the directive value
 * @value_len: Size of value_out
 *
 * Returns: 1 if key found and value extracted, 0 otherwise
 */
static int parse_login_defs_line(char *line, const char *key, char *value_out,
                                 size_t value_len) {
  char *p;
  size_t key_len;

  if (!line || !key || !value_out || value_len == 0)
    return 0;

  p = line;

  /* Skip leading whitespace */
  while (*p == ' ' || *p == '\t')
    p++;

  /* Skip comment lines and blank lines */
  if (*p == '#' || *p == '\n' || *p == '\0')
    return 0;

  key_len = strlen(key);
  if (strncmp(p, key, key_len) != 0)
    return 0;

  /* Key must be followed by whitespace */
  p += key_len;
  if (*p != ' ' && *p != '\t')
    return 0;

  /* Skip whitespace between key and value */
  while (*p == ' ' || *p == '\t')
    p++;

  /* Empty value after key — treat as not found */
  if (*p == '\0' || *p == '\n' || *p == '#')
    return 0;

  /* Strip trailing whitespace and newline */
  char *end = p + strlen(p) - 1;
  while (end > p &&
         (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t'))
    *end-- = '\0';

  if (strlen(p) == 0)
    return 0;

  {
    int n = snprintf(value_out, value_len, "%s", p);
    if (n < 0 || (size_t)n >= value_len)
      return 0;
  }

  return 1;
}

int get_encrypt_settings(const struct syscall_ops *ops,
                         const char *login_defs_path,
                         struct encrypt_settings *settings) {
  FILE *fp;
  char line[LOGIN_DEFS_LINE_MAX];
  char value[ENCRYPT_METHOD_MAX];
  bool have_method = false;
  bool have_yescrypt_cost = false;
  bool have_sha_rounds = false;

  if (!ops || !login_defs_path || !settings) {
    errno = EINVAL;
    return -1;
  }

  /* Initialize with compiled-in defaults */
  {
    int n = snprintf(settings->method, sizeof(settings->method), "%s",
                     DEFAULT_ENCRYPT_METHOD);
    if (n < 0 || (size_t)n >= sizeof(settings->method)) {
      errno = EINVAL;
      return -1;
    }
  }
  settings->yescrypt_cost = (unsigned long)DEFAULT_YESCRYPT_COST;
  settings->sha_rounds = (unsigned long)DEFAULT_SHA_CRYPT_ROUNDS;

  fp = ops->fopen(login_defs_path, "r");
  if (!fp) {
    /* Missing login.defs is not an error — use defaults */
    return 0;
  }

  while (ops->fgets(line, (int)sizeof(line), fp) != NULL) {
    if (!have_method &&
        parse_login_defs_line(line, "ENCRYPT_METHOD", value, sizeof(value))) {
      int n = snprintf(settings->method, sizeof(settings->method), "%s", value);
      if (n > 0 && (size_t)n < sizeof(settings->method))
        have_method = true;
      continue;
    }

    /*
     * YESCRYPT_COST_FACTOR: controls the cost parameter passed to
     * crypt_gensalt_ra() for yescrypt.  NOT the same scale as
     * SHA_CRYPT_MAX_ROUNDS.
     */
    if (!have_yescrypt_cost &&
        parse_login_defs_line(line, "YESCRYPT_COST_FACTOR", value,
                              sizeof(value))) {
      char *endptr;
      unsigned long v = strtoul(value, &endptr, 10);
      if (*endptr == '\0' && v > 0) {
        settings->yescrypt_cost = v;
        have_yescrypt_cost = true;
      }
      continue;
    }

    /*
     * SHA_CRYPT_MAX_ROUNDS: controls the "rounds=N" prefix for
     * SHA-256 and SHA-512 salts.  Has no effect on yescrypt.
     */
    if (!have_sha_rounds && parse_login_defs_line(line, "SHA_CRYPT_MAX_ROUNDS",
                                                  value, sizeof(value))) {
      char *endptr;
      unsigned long v = strtoul(value, &endptr, 10);
      if (*endptr == '\0' && v > 0) {
        settings->sha_rounds = v;
        have_sha_rounds = true;
      }
      continue;
    }
  }

  ops->fclose(fp);
  return 0;
}

/* ============================================================================
 * Salt Generation
 * ============================================================================
 */

/**
 * method_to_prefix - Convert ENCRYPT_METHOD name to crypt prefix
 *
 * DES and MD5 are explicitly rejected: DES has no salt prefix and is
 * trivially brute-forceable; MD5-crypt is cryptographically broken.
 * Both are unsuitable for new password hashing and must not be accepted
 * even if present in login.defs.
 */
static int method_to_prefix(const char *method, char *prefix_out,
                             size_t prefix_len) {
  static const struct {
    const char *name;
    const char *prefix;
  } methods[] = {
    {"SHA512",   "$6$"},
    {"SHA256",   "$5$"},
    {"YESCRYPT", "$y$"},
    {"BLOWFISH", "$2b$"},
    {"BCRYPT",   "$2b$"},
    {NULL,       NULL},
  };

  /*
   * Reject insecure algorithms before consulting the table.
   * DES has no configurable salt prefix and is brute-forceable in seconds.
   * MD5-crypt ($1$) has been broken since the early 2000s.
   * Returning an error here causes hash_password() to fail loudly rather
   * than silently producing a weak hash.
   */
  if (strcmp(method, "DES") == 0 || strcmp(method, "MD5") == 0) {
    errno = EINVAL;
    return -1;
  }

  for (int i = 0; methods[i].name != NULL; i++) {
    if (strcmp(method, methods[i].name) == 0) {
      int n = snprintf(prefix_out, prefix_len, "%s", methods[i].prefix);
      if (n < 0 || (size_t)n >= prefix_len)
        return -1;
      return 0;
    }
  }

  errno = EINVAL;
  return -1;
}

int generate_salt(const struct syscall_ops *ops,
                  const struct encrypt_settings *settings, char *salt_buf,
                  size_t salt_len) {
  char prefix[16];
  unsigned long count;
  char rbytes[32];
  char *salt;

  if (!ops || !settings || !salt_buf || salt_len == 0) {
    errno = EINVAL;
    return -1;
  }

  if (method_to_prefix(settings->method, prefix, sizeof(prefix)) < 0)
    return -1;

  /*
   * Choose the cost parameter for crypt_gensalt_ra:
   * - yescrypt: YESCRYPT_COST_FACTOR (e.g., 5); libxcrypt encodes this
   *   internally as yescrypt parameters — NOT "rounds=N" syntax.
   * - SHA-256/SHA-512: SHA_CRYPT_MAX_ROUNDS (e.g., 65536); appended as
   *   "rounds=65536$" in the salt automatically.
   * - bcrypt: log2(rounds); 12 is the conventional safe default.
   */
  if (strcmp(settings->method, "YESCRYPT") == 0) {
    count = settings->yescrypt_cost;
  } else if (strcmp(settings->method, "BLOWFISH") == 0 ||
             strcmp(settings->method, "BCRYPT") == 0) {
    count = 12UL;
  } else {
    count = settings->sha_rounds;
  }

  /*
   * Read entropy in a loop until the full buffer is filled.
   *
   * getrandom(2) may return fewer bytes than requested when the kernel
   * entropy pool is not yet fully seeded (unlikely at normal runtime but
   * possible early in boot).  Looping guarantees we always pass a full
   * 32-byte entropy buffer to crypt_gensalt_ra regardless.
   *
   * explicit_bzero ensures no raw entropy bytes linger in memory after
   * the salt string has been written to salt_buf.
   */
  {
    size_t total = 0;
    while (total < sizeof(rbytes)) {
      ssize_t n = ops->getrandom(rbytes + total, sizeof(rbytes) - total, 0);
      if (n < 0) {
        explicit_bzero(rbytes, sizeof(rbytes));
        return -1;
      }
      total += (size_t)n;
    }
  }

  salt = ops->crypt_gensalt_ra(prefix, count, rbytes, (int)sizeof(rbytes));
  explicit_bzero(rbytes, sizeof(rbytes));

  if (!salt) {
    errno = EINVAL;
    return -1;
  }

  {
    int sn = snprintf(salt_buf, salt_len, "%s", salt);
    if (sn < 0 || (size_t)sn >= salt_len) {
      ops->free(salt);
      errno = ERANGE;
      return -1;
    }
  }

  ops->free(salt);
  return 0;
}

/* ============================================================================
 * Password Hashing
 * ============================================================================
 */

int hash_password(const struct syscall_ops *ops, const char *password,
                  const struct encrypt_settings *settings, char *hash_buf,
                  size_t hash_len) {
  char salt[SALT_BUF_SIZE];
  struct crypt_data cd;
  char *result;

  if (!ops || !password || *password == '\0' || !settings || !hash_buf ||
      hash_len == 0) {
    errno = EINVAL;
    return -1;
  }

  if (generate_salt(ops, settings, salt, sizeof(salt)) < 0)
    return -1;

  memset(&cd, 0, sizeof(cd));
  result = ops->crypt_r(password, salt, &cd);
  if (!result || result[0] == '*') {
    errno = EINVAL;
    explicit_bzero(salt, sizeof(salt));
    explicit_bzero(&cd, sizeof(cd));
    return -1;
  }

  {
    int n = snprintf(hash_buf, hash_len, "%s", result);
    if (n < 0 || (size_t)n >= hash_len) {
      explicit_bzero(salt, sizeof(salt));
      explicit_bzero(&cd, sizeof(cd));
      errno = ERANGE;
      return -1;
    }
  }

  explicit_bzero(salt, sizeof(salt));
  explicit_bzero(&cd, sizeof(cd));
  return 0;
}

/* ============================================================================
 * Directory Management
 * ============================================================================
 */

int ensure_dir(const struct syscall_ops *ops, const char *path) {
  struct stat st;
  char tmp[VNC_PATH_MAX];
  char *p;

  if (!ops || !path || path[0] == '\0') {
    errno = EINVAL;
    return -1;
  }

  /*
   * Reject paths containing directory traversal sequences ("..").
   * We build passwd paths from pw_dir (system password database) and
   * VNC_PASSWD_DIR (build-time constant), neither of which should contain
   * ".." in normal operation.  This is defence-in-depth against
   * misconfigured or adversarially crafted inputs.
   */
  {
    size_t plen = strlen(path);
    if (strstr(path, "/../") != NULL || strncmp(path, "../", 3) == 0 ||
        (plen >= 3 && strcmp(path + plen - 3, "/..") == 0) ||
        strcmp(path, "..") == 0) {
      errno = EINVAL;
      return -1;
    }
  }

  /*
   * Walk each path component and create it if missing.
   * This handles multi-segment VNC_PASSWD_DIR values like ".config/vnc"
   * without requiring the parent (~/.config) to already exist.
   */
  {
    int n = snprintf(tmp, sizeof(tmp), "%s", path);
    if (n < 0 || (size_t)n >= sizeof(tmp)) {
      errno = ERANGE;
      return -1;
    }
  }

  for (p = tmp + 1; *p != '\0'; p++) {
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
         * EEXIST race: another process created the directory between our
         * lstat() and mkdir().  Accept it if the result is a directory.
         */
        if (errno != EEXIST)
          return -1;
        struct stat eexist_st;
        if (ops->lstat(tmp, &eexist_st) < 0 || !S_ISDIR(eexist_st.st_mode))
          return -1;
      }
    } else {
      return -1;
    }

    *p = '/';
  }

  /* Create (or verify) the final component */
  if (ops->lstat(tmp, &st) == 0) {
    if (!S_ISDIR(st.st_mode)) {
      errno = ENOTDIR;
      return -1;
    }
    return 0;
  }

  if (errno != ENOENT)
    return -1;

  if (ops->mkdir(tmp, 0700) < 0) {
    if (errno != EEXIST)
      return -1;
    struct stat eexist_st;
    if (ops->lstat(tmp, &eexist_st) < 0 || !S_ISDIR(eexist_st.st_mode))
      return -1;
  }

  return 0;
}

/* ============================================================================
 * Atomic Password File Write
 * ============================================================================
 */

int atomic_write_passwd(const struct syscall_ops *ops, const char *path,
                        const char *hash) {
  char tmp_path[VNC_PATH_MAX];
  int fd;
  ssize_t written;
  size_t hash_len;
  int saved_errno;

  if (!ops || !path || !hash) {
    errno = EINVAL;
    return -1;
  }

  {
    int n = snprintf(tmp_path, sizeof(tmp_path), "%s.XXXXXX", path);
    if (n < 0 || (size_t)n >= sizeof(tmp_path)) {
      errno = ERANGE;
      return -1;
    }
  }

  fd = ops->mkstemp(tmp_path);
  if (fd < 0)
    return -1;

  /* Set permissions before writing any data */
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

  ops->close(fd);

  /*
   * rename(2) is SELinux-safe here because the temp file was created in
   * the same directory as the destination (path.XXXXXX alongside path).
   * Files created in a directory inherit its SELinux default type
   * transition, so the temp file already carries the correct label.
   * rename(2) never changes SELinux labels — it only moves the name.
   *
   * selinux_restorecon(3) handles the edge case where the parent directory
   * was itself created with the wrong SELinux context.  Non-fatal.
   */
  if (ops->rename(tmp_path, path) < 0) {
    ops->unlink(tmp_path);
    return -1;
  }

#ifdef HAVE_SELINUX
  (void)selinux_restorecon(path, 0);
#endif

  return 0;
}
