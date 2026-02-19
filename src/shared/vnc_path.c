/**
 * vnc_path.c - VNC password file path construction
 *
 * See vnc_path.h for design rationale.
 */

#include <errno.h>
#include <stdio.h>

#include "autoconf.h"
#include "vnc_path.h"

int build_vnc_dir_path(const char *home_dir, char *buf, size_t buflen) {
  int n;

  if (!home_dir || home_dir[0] == '\0' || !buf || buflen == 0) {
    errno = EINVAL;
    return -1;
  }

  n = snprintf(buf, buflen, "%s/%s", home_dir, VNC_PASSWD_DIR);
  if (n < 0 || (size_t)n >= buflen) {
    errno = ERANGE;
    return -1;
  }

  return 0;
}

int build_vnc_passwd_path(const char *home_dir, const char *file_override,
                          char *buf, size_t buflen) {
  int n;

  if (!buf || buflen == 0) {
    errno = EINVAL;
    return -1;
  }

  if (file_override) {
    /*
     * Validate file_override before use.
     *
     * Reject empty strings, absolute paths, and any path containing ".."
     * components.  The override is supplied by the PAM configuration or
     * the CLI -f flag; both are administrator-controlled, but we still
     * reject obviously unsafe values as defence-in-depth.
     *
     * We do NOT resolve symlinks or check existence here — that is the
     * responsibility of the caller (validate_passwd_file / ensure_dir).
     */
    if (file_override[0] == '\0') {
      errno = EINVAL;
      return -1;
    }

    /* Reject absolute paths: callers should provide relative-to-home or
     * explicit known-safe absolute paths via the non-override code path. */
    if (file_override[0] == '/') {
      errno = EINVAL;
      return -1;
    }

    /* Reject any ".." component */
    if (strcmp(file_override, "..") == 0 ||
        strncmp(file_override, "../", 3) == 0 ||
        strstr(file_override, "/..") != NULL) {
      errno = EINVAL;
      return -1;
    }

    n = snprintf(buf, buflen, "%s", file_override);
    if (n < 0 || (size_t)n >= buflen) {
      errno = ERANGE;
      return -1;
    }
    return 0;
  }

  if (!home_dir || home_dir[0] == '\0') {
    errno = EINVAL;
    return -1;
  }

  n = snprintf(buf, buflen, "%s/%s/%s", home_dir, VNC_PASSWD_DIR,
               VNC_PASSWD_FILE);
  if (n < 0 || (size_t)n >= buflen) {
    errno = ERANGE;
    return -1;
  }

  return 0;
}
