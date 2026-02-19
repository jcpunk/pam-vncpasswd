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
