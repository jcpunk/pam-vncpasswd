/**
 * vnc_path.c - VNC password file path construction
 */

#include "vnc_path.h"

#include <errno.h>
#include <stdio.h>

#include "autoconf.h"

/**
 * build_vnc_dir_path - Construct the VNC configuration directory path
 * @home_dir: Absolute path to the user's home directory.
 * @buf:      Output buffer to receive the constructed path.
 * @buflen:   Size of @buf in bytes.
 *
 * Return: 0 on success, -1 on error (EINVAL: bad args; ERANGE: truncated).
 */
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

/**
 * build_vnc_passwd_path - Construct the VNC password file path
 * @home_dir: Absolute path to the user's home directory.
 * @buf:      Output buffer to receive the constructed path.
 * @buflen:   Size of @buf in bytes.
 *
 * Return: 0 on success, -1 on error (EINVAL: bad args; ERANGE: truncated).
 */
int build_vnc_passwd_path(const char *home_dir, char *buf, size_t buflen) {
  int n;

  if (!home_dir || home_dir[0] == '\0' || !buf || buflen == 0) {
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
