/**
 * fnal-vncpasswd/main.c - fnal-vncpasswd CLI tool
 *
 * Sets or removes the per-user VNC password stored at
 * ~/.config/vnc/fnal-vncpasswd
 * The file is compatible with the pam_fnal_vncpasswd PAM module.
 *
 * USAGE:
 *   fnal-vncpasswd [-h|--help] [--version]
 *
 * SECURITY:
 * - Uses libxcrypt's compiled-in default algorithm
 * - Passes count=0 to crypt_gensalt_ra (libxcrypt algorithm defaults)
 * - Writes password file atomically via mkstemp + rename
 * - Sets file permissions 0600 before writing data
 * - Calls selinux_restorecon() after rename when built with SELinux
 */

#include <bsd/readpassphrase.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_SELINUX
#include <selinux/restorecon.h>
#endif

#include "autoconf.h"
#include "passwd.h"
#include "syscall_ops.h"
#include "vnc_crypto.h"

/* ============================================================================
 * Forward declarations for internal functions
 * ============================================================================
 */
static void print_help(void) __attribute__((cold));
static int read_password(char *buf, size_t buflen)
    __attribute__((warn_unused_result));

/* ============================================================================
 * Terminal password reading
 * ============================================================================
 */

/**
 * read_password - Read a new password interactively with confirmation
 * @buf:    Output buffer
 * @buflen: Size of @buf
 *
 * Prompts twice via readpassphrase(3bsd); verifies the entries match and
 * fall within [VNC_MIN_PASSWORD_LENGTH, VNC_MAX_PASSWORD_LENGTH].
 *
 * readpassphrase opens /dev/tty directly, suppresses echo, and restores
 * the terminal on SIGINT/SIGTERM/SIGHUP — no signal handling is required
 * here.  RPP_REQUIRE_TTY causes it to fail if no controlling terminal is
 * available rather than silently reading from stdin.
 *
 * Returns: 0 on success, -1 on failure (message printed to stderr)
 */
static int read_password(char *buf, size_t buflen) {
  char confirm[VNC_HASH_BUF_SIZE] = {0};
  size_t n1, n2;

  if (buf == NULL || buflen < 2) {
    errno = EINVAL;
    return -1;
  }

  if (readpassphrase("New VNC password: ", buf, buflen,
                     RPP_ECHO_OFF | RPP_REQUIRE_TTY) == NULL) {
    (void)fprintf(stderr, "Error reading password.\n");
    errno = EIO;
    return -1;
  }

  n1 = strlen(buf);

  if (n1 < (size_t)VNC_MIN_PASSWORD_LENGTH) {
    (void)fprintf(stderr, "Password too short (minimum %d characters).\n",
                  VNC_MIN_PASSWORD_LENGTH);
    (void)explicit_bzero(buf, buflen);
    errno = EINVAL;
    return -1;
  }

  if (n1 > (size_t)VNC_MAX_PASSWORD_LENGTH) {
    (void)fprintf(stderr, "Password too long (maximum %d characters).\n",
                  VNC_MAX_PASSWORD_LENGTH);
    (void)explicit_bzero(buf, buflen);
    errno = EINVAL;
    return -1;
  }

  if (readpassphrase("Confirm VNC password: ", confirm, sizeof(confirm),
                     RPP_ECHO_OFF | RPP_REQUIRE_TTY) == NULL) {
    (void)explicit_bzero(buf, buflen);
    (void)explicit_bzero(confirm, sizeof(confirm));
    (void)fprintf(stderr, "Error reading confirmation.\n");
    errno = EIO;
    return -1;
  }

  n2 = strlen(confirm);

  if (n1 != n2 || memcmp(buf, confirm, n1) != 0) {
    (void)fprintf(stderr, "Passwords do not match.\n");
    (void)explicit_bzero(buf, buflen);
    (void)explicit_bzero(confirm, sizeof(confirm));
    errno = EINVAL;
    return -1;
  }

  (void)explicit_bzero(confirm, sizeof(confirm));
  return 0;
}

/* ============================================================================
 * Main
 * ============================================================================
 */

static void print_help(void) {
  (void)printf("Usage: %s [OPTIONS]\n", PROJECT_NAME);
  (void)printf("Version: %s\n", VERSION);
  (void)printf("\n");
  (void)printf("Set the VNC password used by pam_fnal_vncpasswd.\n");
  (void)printf("\n");
  (void)printf("  -h, --help       Show this help\n");
  (void)printf("      --version    Show version\n");
}

int main(int argc, char *argv[]) {
  int opt = 0;
  char passwd_path[PATH_MAX] = {0};
  char password[VNC_MAX_PASSWORD_LENGTH] = {0};
  char hash[VNC_HASH_BUF_SIZE] = {0};

  static const struct option long_opts[] = {
      {"help", no_argument, NULL, 'h'},
      {"version", no_argument, NULL, 1000},
      {NULL, 0, NULL, 0}};

  while ((opt = getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
    switch (opt) {
    case 'h':
      print_help();
      exit(EXIT_SUCCESS);
    case 1000: /* --version */
      (void)printf("%s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
      exit(EXIT_SUCCESS);
    default:
      print_help();
      exit(EXIT_FAILURE);
    }
  }

  if (get_passwd_path(&syscall_ops_default, getuid(), passwd_path,
                      sizeof(passwd_path)) < 0) {
    (void)fprintf(stderr, "Cannot determine password file path: %s\n",
                  strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (read_password(password, sizeof(password)) < 0) {
    (void)explicit_bzero(password, sizeof(password));
    exit(EXIT_FAILURE);
  }

  if (hash_password(&syscall_ops_default, password, hash, sizeof(hash)) < 0) {
    (void)fprintf(stderr, "Failed to hash password: %s\n", strerror(errno));
    (void)explicit_bzero(password, sizeof(password));
    (void)explicit_bzero(hash, sizeof(hash));
    exit(EXIT_FAILURE);
  }
  (void)explicit_bzero(password, sizeof(password));

  if (atomic_write_passwd_file(&syscall_ops_default, passwd_path, hash) < 0) {
    (void)fprintf(stderr, "Failed to write %s: %s\n", passwd_path,
                  strerror(errno));
    (void)explicit_bzero(hash, sizeof(hash));
    exit(EXIT_FAILURE);
  }
  (void)explicit_bzero(hash, sizeof(hash));

  (void)printf("VNC password updated successfully.\n");
  exit(EXIT_SUCCESS);
}
