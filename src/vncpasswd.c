/**
 * vncpasswd.c - fnal-vncpasswd CLI tool
 *
 * Sets a per-user VNC password in ~/.config/vnc/fnal_vncpasswd using crypt(3)
 * hashing. The password file is compatible with pam_fnal_vncpasswd.so
 * authentication.
 *
 * USAGE:
 *   fnal-vncpasswd [-f file] [-n] [-h] [-v]
 *
 * OPTIONS:
 *   -f <file>   Write to a specific file instead of
 * ~/.config/vnc/fnal_vncpasswd -n          Non-interactive: read password from
 * stdin (no confirmation) -h          Show help -v          Show version
 *
 * SECURITY:
 * - Reads ENCRYPT_METHOD and cost factors from /etc/login.defs
 * - Uses crypt_gensalt_ra() for algorithm-aware salt generation
 * - yescrypt (RHEL default) uses YESCRYPT_COST_FACTOR, not rounds=N
 * - Writes password file atomically via mkstemp + rename
 * - Sets file permissions 0600 before writing data
 * - explicit_bzero() all sensitive buffers before exit
 */

#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include "autoconf.h"
#include "pam_fnal_vncpasswd.h"
#include "syscall_ops.h"

/* ============================================================================
 * Password Reading
 * ============================================================================
 */

/**
 * read_password_from_terminal - Read a password from the terminal
 * @prompt: Prompt string to display
 * @buf: Output buffer
 * @buflen: Size of output buffer
 *
 * Temporarily disables terminal echo (ECHO) so the password is not
 * displayed as the user types.
 *
 * Returns: number of characters read on success, -1 on error
 */
static ssize_t read_password_from_terminal(const char *prompt, char *buf,
                                           size_t buflen) {
  struct termios old_term, new_term;
  bool saved_term = false;
  int ttyfd;
  ssize_t nread = -1;

  ttyfd = open("/dev/tty", O_RDWR);
  if (ttyfd < 0) {
    /* Fall back to stdin if /dev/tty is not available */
    ttyfd = STDIN_FILENO;
  }

  if (tcgetattr(ttyfd, &old_term) == 0) {
    saved_term = true;
    new_term = old_term;
    new_term.c_lflag &= ~(tcflag_t)ECHO;
    new_term.c_lflag |= (tcflag_t)ECHONL;
    tcsetattr(ttyfd, TCSAFLUSH, &new_term);
  }

  if (write(STDOUT_FILENO, prompt, strlen(prompt)) < 0) {
    /* Non-fatal — prompt is cosmetic only */
  }

  if (buflen > 0) {
    nread = read(ttyfd, buf, buflen - 1);
    if (nread > 0) {
      /* Strip trailing newline */
      if (buf[nread - 1] == '\n')
        nread--;
      buf[nread] = '\0';
    }
  }

  if (ttyfd != STDIN_FILENO) {
    if (saved_term)
      tcsetattr(ttyfd, TCSAFLUSH, &old_term);
    close(ttyfd);
  } else {
    if (saved_term)
      tcsetattr(ttyfd, TCSAFLUSH, &old_term);
  }

  return nread;
}

/**
 * read_password_interactive - Read password interactively with confirmation
 * @buf: Output buffer
 * @buflen: Size of output buffer
 *
 * Prompts twice; returns -1 if the two entries do not match or if either
 * is below the minimum length.
 *
 * Returns: 0 on success, -1 on failure (errno set)
 */
int read_password_interactive(char *buf, size_t buflen) {
  char confirm[HASH_BUF_SIZE];
  ssize_t n1, n2;

  if (!buf || buflen < 2) {
    errno = EINVAL;
    return -1;
  }

  n1 = read_password_from_terminal("New VNC password: ", buf, buflen);
  if (n1 < 0) {
    errno = EIO;
    return -1;
  }

  /*
   * Enforce VNC protocol maximum password length.
   * The RFB protocol VNC Authentication type limits passwords to
   * MAX_PASSWORD_LENGTH (8) characters. Longer passwords would be
   * silently truncated by VNC clients, creating a confusing mismatch
   * between what the user typed and what was actually authenticated.
   */
  if ((size_t)n1 > (size_t)MAX_PASSWORD_LENGTH) {
    fprintf(stderr,
            "Password too long: the VNC protocol limits passwords to "
            "%d characters.\n",
            MAX_PASSWORD_LENGTH);
    explicit_bzero(buf, buflen);
    errno = EINVAL;
    return -1;
  }

  if ((size_t)n1 < (size_t)MIN_PASSWORD_LENGTH) {
    fprintf(stderr, "Password too short (minimum %d characters).\n",
            MIN_PASSWORD_LENGTH);
    explicit_bzero(buf, buflen);
    errno = EINVAL;
    return -1;
  }

  n2 = read_password_from_terminal("Confirm VNC password: ", confirm,
                                   sizeof(confirm));
  if (n2 < 0) {
    explicit_bzero(buf, buflen);
    explicit_bzero(confirm, sizeof(confirm));
    errno = EIO;
    return -1;
  }

  if (n1 != n2 || memcmp(buf, confirm, (size_t)n1) != 0) {
    fprintf(stderr, "Passwords do not match.\n");
    explicit_bzero(buf, buflen);
    explicit_bzero(confirm, sizeof(confirm));
    errno = EINVAL;
    return -1;
  }

  explicit_bzero(confirm, sizeof(confirm));
  return 0;
}

/**
 * read_password_noninteractive - Read password from stdin (single line)
 * @buf: Output buffer
 * @buflen: Size of output buffer
 *
 * Reads one line from stdin, strips trailing newline.
 * Used with the -n flag for scripted operation.
 *
 * Returns: 0 on success, -1 on failure (errno set)
 */
int read_password_noninteractive(char *buf, size_t buflen) {
  ssize_t nread;

  if (!buf || buflen < 2) {
    errno = EINVAL;
    return -1;
  }

  nread = read(STDIN_FILENO, buf, buflen - 1);
  if (nread <= 0) {
    errno = EIO;
    return -1;
  }

  /* Strip trailing newline */
  if (nread > 0 && buf[nread - 1] == '\n')
    nread--;
  buf[nread] = '\0';

  if ((size_t)nread < (size_t)MIN_PASSWORD_LENGTH) {
    fprintf(stderr, "Password too short (minimum %d characters).\n",
            MIN_PASSWORD_LENGTH);
    explicit_bzero(buf, buflen);
    errno = EINVAL;
    return -1;
  }

  /*
   * Enforce VNC protocol maximum password length.
   * The RFB protocol VNC Authentication type limits passwords to
   * MAX_PASSWORD_LENGTH (8) characters.
   */
  if ((size_t)nread > (size_t)MAX_PASSWORD_LENGTH) {
    fprintf(stderr,
            "Password too long: the VNC protocol limits passwords to "
            "%d characters.\n",
            MAX_PASSWORD_LENGTH);
    explicit_bzero(buf, buflen);
    errno = EINVAL;
    return -1;
  }

  return 0;
}

/* ============================================================================
 * Main
 * ============================================================================
 */

#ifndef VNCPASSWD_TESTING
static void usage(const char *prog) {
  fprintf(stderr,
          "Usage: %s [OPTIONS]\n"
          "\n"
          "Set the VNC password for use with pam_fnal_vncpasswd.so\n"
          "\n"
          "Options:\n"
          "  -f <file>  Write to a specific file (default: "
          "~/.config/vnc/fnal_vncpasswd)\n"
          "  -n         Non-interactive: read password from stdin\n"
          "  -h         Show this help\n"
          "  -v         Show version\n",
          prog);
}

int main(int argc, char *argv[]) {
  const char *file_override = NULL;
  bool noninteractive = false;
  int opt;

  while ((opt = getopt(argc, argv, "f:nhv")) != -1) {
    switch (opt) {
    case 'f':
      file_override = optarg;
      break;
    case 'n':
      noninteractive = true;
      break;
    case 'h':
      usage(argv[0]);
      return EXIT_SUCCESS;
    case 'v':
      printf("%s %s\n", PROJECT_NAME, VERSION);
      return EXIT_SUCCESS;
    default:
      usage(argv[0]);
      return EXIT_FAILURE;
    }
  }

  /* Read encryption settings from login.defs */
  struct encrypt_settings settings;
  if (get_encrypt_settings(&syscall_ops_default, LOGIN_DEFS_PATH, &settings) <
      0) {
    fprintf(stderr, "Failed to read encryption settings: %s\n",
            strerror(errno));
    return EXIT_FAILURE;
  }

  /* Determine the password file path */
  char passwd_path[PAM_ARGS_FILE_MAX];
  if (file_override) {
    if (snprintf(passwd_path, sizeof(passwd_path), "%s", file_override) < 0) {
      fprintf(stderr, "File path too long\n");
      return EXIT_FAILURE;
    }
  } else {
    /* Get current user's home directory */
    struct passwd pw;
    struct passwd *pwresult;
    char pwbuf[4096];

    if (getpwuid_r(getuid(), &pw, pwbuf, sizeof(pwbuf), &pwresult) != 0 ||
        pwresult == NULL) {
      fprintf(stderr, "Cannot determine home directory\n");
      return EXIT_FAILURE;
    }

    char vnc_dir[PAM_ARGS_FILE_MAX];
    if (snprintf(vnc_dir, sizeof(vnc_dir), "%s/%s", pw.pw_dir, VNC_PASSWD_DIR) <
        0) {
      fprintf(stderr, "Home directory path too long\n");
      return EXIT_FAILURE;
    }

    if (ensure_dir(&syscall_ops_default, vnc_dir) < 0) {
      fprintf(stderr, "Cannot create %s: %s\n", vnc_dir, strerror(errno));
      return EXIT_FAILURE;
    }

    if (snprintf(passwd_path, sizeof(passwd_path), "%s/%s", vnc_dir,
                 VNC_PASSWD_FILE) < 0) {
      fprintf(stderr, "Password path too long\n");
      return EXIT_FAILURE;
    }
  }

  /* Read the new password */
  char password[HASH_BUF_SIZE];
  int rc;

  if (noninteractive) {
    rc = read_password_noninteractive(password, sizeof(password));
  } else {
    rc = read_password_interactive(password, sizeof(password));
  }

  if (rc < 0) {
    explicit_bzero(password, sizeof(password));
    return EXIT_FAILURE;
  }

  /* Hash the password */
  char hash[HASH_BUF_SIZE];
  if (hash_password(&syscall_ops_default, password, &settings, hash,
                    sizeof(hash)) < 0) {
    fprintf(stderr, "Failed to hash password: %s\n", strerror(errno));
    explicit_bzero(password, sizeof(password));
    explicit_bzero(hash, sizeof(hash));
    return EXIT_FAILURE;
  }
  explicit_bzero(password, sizeof(password));

  /* Write the hash atomically */
  if (atomic_write_passwd(&syscall_ops_default, passwd_path, hash) < 0) {
    fprintf(stderr, "Failed to write password file %s: %s\n", passwd_path,
            strerror(errno));
    explicit_bzero(hash, sizeof(hash));
    return EXIT_FAILURE;
  }

  explicit_bzero(hash, sizeof(hash));
  printf("VNC password updated successfully.\n");
  return EXIT_SUCCESS;
}
#endif /* VNCPASSWD_TESTING */
