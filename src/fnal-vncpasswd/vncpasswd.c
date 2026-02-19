/**
 * vncpasswd.c - fnal-vncpasswd CLI tool
 *
 * Sets a per-user VNC password in ~/.config/vnc/fnal-vncpasswd using crypt(3)
 * hashing.  The password file is compatible with pam_fnal_vncpasswd.so.
 *
 * USAGE:
 *   fnal-vncpasswd [-f file] [-n] [-h] [-v]
 *
 * OPTIONS:
 *   -f <file>   Write to a specific file instead of default
 *   -n          Non-interactive: read password from stdin
 *   -h          Show help
 *   -v          Show version
 *
 * SECURITY:
 * - Reads ENCRYPT_METHOD and cost factors from /etc/login.defs
 * - Uses crypt_gensalt_ra() for algorithm-aware salt generation
 * - yescrypt (RHEL default) uses YESCRYPT_COST_FACTOR, not rounds=N
 * - Writes password file atomically via mkstemp + rename
 * - Sets file permissions 0600 before writing data
 * - explicit_bzero() all sensitive buffers before exit
 */

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include "autoconf.h"
#include "passwd.h"
#include "syscall_ops.h"
#include "vnc_crypto.h"
#include "vnc_path.h"

/* ============================================================================
 * Terminal State Restoration on Signal
 * ============================================================================
 */

/*
 * Module-scope state for terminal restoration.
 *
 * read_password_from_terminal disables terminal echo while reading.  If the
 * process is interrupted (Ctrl-C, kill, hangup) while echo is off, the
 * terminal would remain in a non-echoing state — confusing and frustrating
 * for the user.
 *
 * A signal handler registered before disabling echo restores the terminal
 * before the process exits.  The handler uses only async-signal-safe
 * functions (tcsetattr, raise, signal) as required by POSIX.
 *
 * WHY STATIC/MODULE SCOPE:
 * Signal handlers cannot receive parameters, so the terminal state that must
 * be restored must be reachable from the handler.  These variables are written
 * once (inside read_password_from_terminal, while signals are temporarily
 * blocked by sigprocmask) and read once (in the handler).
 *
 * g_term_fd is initialised to -1 so the handler can safely skip restoration
 * when no terminal has been opened yet.
 */
static volatile sig_atomic_t g_term_saved = 0;
static int                   g_term_fd    = -1;
static struct termios        g_term_old;

static void restore_terminal_on_signal(int signo) {
  if (g_term_saved && g_term_fd >= 0)
    tcsetattr(g_term_fd, TCSAFLUSH, (struct termios *)&g_term_old);
  signal(signo, SIG_DFL);
  raise(signo);
}

/* ============================================================================
 * Password Reading
 * ============================================================================
 */

/**
 * read_password_from_terminal - Read a password from the terminal
 * @prompt: Prompt string to display
 * @buf:    Output buffer
 * @buflen: Size of output buffer
 *
 * Temporarily disables terminal echo (ECHO) so the password is not
 * displayed as the user types.  Registers a signal handler before disabling
 * echo so that SIGINT/SIGTERM/SIGHUP restore the terminal before exit.
 *
 * Returns: number of characters read (excluding newline) on success, -1 on error
 */
static ssize_t read_password_from_terminal(const char *prompt, char *buf,
                                           size_t buflen) {
  struct termios new_term;
  bool saved_term = false;
  int ttyfd;
  ssize_t nread = -1;

  struct sigaction sa_new, sa_old_int, sa_old_term, sa_old_hup;

  ttyfd = open("/dev/tty", O_RDWR);
  if (ttyfd < 0) {
    /* Fall back to stdin if /dev/tty is not available */
    ttyfd = STDIN_FILENO;
  }

  if (tcgetattr(ttyfd, &g_term_old) == 0) {
    /*
     * Save terminal state into the module-scope buffer so the signal
     * handler can reach it, then install handlers before disabling echo.
     * sigprocmask is not strictly necessary here (the write to g_term_old
     * and the tcsetattr are not an atomic pair), but the window between
     * saving the state and installing the handler is a single function call,
     * which is acceptably small for a CLI password tool.
     */
    g_term_fd = ttyfd;

    sa_new.sa_handler = restore_terminal_on_signal;
    sigemptyset(&sa_new.sa_mask);
    sa_new.sa_flags = SA_RESETHAND; /* remove handler after first delivery */

    sigaction(SIGINT,  &sa_new, &sa_old_int);
    sigaction(SIGTERM, &sa_new, &sa_old_term);
    sigaction(SIGHUP,  &sa_new, &sa_old_hup);

    /* Disable echo, enable newline echo so the cursor advances */
    new_term = g_term_old;
    new_term.c_lflag &= ~(tcflag_t)ECHO;
    new_term.c_lflag |= (tcflag_t)ECHONL;
    if (tcsetattr(ttyfd, TCSAFLUSH, &new_term) == 0) {
      saved_term = true;
      g_term_saved = 1;
    }
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

  /* Restore terminal and deregister signal handlers */
  if (saved_term) {
    tcsetattr(ttyfd, TCSAFLUSH, &g_term_old);
    g_term_saved = 0;
  }

  sigaction(SIGINT,  &sa_old_int,  NULL);
  sigaction(SIGTERM, &sa_old_term, NULL);
  sigaction(SIGHUP,  &sa_old_hup,  NULL);

  if (ttyfd != STDIN_FILENO)
    close(ttyfd);

  g_term_fd = -1;
  return nread;
}

int read_password_interactive(char *buf, size_t buflen) {
  char confirm[VNC_HASH_BUF_SIZE];
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
   * MAX_PASSWORD_LENGTH (8) characters.  Longer passwords would be
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

int read_password_noninteractive(char *buf, size_t buflen) {
  size_t total = 0;

  if (!buf || buflen < 2) {
    errno = EINVAL;
    return -1;
  }

  /*
   * Read in a loop to handle partial reads and EINTR.
   *
   * A single read(2) is not guaranteed to return all available bytes.
   * We stop when: a newline is encountered, the buffer is full, read
   * returns 0 (EOF), or an unrecoverable error occurs.
   */
  while (total < buflen - 1) {
    ssize_t n = read(STDIN_FILENO, buf + total, buflen - 1 - total);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      explicit_bzero(buf, buflen);
      errno = EIO;
      return -1;
    }
    if (n == 0)
      break; /* EOF */
    total += (size_t)n;
    if (buf[total - 1] == '\n')
      break; /* got a complete line */
  }

  if (total == 0) {
    errno = EIO;
    return -1;
  }

  /* Strip single trailing newline */
  if (total > 0 && buf[total - 1] == '\n')
    total--;
  buf[total] = '\0';

  if (total < (size_t)MIN_PASSWORD_LENGTH) {
    fprintf(stderr, "Password too short (minimum %d characters).\n",
            MIN_PASSWORD_LENGTH);
    explicit_bzero(buf, buflen);
    errno = EINVAL;
    return -1;
  }

  if (total > (size_t)MAX_PASSWORD_LENGTH) {
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
          "~/.config/vnc/fnal-vncpasswd)\n"
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
      printf("%s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
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
  char passwd_path[VNC_PATH_MAX];
  if (file_override) {
    if (build_vnc_passwd_path(NULL, file_override, passwd_path,
                              sizeof(passwd_path)) < 0) {
      fprintf(stderr, "File path invalid or too long\n");
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

    char vnc_dir[VNC_PATH_MAX];
    if (build_vnc_dir_path(pw.pw_dir, vnc_dir, sizeof(vnc_dir)) < 0) {
      fprintf(stderr, "Home directory path too long\n");
      return EXIT_FAILURE;
    }

    if (ensure_dir(&syscall_ops_default, vnc_dir) < 0) {
      fprintf(stderr, "Cannot create %s: %s\n", vnc_dir, strerror(errno));
      return EXIT_FAILURE;
    }

    if (build_vnc_passwd_path(pw.pw_dir, NULL, passwd_path,
                              sizeof(passwd_path)) < 0) {
      fprintf(stderr, "Password path too long\n");
      return EXIT_FAILURE;
    }
  }

  /* Read the new password */
  char password[VNC_HASH_BUF_SIZE];
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
  char hash[VNC_HASH_BUF_SIZE];
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
