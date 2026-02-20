/**
 * fnal-vncpasswd/main.c - fnal-vncpasswd CLI tool
 *
 * Sets or removes the per-user VNC password stored at
 * ~/.config/vnc/fnal-vncpasswd
 * The file is compatible with the pam_fnal_vncpasswd PAM module.
 *
 * USAGE:
 *   fnal-vncpasswd [-h] [-v]
 *
 * OPTIONS:
 *   -h   Show help
 *   -v   Show version
 *
 * SECURITY:
 * - Reads ENCRYPT_METHOD from /etc/login.defs; defaults to yescrypt
 * - Passes count=0 to crypt_gensalt_ra (libxcrypt algorithm defaults)
 * - Writes password file atomically via mkstemp + rename
 * - Sets file permissions 0600 before writing data
 * - Calls selinux_restorecon() after rename when built with SELinux
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#ifdef HAVE_SELINUX
#include <selinux/restorecon.h>
#endif

#include "autoconf.h"
#include "passwd.h"
#include "syscall_ops.h"
#include "vnc_crypto.h"
#include "vnc_path.h"

/* ============================================================================
 * Terminal state — module scope for signal handler access
 * ============================================================================
 */

/*
 * termios echo suppression is active between the tcsetattr(noecho) and
 * tcsetattr(restore) calls in read_from_terminal().  If the process is
 * interrupted in that window the terminal would remain non-echoing.
 *
 * The signal handler restores the saved termios state and re-raises the
 * signal so the default action (termination) proceeds normally.
 *
 * tcsetattr(2) is not listed as async-signal-safe by POSIX, but the same
 * risk is accepted by every terminal-aware CLI tool (ssh, sudo, passwd).
 * g_term_suppressed gates the restore so the handler is safe to call at
 * any point outside the suppression window.
 */
static volatile sig_atomic_t g_term_suppressed = 0;
static int g_tty_fd = -1;
static struct termios g_saved_termios;

static void restore_terminal_on_signal(int signo) {
  if (g_term_suppressed) {
    (void)tcsetattr(g_tty_fd, TCSAFLUSH, &g_saved_termios);
  }
  signal(signo, SIG_DFL);
  raise(signo);
}

static void arm_signal_handlers(struct sigaction *old_int,
                                struct sigaction *old_term,
                                struct sigaction *old_hup) {
  struct sigaction sa;
  sa.sa_handler = restore_terminal_on_signal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGINT, &sa, old_int);
  sigaction(SIGTERM, &sa, old_term);
  sigaction(SIGHUP, &sa, old_hup);
}

static void disarm_signal_handlers(const struct sigaction *old_int,
                                   const struct sigaction *old_term,
                                   const struct sigaction *old_hup) {
  sigaction(SIGINT, old_int, NULL);
  sigaction(SIGTERM, old_term, NULL);
  sigaction(SIGHUP, old_hup, NULL);
}

/* ============================================================================
 * Terminal password reading
 * ============================================================================
 */

/**
 * read_from_terminal - Read one password line from the terminal via termios
 * @prompt: Prompt string to display; may be NULL
 * @buf:    Output buffer; NUL-terminated on success
 * @buflen: Size of @buf
 *
 * Opens /dev/tty directly so stdin/stdout redirection does not affect the
 * prompt or the read.  ECHO is cleared in a copy of the current termios
 * state; the original is restored unconditionally before returning.
 * A trailing newline is stripped from the result.
 *
 * Returns: number of characters read (excluding NUL), -1 on error
 */
static ssize_t read_from_terminal(const char *prompt, char *buf,
                                  size_t buflen) {
  struct termios noecho;
  struct sigaction old_int, old_term, old_hup;
  FILE *tty;
  ssize_t nread = -1;
  size_t len;

  if (buf == NULL || buflen < 2) {
    return -1;
  }

  tty = fopen("/dev/tty", "r+");
  if (tty == NULL) {
    return -1;
  }

  g_tty_fd = fileno(tty);

  if (tcgetattr(g_tty_fd, &g_saved_termios) != 0) {
    (void)fclose(tty);
    g_tty_fd = -1;
    return -1;
  }

  noecho = g_saved_termios;
  noecho.c_lflag &= ~((tcflag_t)ECHO);

  if (tcsetattr(g_tty_fd, TCSAFLUSH, &noecho) != 0) {
    (void)fclose(tty);
    g_tty_fd = -1;
    return -1;
  }

  arm_signal_handlers(&old_int, &old_term, &old_hup);
  g_term_suppressed = 1;

  if (prompt != NULL) {
    (void)fputs(prompt, tty);
    (void)fflush(tty);
  }

  if (fgets(buf, (int)buflen, tty) != NULL) {
    len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
      buf[--len] = '\0';
    }
    nread = (ssize_t)len;
  }

  g_term_suppressed = 0;
  (void)tcsetattr(g_tty_fd, TCSAFLUSH, &g_saved_termios);

  /*
   * Emit a newline: fgets consumed Enter but ECHO was suppressed, so the
   * cursor would otherwise remain on the prompt line.
   */
  (void)fputs("\n", tty);
  (void)fflush(tty);

  disarm_signal_handlers(&old_int, &old_term, &old_hup);

  g_tty_fd = -1;
  (void)fclose(tty);
  return nread;
}

/**
 * read_password - Read a new password interactively with confirmation
 * @buf:    Output buffer
 * @buflen: Size of @buf
 *
 * Prompts twice; verifies the entries match and fall within
 * [VNC_MIN_PASSWORD_LENGTH, VNC_MAX_PASSWORD_LENGTH].
 *
 * Returns: 0 on success, -1 on failure (message printed to stderr)
 */
static int read_password(char *buf, size_t buflen) {
  char confirm[VNC_HASH_BUF_SIZE] = {0};
  ssize_t n1 = -1, n2 = -1;

  if (buf == NULL || buflen < 2) {
    errno = EINVAL;
    return -1;
  }

  n1 = read_from_terminal("New VNC password: ", buf, buflen);
  if (n1 < 0) {
    (void)fprintf(stderr, "Error reading password.\n");
    errno = EIO;
    return -1;
  }

  if ((size_t)n1 < (size_t)VNC_MIN_PASSWORD_LENGTH) {
    (void)fprintf(stderr, "Password too short (minimum %d characters).\n",
                  VNC_MIN_PASSWORD_LENGTH);
    (void)explicit_bzero(buf, buflen);
    errno = EINVAL;
    return -1;
  }

  if ((size_t)n1 > (size_t)VNC_MAX_PASSWORD_LENGTH) {
    (void)fprintf(stderr, "Password too long (maximum %d characters).\n",
                  VNC_MAX_PASSWORD_LENGTH);
    (void)explicit_bzero(buf, buflen);
    errno = EINVAL;
    return -1;
  }

  n2 = read_from_terminal("Confirm VNC password: ", confirm, sizeof(confirm));
  if (n2 < 0) {
    (void)explicit_bzero(buf, buflen);
    (void)explicit_bzero(confirm, sizeof(confirm));
    (void)fprintf(stderr, "Error reading confirmation.\n");
    errno = EIO;
    return -1;
  }

  if (n1 != n2 || memcmp(buf, confirm, (size_t)n1) != 0) {
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
  (void)printf("  -h   Show this help\n");
  (void)printf("  -v   Show version\n");
}

int main(int argc, char *argv[]) {
  int opt = 0;
  char passwd_path[PATH_MAX] = {0};
  char prefix[16] = {0};
  char password[VNC_MAX_PASSWORD_LENGTH] = {0};
  char hash[VNC_HASH_BUF_SIZE] = {0};

  while ((opt = getopt(argc, argv, "hv")) != -1) {
    switch (opt) {
    case 'h':
      print_help();
      exit(EXIT_SUCCESS);
    case 'v':
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

  if (get_crypt_prefix(&syscall_ops_default, LOGIN_DEFS_PATH, prefix,
                       sizeof(prefix)) < 0) {
    (void)fprintf(stderr, "Unsupported ENCRYPT_METHOD in %s: %s\n",
                  LOGIN_DEFS_PATH, strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (read_password(password, sizeof(password)) < 0) {
    (void)explicit_bzero(password, sizeof(password));
    exit(EXIT_FAILURE);
  }

  if (hash_password(&syscall_ops_default, password, prefix, hash,
                    sizeof(hash)) < 0) {
    (void)fprintf(stderr, "Failed to hash password: %s\n", strerror(errno));
    (void)explicit_bzero(password, sizeof(password));
    (void)explicit_bzero(hash, sizeof(hash));
    exit(EXIT_FAILURE);
  }
  (void)explicit_bzero(password, sizeof(password));

  if (atomic_write_passwd(&syscall_ops_default, passwd_path, hash) < 0) {
    (void)fprintf(stderr, "Failed to write %s: %s\n", passwd_path,
                  strerror(errno));
    (void)explicit_bzero(hash, sizeof(hash));
    exit(EXIT_FAILURE);
  }
  (void)explicit_bzero(hash, sizeof(hash));

  (void)printf("VNC password updated successfully.\n");
  exit(EXIT_SUCCESS);
}
