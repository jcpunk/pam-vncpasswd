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

#include <curses.h>
#include <errno.h>
#include <signal.h>
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
#include "vnc_path.h"

/* ============================================================================
 * Terminal state — module scope for signal handler access
 * ============================================================================
 */

/*
 * ncurses owns terminal state while a SCREEN is active.  If the process is
 * interrupted between noecho() and endwin(), the terminal would remain in
 * a non-echoing state.  The signal handler calls endwin() to restore it
 * before re-raising the signal.
 *
 * g_screen_active is 0 until just before noecho() and is cleared to 0 by
 * after endwin(), so the handler is safe to call at any time.
 *
 * endwin(3) is not listed as async-signal-safe by POSIX, but in practice
 * it only writes a terminfo reset sequence — the same risk accepted by
 * every other terminal-aware CLI tool (ssh, sudo, passwd itself).
 */
static volatile sig_atomic_t g_screen_active = 0;

static void restore_terminal_on_signal(int signo) {
  if (g_screen_active) {
    endwin();
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
 * read_from_terminal - Read one password line from the terminal via ncurses
 * @prompt: Prompt string to display
 * @buf:    Output buffer; NUL-terminated on success
 * @buflen: Size of @buf
 *
 * Opens /dev/tty via newterm() so stdin/stdout redirection does not affect
 * the prompt or the read.  ncurses noecho() suppresses character display;
 * getnstr() reads up to buflen-1 characters, NUL-terminates, and does not
 * include the newline.  endwin() restores the terminal unconditionally.
 *
 * Returns: number of characters read, -1 on error
 */
static ssize_t read_from_terminal(const char *prompt, char *buf,
                                  size_t buflen) {
  SCREEN *scr;
  FILE *tty;
  struct sigaction old_int, old_term, old_hup;
  ssize_t nread = -1;

  if (!buf || buflen < 2) {
    return -1;
    {
      tty = fopen("/dev/tty", "r+");
      if (!tty) {
        return -1;
      }

      /*
       * newterm(NULL, ...) uses the TERM environment variable.
       * Both output and input are directed to the tty FILE so ncurses
       * never touches stdin or stdout.
       */
      scr = newterm(NULL, tty, tty);
      if (!scr) {
        fclose(tty);
        return -1;
      }
      set_term(scr);

      arm_signal_handlers(&old_int, &old_term, &old_hup);
      g_screen_active = 1;

      noecho();
      if (prompt) {
        addstr(prompt);
      }
      refresh();

      if (getnstr(buf, (int)(buflen - 1)) == OK) {
        nread = (ssize_t)strlen(buf);
      }

      echo();
      /* Emit a newline: getnstr consumed Enter but noecho suppressed the
       * line advance, so the cursor would otherwise stay on the prompt line.
       */
      addch('\n');
      refresh();
      endwin();

      g_screen_active = 0;
      disarm_signal_handlers(&old_int, &old_term, &old_hup);

      delscreen(scr);
      fclose(tty);
      return nread;
    }
  }
}

/**
 * read_password - Read a new password interactively with confirmation
 * @buf:    Output buffer
 * @buflen: Size of @buf
 *
 * Prompts twice; verifies the entries match and fall within
 * [VNC_MIN_LEN, VNC_MAX_LEN].
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
    fprintf(stderr, "Error reading password.\n");
    errno = EIO;
    return -1;
  }

  if ((size_t)n1 < (size_t)VNC_MIN_PASSWORD_LENGTH) {
    fprintf(stderr, "Password too short (minimum %d characters).\n",
            VNC_MIN_LEN);
    explicit_bzero(buff, bufflen);
    errno = EINVAL;
    return -1;
  }

  if ((size_t)n1 > (size_t)VNC_MAX_PASSWORD_LENGTH) {
    fprintf(stderr, "Password too long: max password is %d characters.\n",
            VNC_MAX_PASSWORD_LENGTH);
    explicit_bzero(buff, bufflen);
    errno = EINVAL;
    return -1;
  }

  n2 = read_from_terminal("Confirm VNC password: ", confirm, sizeof(confirm));
  if (n2 < 0) {
    explicit_bzero(buff, bufflen);
    explicit_bzero(confirm, sizeof(confirm));
    fprintf(stderr, "Error reading confirmation.\n");
    errno = EIO;
    return -1;
  }

  if (n1 != n2 || memcmp(buf, confirm, (size_t)n1) != 0) {
    fprintf(stderr, "Passwords do not match.\n");
    explicit_bzero(buff, bufflen);
    explicit_bzero(confirm, sizeof(confirm));
    errno = EINVAL;
    return -1;
  }

  /* buff contains the password we've accepted */
  explicit_bzero(confirm, sizeof(confirm));
  return 0;
}

/* ============================================================================
 * Main
 * ============================================================================
 */

static void usage(const char *prog) {
  fprintf(stderr,
          "Usage: %s [-h] [-v]\n"
          "\n"
          "  Set the VNC password used by pam_fnal_vncpasswd.\n"
          "\n"
          "  -h   Show this help\n"
          "  -v   Show version\n",
          prog);
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
      usage(argv[0]);
      exit(EXIT_SUCCESS);
    case 'v':
      printf("%s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
      exit(EXIT_SUCCESS);
    default:
      usage(argv[0]);
      exit(EXIT_FAILURE);
    }
  }

  if (get_passwd_path(&syscall_ops_default, getuid(), passwd_path,
                      sizeof(passwd_path)) < 0) {
    fprintf(stderr, "Cannot determine password file path: %s\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (get_crypt_prefix(&syscall_ops_default, LOGIN_DEFS_PATH, prefix,
                       sizeof(prefix)) < 0) {
    fprintf(stderr, "Unsupported ENCRYPT_METHOD in %s: %s\n", LOGIN_DEFS_PATH,
            strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (read_password(password, sizeof(password)) < 0) {
    explicit_bzero(password, sizeof(password));
    exit(EXIT_FAILURE);
  }

  if (hash_password(&syscall_ops_default, password, prefix, hash,
                    sizeof(hash)) < 0) {
    fprintf(stderr, "Failed to hash password: %s\n", strerror(errno));
    explicit_bzero(password, sizeof(password));
    explicit_bzero(hash, sizeof(hash));
    exit(EXIT_FAILURE);
  }
  explicit_bzero(password, sizeof(password));

  if (atomic_write_passwd(&syscall_ops_default, passwd_path, hash) < 0) {
    fprintf(stderr, "Failed to write %s: %s\n", passwd_path, strerror(errno));
    explicit_bzero(hash, sizeof(hash));
    exit(EXIT_FAILURE);
  }
  explicit_bzero(hash, sizeof(hash));

  printf("VNC password updated successfully.\n");
  exit(EXIT_SUCCESS);
}
