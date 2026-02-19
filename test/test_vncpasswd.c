/**
 * test_vncpasswd.c - Tests for fnal-vncpasswd CLI tool functions
 *
 * Tests the functions in vncpasswd.c and pam_vncpasswd.c that are used
 * by the CLI tool: ensure_vnc_dir(), atomic_write_passwd(), and the
 * shared hash_password()/verify_password() functions.
 *
 * Integration test: hash a password with yescrypt (RHEL default), write it
 * to a temp file, and verify it using authenticate_vnc_user().
 */

#define _GNU_SOURCE

#include "autoconf.h"
#include "pam_vncpasswd.h"
#include "syscall_ops.h"

#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "test_framework.h"

/* Minimal PAM return codes for tests */
#ifndef PAM_SUCCESS
#define PAM_SUCCESS          0
#define PAM_AUTH_ERR         7
#define PAM_AUTHINFO_UNAVAIL 9
#define PAM_USER_UNKNOWN     10
#endif

/* ============================================================================
 * Mock Infrastructure
 * ============================================================================
 */

static int g_mock_mkdir_fail;
static int g_mock_mkstemp_fail;
static int g_mock_fchmod_fail;
static int g_mock_fsync_fail;
static int g_mock_rename_fail;
static char g_mock_tmpfile_path[256];

static int mock_mkdir_ok(const char *p, mode_t m) {
  (void)p; (void)m;
  return 0;
}
static int mock_mkdir_fail(const char *p, mode_t m) {
  (void)p; (void)m;
  errno = EACCES;
  return -1;
}

/* lstat mocks */
static int mock_lstat_noent(const char *p, struct stat *st) {
  (void)p; (void)st;
  errno = ENOENT;
  return -1;
}
static int mock_lstat_isdir(const char *p, struct stat *st) {
  (void)p;
  memset(st, 0, sizeof(*st));
  st->st_mode = S_IFDIR | 0700;
  return 0;
}
static int mock_lstat_isfile(const char *p, struct stat *st) {
  (void)p;
  memset(st, 0, sizeof(*st));
  st->st_mode = S_IFREG | 0600;
  return 0;
}
static int mock_lstat_badperms(const char *p, struct stat *st) {
  (void)p;
  memset(st, 0, sizeof(*st));
  st->st_mode = S_IFDIR | 0777;
  return 0;
}

/* mkstemp: creates a real temp file so we can test writes */
static int mock_mkstemp_ok(char *tmpl) {
  /* Use real mkstemp */
  int fd = mkstemp(tmpl);
  if (fd >= 0)
    snprintf(g_mock_tmpfile_path, sizeof(g_mock_tmpfile_path), "%s", tmpl);
  return fd;
}
static int mock_mkstemp_fail(char *tmpl) {
  (void)tmpl;
  errno = EACCES;
  return -1;
}

static int mock_fchmod_fail(int fd, mode_t m) {
  (void)fd; (void)m;
  errno = EPERM;
  return -1;
}

static int mock_fsync_fail(int fd) {
  (void)fd;
  errno = EIO;
  return -1;
}

static int mock_rename_fail(const char *o, const char *n) {
  (void)o; (void)n;
  errno = EXDEV;
  return -1;
}

/* mock_open for auth tests */
static char g_auth_file[256];
static int mock_auth_open(const char *p, int f, ...) {
  (void)p; (void)f;
  return open(g_auth_file, O_RDONLY);
}

static int mock_mlock_ok(const void *a, size_t l) { (void)a; (void)l; return 0; }
static int mock_munlock_ok(const void *a, size_t l) { (void)a; (void)l; return 0; }

/* ============================================================================
 * Tests: Directory Creation (ensure_vnc_dir)
 * ============================================================================
 */

TEST(ensure_vnc_dir_creates_new) {
  struct syscall_ops ops = syscall_ops_default;
  ops.lstat = mock_lstat_noent;
  ops.mkdir = mock_mkdir_ok;
  TEST_ASSERT_EQ(ensure_vnc_dir(&ops, "/tmp/fakenewdir"), 0,
                 "Should create new directory");
}

TEST(ensure_vnc_dir_already_exists) {
  struct syscall_ops ops = syscall_ops_default;
  ops.lstat = mock_lstat_isdir;
  /* mkdir should not be called */
  ops.mkdir = mock_mkdir_fail;
  TEST_ASSERT_EQ(ensure_vnc_dir(&ops, "/tmp/existingdir"), 0,
                 "Existing directory should succeed");
}

TEST(ensure_vnc_dir_mkdir_fails) {
  struct syscall_ops ops = syscall_ops_default;
  ops.lstat = mock_lstat_noent;
  ops.mkdir = mock_mkdir_fail;
  TEST_ASSERT_EQ(ensure_vnc_dir(&ops, "/tmp/faildir"), -1,
                 "Should fail when mkdir fails");
}

TEST(ensure_vnc_dir_wrong_permissions) {
  /*
   * If the directory exists but is not a directory (e.g., it's a file),
   * ensure_vnc_dir should return -1 with ENOTDIR.
   */
  struct syscall_ops ops = syscall_ops_default;
  ops.lstat = mock_lstat_isfile;
  TEST_ASSERT_EQ(ensure_vnc_dir(&ops, "/tmp/notadir"), -1,
                 "Non-directory path should fail");
  TEST_ASSERT_EQ(errno, ENOTDIR, "Should set ENOTDIR");
}

TEST(ensure_vnc_dir_null_path) {
  struct syscall_ops ops = syscall_ops_default;
  TEST_ASSERT_EQ(ensure_vnc_dir(&ops, NULL), -1,
                 "NULL path should fail");
  TEST_ASSERT_EQ(errno, EINVAL, "Should set EINVAL");
}

/* ============================================================================
 * Tests: Atomic File Write (atomic_write_passwd)
 * ============================================================================
 */

TEST(atomic_write_success) {
  struct syscall_ops ops = syscall_ops_default;
  char dest[] = "/tmp/test_atomic_dest_XXXXXX";
  /* Create a destination to get a usable name */
  int dfd = mkstemp(dest);
  close(dfd);
  unlink(dest);

  int rc = atomic_write_passwd(&ops, dest,
                               "$6$rounds=65536$salt$hashvalue");
  TEST_ASSERT_EQ(rc, 0, "Atomic write should succeed");

  /* Verify file exists and has correct permissions */
  struct stat st;
  TEST_ASSERT_EQ(stat(dest, &st), 0, "File should exist after write");
  TEST_ASSERT_EQ((long)(st.st_mode & 0777), (long)0600,
                 "File should have 0600 permissions");

  /* Read back and verify content */
  char buf[256];
  dfd = open(dest, O_RDONLY);
  ssize_t n = read(dfd, buf, sizeof(buf) - 1);
  close(dfd);
  TEST_ASSERT_NOT_EQ((long)n, 0L, "File should have content");
  buf[n] = '\0';
  TEST_ASSERT_NOT_EQ(strstr(buf, "$6$rounds=65536$salt$hashvalue"), NULL,
                     "File should contain the hash");
  unlink(dest);
}

TEST(atomic_write_mkstemp_fails) {
  struct syscall_ops ops = syscall_ops_default;
  ops.mkstemp = mock_mkstemp_fail;
  TEST_ASSERT_EQ(atomic_write_passwd(&ops, "/tmp/dest", "hash"), -1,
                 "Should fail when mkstemp fails");
}

TEST(atomic_write_fsync_fails) {
  struct syscall_ops ops = syscall_ops_default;
  ops.mkstemp = mock_mkstemp_ok;
  ops.fsync = mock_fsync_fail;

  char dest[] = "/tmp/test_atomic_fsync_XXXXXX";
  int dfd = mkstemp(dest);
  close(dfd);
  unlink(dest);

  int rc = atomic_write_passwd(&ops, dest, "somehash");
  TEST_ASSERT_EQ(rc, -1, "Should fail when fsync fails");
  /* Temp file should be cleaned up */
  TEST_ASSERT_EQ(access(g_mock_tmpfile_path, F_OK), -1,
                 "Temp file should be cleaned up");
  unlink(dest); /* dest may or may not exist */
}

TEST(atomic_write_rename_fails) {
  struct syscall_ops ops = syscall_ops_default;
  ops.mkstemp = mock_mkstemp_ok;
  ops.rename = mock_rename_fail;

  char dest[] = "/tmp/test_atomic_rename_XXXXXX";
  int dfd = mkstemp(dest);
  close(dfd);
  unlink(dest);

  int rc = atomic_write_passwd(&ops, dest, "somehash");
  TEST_ASSERT_EQ(rc, -1, "Should fail when rename fails");
  /* Temp file should be cleaned up */
  TEST_ASSERT_EQ(access(g_mock_tmpfile_path, F_OK), -1,
                 "Temp file should be cleaned up after rename failure");
  unlink(dest);
}

TEST(atomic_write_sets_permissions) {
  struct syscall_ops ops = syscall_ops_default;

  char dest[] = "/tmp/test_atomic_perms_XXXXXX";
  int dfd = mkstemp(dest);
  close(dfd);
  unlink(dest);

  TEST_ASSERT_EQ(atomic_write_passwd(&ops, dest, "hashvalue"), 0,
                 "Write should succeed");

  struct stat st;
  TEST_ASSERT_EQ(stat(dest, &st), 0, "File should exist");
  TEST_ASSERT_EQ((long)(st.st_mode & 0777), (long)0600,
                 "File must be 0600");
  unlink(dest);
}

/* ============================================================================
 * Tests: Encrypt Method from login.defs (shared with PAM module)
 * ============================================================================
 */

static char g_fgets_content[4096];
static int g_fgets_called;

static char *mock_fgets_vncpasswd(char *str, int n, FILE *stream) {
  (void)stream;
  static char *pos;
  if (!g_fgets_called) {
    pos = g_fgets_content;
    g_fgets_called = 1;
  }
  if (!pos || *pos == '\0')
    return NULL;
  char *dst = str;
  int written = 0;
  while (*pos && written < n - 1) {
    *dst++ = *pos;
    written++;
    if (*pos++ == '\n')
      break;
  }
  *dst = '\0';
  return (written > 0) ? str : NULL;
}
static FILE *mock_fopen_ok_v(const char *p, const char *m) {
  (void)p; (void)m; return (FILE *)0x1;
}
static int mock_fclose_noop_v(FILE *f) { (void)f; return 0; }
static FILE *mock_fopen_fail_v(const char *p, const char *m) {
  (void)p; (void)m; errno = ENOENT; return NULL;
}

TEST(vncpasswd_reads_login_defs) {
  struct syscall_ops ops = syscall_ops_default;
  g_fgets_called = 0;
  snprintf(g_fgets_content, sizeof(g_fgets_content),
           "ENCRYPT_METHOD SHA256\nSHA_CRYPT_MAX_ROUNDS 100000\n");
  ops.fopen = mock_fopen_ok_v;
  ops.fclose = mock_fclose_noop_v;
  ops.fgets = mock_fgets_vncpasswd;

  struct encrypt_settings s;
  TEST_ASSERT_EQ(get_encrypt_settings(&ops, "/etc/login.defs", &s), 0,
                 "Should succeed");
  TEST_ASSERT_STR_EQ(s.method, "SHA256", "Method should be SHA256");
  TEST_ASSERT_EQ((long)s.sha_rounds, 100000L, "Rounds should be 100000");
}

TEST(vncpasswd_falls_back_sha512) {
  struct syscall_ops ops = syscall_ops_default;
  ops.fopen = mock_fopen_fail_v;

  struct encrypt_settings s;
  TEST_ASSERT_EQ(get_encrypt_settings(&ops, "/etc/login.defs", &s), 0,
                 "Missing login.defs should succeed with defaults");
  TEST_ASSERT_STR_EQ(s.method, DEFAULT_ENCRYPT_METHOD,
                     "Should use DEFAULT_ENCRYPT_METHOD");
}

/*
 * yescrypt is the default on RHEL10. Verify the tool reads
 * YESCRYPT_COST_FACTOR correctly and uses the yescrypt prefix.
 */
TEST(vncpasswd_reads_yescrypt_cost) {
  struct syscall_ops ops = syscall_ops_default;
  g_fgets_called = 0;
  snprintf(g_fgets_content, sizeof(g_fgets_content),
           "ENCRYPT_METHOD YESCRYPT\nYESCRYPT_COST_FACTOR 5\n");
  ops.fopen = mock_fopen_ok_v;
  ops.fclose = mock_fclose_noop_v;
  ops.fgets = mock_fgets_vncpasswd;

  struct encrypt_settings s;
  TEST_ASSERT_EQ(get_encrypt_settings(&ops, "/etc/login.defs", &s), 0,
                 "Should succeed");
  TEST_ASSERT_STR_EQ(s.method, "YESCRYPT", "Method should be YESCRYPT");
  TEST_ASSERT_EQ((long)s.yescrypt_cost, 5L, "yescrypt cost should be 5");

  /* Generate a salt and confirm it uses yescrypt format */
  char salt[SALT_BUF_SIZE];
  ops.getrandom = NULL; /* use real getrandom */
  ops.crypt_gensalt_ra = NULL; /* use real crypt_gensalt_ra */
  ops = syscall_ops_default;
  /* Re-apply fopen/fclose/fgets so they stay as default for salt gen */
  TEST_ASSERT_EQ(generate_salt(&ops, &s, salt, sizeof(salt)), 0,
                 "yescrypt salt generation should succeed");
  TEST_ASSERT_EQ(strncmp(salt, "$y$", 3), 0,
                 "yescrypt salt must start with $y$");
  TEST_ASSERT_EQ(strstr(salt, "rounds="), NULL,
                 "yescrypt salt must not contain rounds=");
}

/* ============================================================================
 * Tests: Integration — set password via tool, verify via PAM
 * ============================================================================
 */

TEST(full_password_set_and_verify) {
  /*
   * Integration test: use the CLI tool functions to hash and store a
   * password, then use the PAM module functions to verify it.
   * Tests the complete code path including yescrypt (RHEL default).
   */
  struct syscall_ops ops = syscall_ops_default;

  /* Use yescrypt (RHEL default) */
  struct encrypt_settings settings = { "YESCRYPT", 65536UL, 5UL };

  /* Hash the password */
  char hash[HASH_BUF_SIZE];
  TEST_ASSERT_EQ(hash_password(&ops, "integrationtest", &settings,
                               hash, sizeof(hash)), 0,
                 "hash_password should succeed");
  TEST_ASSERT_EQ(strncmp(hash, "$y$", 3), 0,
                 "Should produce yescrypt hash");

  /* Write to temp file atomically */
  char dest[] = "/tmp/test_integration_XXXXXX";
  int dfd = mkstemp(dest);
  close(dfd);
  unlink(dest);

  TEST_ASSERT_EQ(atomic_write_passwd(&ops, dest, hash), 0,
                 "atomic_write_passwd should succeed");

  /* Verify file permissions */
  struct stat st;
  TEST_ASSERT_EQ(stat(dest, &st), 0, "File should exist");
  TEST_ASSERT_EQ((long)(st.st_mode & 0777), (long)0600, "Permissions must be 0600");

  /* Store dest for mock open */
  snprintf(g_auth_file, sizeof(g_auth_file), "%s", dest);

  /* Verify via authenticate_vnc_user */
  ops.open = mock_auth_open;
  ops.mlock = mock_mlock_ok;
  ops.munlock = mock_munlock_ok;

  int rc = authenticate_vnc_user(&ops, "testuser", "integrationtest",
                                  dest, false);
  TEST_ASSERT_EQ(rc, PAM_SUCCESS,
                 "Integration: correct password should authenticate");

  rc = authenticate_vnc_user(&ops, "testuser", "wrongpassword",
                              dest, false);
  TEST_ASSERT_EQ(rc, PAM_AUTH_ERR,
                 "Integration: wrong password should fail");

  unlink(dest);
  explicit_bzero(hash, sizeof(hash));
}

/* ============================================================================
 * Test Runner
 * ============================================================================
 */

int main(int argc, char **argv) {
  TEST_INIT(30, false, false);

  /* Directory creation */
  RUN_TEST(ensure_vnc_dir_creates_new);
  RUN_TEST(ensure_vnc_dir_already_exists);
  RUN_TEST(ensure_vnc_dir_mkdir_fails);
  RUN_TEST(ensure_vnc_dir_wrong_permissions);
  RUN_TEST(ensure_vnc_dir_null_path);

  /* Atomic file write */
  RUN_TEST(atomic_write_success);
  RUN_TEST(atomic_write_mkstemp_fails);
  RUN_TEST(atomic_write_fsync_fails);
  RUN_TEST(atomic_write_rename_fails);
  RUN_TEST(atomic_write_sets_permissions);

  /* Encrypt method from login.defs */
  RUN_TEST(vncpasswd_reads_login_defs);
  RUN_TEST(vncpasswd_falls_back_sha512);
  RUN_TEST(vncpasswd_reads_yescrypt_cost);

  /* Integration */
  RUN_TEST(full_password_set_and_verify);

  return TEST_EXECUTE();
}
