/**
 * syscall_ops.h - System call abstraction layer for dependency injection
 *
 * WHY THIS EXISTS:
 * Unit testing code that makes system calls is difficult because:
 * - Tests require root privileges (file ownership checks, mlock)
 * - Tests have side effects (creating files, modifying directories)
 * - Tests depend on system state (existing users, file permissions)
 * - Cryptographic operations use real entropy in production
 *
 * This abstraction layer solves these problems by:
 * 1. Separating interface (what operations we need) from implementation
 * 2. Allowing tests to provide mock implementations without syscall privileges
 * 3. Making dependencies explicit in function signatures
 * 4. Enabling isolated testing without system resources
 *
 * PATTERN:
 * Production code uses syscall_ops_default (maps to actual system calls).
 * Test code creates custom ops structures with controlled behavior.
 * Functions receive ops as first parameter (kernel convention).
 */

#ifndef SYSCALL_OPS_H
#define SYSCALL_OPS_H

#include <pwd.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

/**
 * struct syscall_ops - Operations structure for system call abstraction
 *
 * Function pointer table that wraps all external system dependencies.
 * Follows the Linux kernel pattern of embedding operations in a structure
 * (e.g., struct file_operations, struct inode_operations).
 *
 * WHY FUNCTION POINTERS:
 * - Type-safe: compiler verifies signatures match POSIX prototypes
 * - Runtime swappable: same binary can use different implementations
 * - Thread-safe: no global state, each context gets its own ops
 * - Explicit: dependencies are visible in function signatures
 *
 * USAGE PATTERN:
 * Pass as first parameter (like kernel "ops" convention):
 *   int some_function(const struct syscall_ops *ops, ...)
 */
struct syscall_ops {
  /*
   * File operations
   *
   * WHY WE NEED THESE:
   * Password files must be validated for security (owner, permissions,
   * not a symlink). Tests need to simulate different file states
   * without creating actual filesystem entries.
   */
  int (*open)(const char *pathname, int flags, ...);
  int (*close)(int fd);
  int (*fstat)(int fd, struct stat *statbuf);
  int (*lstat)(const char *pathname, struct stat *statbuf);
  FILE *(*fopen)(const char *pathname, const char *mode);
  int (*fclose)(FILE *stream);
  char *(*fgets)(char *str, int n, FILE *stream);

  /*
   * Directory operations
   *
   * WHY WE NEED THESE:
   * Must create ~/.config/vnc/ directory if it doesn't exist.
   * Tests verify directory creation without actually creating dirs.
   */
  int (*mkdir)(const char *pathname, mode_t mode);

  /*
   * Atomic file write operations
   *
   * WHY WE NEED THESE:
   * Password file must be written atomically to prevent partial writes.
   * Pattern: mkstemp → write → fchmod → fsync → rename.
   * Tests verify the sequence without touching the filesystem.
   *
   * read is also abstracted so tests can inject hash content directly
   * into read_passwd_hash() without needing a real file descriptor.
   */
  int (*mkstemp)(char *template);
  int (*fchmod)(int fd, mode_t mode);
  int (*fsync)(int fd);
  int (*rename)(const char *oldpath, const char *newpath);
  int (*unlink)(const char *pathname);
  ssize_t (*read)(int fd, void *buf, size_t count);
  ssize_t (*write)(int fd, const void *buf, size_t count);

  /*
   * User database operations
   *
   * WHY WE NEED THESE:
   * Must look up the user's home directory to find ~/.config/vnc/fnal_vncpasswd.
   * Production reads from /etc/passwd + NSS. Tests provide controlled
   * user database without requiring actual system users.
   *
   * THREAD SAFETY:
   * getpwnam_r is the reentrant version (vs getpwnam).
   */
  int (*getpwnam_r)(const char *name, struct passwd *pwd, char *buf,
                    size_t buflen, struct passwd **result);

  /*
   * Entropy generation
   *
   * WHY WE NEED THESE:
   * Salt generation requires cryptographically secure random bytes.
   * Tests can inject known bytes to verify salt construction.
   *
   * SECURITY NOTE:
   * Never use rand() or time()-seeded PRNGs for cryptographic salts.
   * getrandom(2) reads from the kernel CSPRNG (same source as /dev/urandom
   * after boot entropy is gathered).
   */
  ssize_t (*getrandom)(void *buf, size_t buflen, unsigned int flags);

  /*
   * Cryptographic operations
   *
   * WHY WE NEED THESE:
   * Password hashing and salt generation need to be mockable for tests
   * that verify error handling paths (e.g., crypt_r returning NULL).
   *
   * YESCRYPT NOTE:
   * crypt_gensalt_ra handles algorithm-specific salt encoding automatically:
   * - SHA-512 ($6$): count = rounds (e.g., 65536), appends "rounds=N$"
   * - SHA-256 ($5$): count = rounds (e.g., 65536), appends "rounds=N$"
   * - yescrypt ($y$): count = cost factor (e.g., 5), encodes as params
   * - bcrypt ($2b$): count = log2(rounds) (e.g., 12)
   * This is the KEY difference: yescrypt does NOT use "rounds=N" syntax.
   *
   * crypt_gensalt_ra returns a heap-allocated string (caller must free).
   * crypt_r writes to the caller-provided crypt_data buffer (no alloc).
   */
  char *(*crypt_gensalt_ra)(const char *prefix, unsigned long count,
                            const char *rbytes, int nrbytes);
  char *(*crypt_r)(const char *phrase, const char *setting,
                   struct crypt_data *data);

  /*
   * Memory protection
   *
   * WHY WE NEED THESE:
   * Plaintext passwords should be locked in RAM to prevent them from
   * being swapped to disk where they could be recovered later.
   * mlock failure is non-fatal; auth should continue regardless.
   * Tests verify that mlock failure doesn't abort authentication.
   */
  int (*mlock)(const void *addr, size_t len);
  int (*munlock)(const void *addr, size_t len);

  /*
   * Memory management
   *
   * WHY WE NEED THESE:
   * Must ensure our memory allocation checks have tests for
   * when allocation fails (e.g., calloc returning NULL).
   */
  void *(*calloc)(size_t nmemb, size_t size);
  void (*free)(void *ptr);
};

/**
 * syscall_ops_default - Production system call implementation
 *
 * Global constant structure containing pointers to actual POSIX system calls
 * and C library functions. Use this in production code paths.
 *
 * WHY EXTERN:
 * - Declared in header, defined in syscall_ops_default.c
 * - Single instance shared across all translation units
 *
 * WHY CONST:
 * - Read-only after initialization (security)
 * - Can be placed in .rodata segment (write-protected memory)
 * - Multiple threads can safely share (no synchronization needed)
 *
 * TEST USAGE (override specific operations):
 *   struct syscall_ops test_ops = syscall_ops_default;
 *   test_ops.crypt_r = mock_crypt_r_null;
 *   test_ops.getrandom = mock_getrandom_fail;
 */
extern const struct syscall_ops syscall_ops_default;

#endif /* SYSCALL_OPS_H */
