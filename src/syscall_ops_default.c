/**
 * syscall_ops_default.c - Production system call implementation
 *
 * Provides the canonical implementation that maps function pointers
 * directly to POSIX system calls and C library functions.
 *
 * WHY THIS FILE EXISTS:
 * Separates the abstract interface (syscall_ops.h) from the concrete
 * implementation. This allows:
 * - Production code to link against real system calls
 * - Test code to link against mock implementations
 * - Clear separation between interface and implementation
 *
 * MODIFICATION:
 * When adding new system call dependencies:
 * 1. Add function pointer to struct syscall_ops (syscall_ops.h)
 * 2. Add mapping here in syscall_ops_default
 * 3. Update test mocks as needed
 */

#include <crypt.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include "syscall_ops.h"

/**
 * syscall_ops_default - Global production syscall implementation
 *
 * Maps each function pointer in the ops structure to its corresponding
 * POSIX/libc function.
 *
 * INITIALIZATION ORDER:
 * Uses C99 designated initializers (.field = value) which:
 * - Make order independent (can add/remove/reorder freely)
 * - Are self-documenting (field name visible at each assignment)
 * - Catch typos at compile time (unknown field = error)
 *
 * CONST CORRECTNESS:
 * The structure itself is const (immutable after initialization).
 * The function pointers point to system calls (not const, they're code).
 *
 * STORAGE LINKAGE:
 * - extern in header makes it visible across translation units
 * - const makes it immutable (placed in .rodata, write-protected)
 * - Single definition here (not in header, avoids multiple definition errors)
 */
const struct syscall_ops syscall_ops_default = {
    /*
     * File operations
     */
    .open = open,
    .close = close,
    .fstat = fstat,
    .lstat = lstat,
    .fopen = fopen,
    .fclose = fclose,
    .fgets = fgets,

    /*
     * Directory operations
     */
    .mkdir = mkdir,

    /*
     * Atomic file write operations
     */
    .mkstemp = mkstemp,
    .fchmod = fchmod,
    .fsync = fsync,
    .rename = rename,
    .unlink = unlink,
    .read = read,
    .write = write,

    /*
     * User database operations
     */
    .getpwnam_r = getpwnam_r,

    /*
     * Entropy generation
     */
    .getrandom = getrandom,

    /*
     * Cryptographic operations
     *
     * NOTE ON YESCRYPT:
     * crypt_gensalt_ra uses the count parameter differently per algorithm:
     * - For SHA-512/SHA-256: count is the number of rounds (e.g., 65536)
     * - For yescrypt ($y$): count is the cost factor (e.g., 5), NOT rounds
     * - For bcrypt: count is log2(rounds) (e.g., 12)
     * libxcrypt handles yescrypt parameter encoding internally.
     */
    .crypt_gensalt_ra = crypt_gensalt_ra,
    .crypt_r = crypt_r,

    /*
     * Memory protection
     */
    .mlock = mlock,
    .munlock = munlock,

    /*
     * Memory management
     */
    .calloc = calloc,
    .free = free,
};
