/**
 * shared/vnc_crypto.h - Cryptographic buffer size constants
 *
 * Separated from vnc_path.h to keep path and crypto concerns distinct.
 * Consumers that need VNC_HASH_BUF_SIZE include this header; consumers
 * that only need path construction include vnc_path.h.
 */

#ifndef VNC_CRYPTO_H
#define VNC_CRYPTO_H

#include <crypt.h>

/**
 * VNC_HASH_BUF_SIZE - buffer large enough for any crypt(3) output string
 *
 * CRYPT_OUTPUT_SIZE is the maximum defined by libxcrypt in crypt.h.
 */
enum { VNC_HASH_BUF_SIZE = CRYPT_OUTPUT_SIZE };

_Static_assert(VNC_HASH_BUF_SIZE <= INT_MAX,
               "hash buffer exceeds fgets limit!");

#endif /* VNC_CRYPTO_H */
