/**
 * \file psa/crypto_platform.h
 *
 * \brief PSA cryptography module: eSecure platform definitions
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * This file contains platform-dependent type definitions.
 *
 * In implementations with isolation between the application and the
 * cryptography module, implementers should take care to ensure that
 * the definitions that are exposed to applications match what the
 * module implements.
 */

#ifndef PSA_CRYPTO_PLATFORM_H
#define PSA_CRYPTO_PLATFORM_H

#include "esecure.h"

/* Integral type representing a key handle. */
typedef uint32_t psa_key_handle_t;

#endif /* PSA_CRYPTO_PLATFORM_H */
