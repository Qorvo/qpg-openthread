/**
 * \file sha512.h
 *
 * \brief The SHA-384 and SHA-512 cryptographic hash function.
 */
/*
 *  Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#ifndef MBEDTLS_SHA512_ALT_H
#define MBEDTLS_SHA512_ALT_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include <mbedtls/build_info.h>
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/* MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED is deprecated and should not be used. */
/** SHA-512 hardware accelerator failed */
#define MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED -0x0037

/**
 * \brief          SHA-512 context structure
 */

typedef struct
{
    uint64_t total[2];         /*!< number of bytes processed  */
    uint64_t state[8];         /*!< intermediate digest state  */
    unsigned char buffer[128]; /*!< data block being processed */
    int is384;                 /*!< 0 => SHA-512, else SHA-384 */
} mbedtls_sha512_context;

/**
 * \brief          This function initializes a SHA-512 context.
 *
 * \param ctx      The SHA-512 context to initialize.
 */
void mbedtls_sha512_init(mbedtls_sha512_context* ctx);

/**
 * \brief          This function clears a SHA-512 context.
 *
 * \param ctx      The SHA-512 context to clear.
 */
void mbedtls_sha512_free(mbedtls_sha512_context* ctx);

/**
 * \brief          This function clones the state of a SHA-512 context.
 *
 * \param dst      The destination context.
 * \param src      The context to clone.
 */
void mbedtls_sha512_clone(mbedtls_sha512_context* dst,
                          const mbedtls_sha512_context* src);

/**
 * \brief          This function starts a SHA-384 or SHA-512 checksum
 *                 calculation.
 *
 * \param ctx      The SHA-512 context to initialize.
 * \param is384    Determines which function to use.
 *                 <ul><li>0: Use SHA-512.</li>
 *                 <li>1: Use SHA-384.</li></ul>
 *
 * \return         \c 0 on success.
 */
int mbedtls_sha512_starts(mbedtls_sha512_context* ctx, int is384);

/**
 * \brief          This function feeds an input buffer into an ongoing
 *                 SHA-512 checksum calculation.
 *
 * \param ctx      The SHA-512 context.
 * \param input    The buffer holding the input data.
 * \param ilen     The length of the input data.
 *
 * \return         \c 0 on success.
 */
int mbedtls_sha512_update(mbedtls_sha512_context* ctx,
                              const unsigned char* input,
                              size_t ilen);

/**
 * \brief          This function finishes the SHA-512 operation, and writes
 *                 the result to the output buffer. This function is for
 *                 internal use only.
 *
 * \param ctx      The SHA-512 context.
 * \param output   The SHA-384 or SHA-512 checksum result.
 *
 * \return         \c 0 on success.
 */
int mbedtls_sha512_finish(mbedtls_sha512_context* ctx,
                              unsigned char output[64]);

/**
 * \brief          This function processes a single data block within
 *                 the ongoing SHA-512 computation.
 *
 * \param ctx      The SHA-512 context.
 * \param data     The buffer holding one block of data.
 *
 * \return         \c 0 on success.
 */
int mbedtls_internal_sha512_process(mbedtls_sha512_context* ctx,
                                    const unsigned char data[128]);

#ifdef __cplusplus
}
#endif
#endif
