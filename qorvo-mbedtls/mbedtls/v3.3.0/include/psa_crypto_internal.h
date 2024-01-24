/**
 * @brief Internal Definitions for Silex PSA API Implementation that also
 *        collects mutual symbols between PSA Sub-APIs (Key Management, Hash etc)
 *
 * @copyright Copyright (c) 2022 Silex Insight. All Rights reserved
 */

#ifndef __PSA_CRYPTO_INTERNAL_H
#define __PSA_CRYPTO_INTERNAL_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define PSA_KEY_SLOT_INVALID            ((psa_key_type_t)-1)

#define PSA_KEY_SLOT_AVAILABLE(__key_type)  ((__key_type) == PSA_KEY_TYPE_NONE)
#define PSA_KEY_SLOT_OCCUPIED(__key_type)   ((__key_type) != PSA_KEY_TYPE_NONE && (__key_type) != PSA_KEY_SLOT_INVALID)
#define RSA_MAX_KEY_LEN_BYTES               (4096/8)

/*
 * - Domain N : Size
 * - E : Size or 32 Bits
 * - P : Size / 2
 * - Q : Size / 2
 * - DP : Size / 2
 * - DQ : Size / 2
 * - QP : Size / 2
 */
#define ESECURE_RSA_MAX_KEY_CONTENT_SIZE   (RSA_MAX_KEY_LEN_BYTES +\
                                            RSA_MAX_KEY_LEN_BYTES +\
                                            RSA_MAX_KEY_LEN_BYTES/2 +\
                                            RSA_MAX_KEY_LEN_BYTES/2 +\
                                            RSA_MAX_KEY_LEN_BYTES/2 +\
                                            RSA_MAX_KEY_LEN_BYTES/2 +\
                                            RSA_MAX_KEY_LEN_BYTES/2)

#define CHECK_INIT()  { if (!psa_settings.flags.initialised) return PSA_ERROR_BAD_STATE; }

/*
 * Union to keep different type of eSecure Key instances
 */
typedef union {
    struct esec_skey skey;
    struct esec_rsa_key rsakey;
    struct esec_ecc_key ecckey;
} esec_key;

/*
 * PSA eSecure Key Structure
 */
typedef struct {
    /* PSA Key Attributes; we keep PSA Key Attributes in PSA Implementation */
    psa_key_attributes_t attributes;

    /* eSecure Key Info */
    esec_key eseckey;
} psa_esec_key;

/*
 * psa_crypto implementation settings.
 */
typedef struct {
    struct {
        uint32_t initialised    : 1;
    } flags;
} psa_esec_settings;

static const uint8_t firmware_key_auth[ESEC_STOR_AUTH_SIZE] = "12345678";

/** Converts esec errors to psa errors
 */
static psa_status_t convert_esec_status_to_psa_status(uint32_t status)
{
    psa_status_t retval;
    switch (status) {
    case ESEC_OKAY:
        retval = PSA_SUCCESS;
        break;
    case ESEC_AUTHORIZATION_ERROR:
    case ESEC_INVALID_LENGTH:
    case ESEC_INVALID_PARAMETER:
        retval = PSA_ERROR_INVALID_ARGUMENT;
        break;
    case ESEC_INVALID_SIGNATURE:
        retval = PSA_ERROR_INVALID_SIGNATURE;
        break;
    case ESEC_INVALID_COMMAND:
    case ESEC_DMA_ERROR:
    case ESEC_TX_FIFO_FULL:
    case ESEC_INVALID_KEY:
    case ESEC_INVALID_RESPONSE:
    default:
        retval = PSA_ERROR_GENERIC_ERROR;
        break;
    }

    return retval;
}

extern uint32_t esec_rsa_key_content[ESECURE_RSA_MAX_KEY_CONTENT_SIZE / 4];
extern psa_esec_key psa_keys[];
extern psa_esec_settings psa_settings;

psa_status_t psa_check_key_policy(const psa_key_attributes_t *attr, psa_key_usage_t usage, psa_algorithm_t alg);

bool psa_check_cipher_arguments(psa_algorithm_t alg, psa_key_type_t key_type);

uint32_t memcmp_time_cst(const uint8_t *in1, const uint8_t *in2, uint32_t size);

psa_status_t psa_crypto_rsa_keypair_der_parse(const uint8_t *der_input, uint32_t der_input_len, uint8_t *out, uint32_t out_size, uint32_t *key_len, bool *short_expo);

psa_status_t psa_crypto_rsa_public_key_der_parse(const uint8_t *der_input, uint32_t der_input_len, uint8_t *out, uint32_t out_size, uint32_t *key_len_out, bool *short_expo_out);

#endif /* __PSA_CRYPTO_INTERNAL_H */
