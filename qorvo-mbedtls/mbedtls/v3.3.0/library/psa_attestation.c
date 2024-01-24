
/**
 * @brief Attestation Core Implementation
 * @file
 * @copyright Copyright (c) 2022 Silex Insight. All Rights reserved
 */

#include <stdint.h>
#include <string.h>
#include <stddef.h>

#include "psa/initial_attestation.h"

#include "psa_crypto_internal.h"

psa_status_t psa_initial_attest_get_token(const uint8_t *auth_challenge, size_t challenge_size,
                                 uint8_t *token_buf, size_t token_buf_size, size_t *token_length)
{
    int32_t attest_status;
    uint32_t esec_status = esec_get_attestation_token((uint8_t*)auth_challenge, challenge_size, token_buf, token_buf_size, token_length, &attest_status);
    if (esec_status != ESEC_OKAY) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    return (psa_status_t)attest_status;
}

psa_status_t psa_initial_attest_get_token_size(size_t challenge_size, size_t *token_length)
{
    int32_t attest_status;
    uint32_t esec_status = esec_get_attestation_token_len(challenge_size, token_length, &attest_status);
    if (esec_status != ESEC_OKAY) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    return (psa_status_t)attest_status;
}

psa_status_t psa_initial_attest_get_public_key(uint8_t *public_key, size_t public_key_buf_size, size_t *public_key_len, psa_ecc_family_t *elliptic_curve_type)
{
    enum psa_attest_err_t attest_err = PSA_ATTEST_ERR_SUCCESS;
    uint8_t *key_source;
    size_t key_len;
    psa_ecc_family_t curve_type;
    uint32_t esec_status;
    struct esec_chip_certificate chip_cert;

    if (public_key_buf_size < ESEC_MFCT_PUBKEY_SZ + 1) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    
    esec_status = esec_read_chip_certificate(&chip_cert);
    if (esec_status != ESEC_OKAY) {
        return convert_esec_status_to_psa_status(esec_status);
    }

    *elliptic_curve_type = PSA_ECC_FAMILY_SECP_R1;
    *public_key_len = ESEC_MFCT_PUBKEY_SZ + 1;
    public_key[0] = 0x4; // Old-style ECC Prefix (0x4)
    memcpy(&public_key[1], chip_cert.endorsment_pubkey, ESEC_MFCT_PUBKEY_SZ);

    return PSA_SUCCESS;
}
