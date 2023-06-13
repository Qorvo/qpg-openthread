#include "psa/crypto.h"

#include "psa_esec_platform.h"
#include "psa_crypto_internal.h"

extern uint32_t esec_rsa_key_content[];

static psa_status_t psa_asymmetric_encrypt_internal(
        const psa_esec_key *slot, psa_algorithm_t alg, const uint8_t *input,
        size_t input_length, const uint8_t *salt, size_t salt_length, uint8_t *output,
        size_t output_size, size_t *output_length)
{
    psa_status_t status;
    (void)salt;

    /* Empty Slot */
    if (slot->attributes.core.bits == 0) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    status = psa_check_key_policy(&slot->attributes, PSA_KEY_USAGE_ENCRYPT, 0);
    if (status != PSA_SUCCESS) {
        return status;
    }

    *output_length = 0;

    if (!PSA_ALG_IS_RSA_OAEP(alg) && salt_length != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!(PSA_KEY_TYPE_IS_PUBLIC_KEY(slot->attributes.core.type) || 
          PSA_KEY_TYPE_IS_KEY_PAIR(slot->attributes.core.type))) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint32_t esec_status;
    if (PSA_KEY_TYPE_IS_RSA(slot->attributes.core.type)) {
        if (output_size < (size_t)slot->attributes.core.bits/8) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }

        if (alg == PSA_ALG_RSA_PKCS1V15_CRYPT) {
            esec_status = esec_rsa_encrypt(ESEC_RSA_PADDING_EME_PKCS, slot->eseckey.rsakey, input, input_length, output, ESEC_HASH_ALGO_SHA1);
        } else {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        if (esec_status == 0) {
            *output_length = slot->attributes.core.bits / 8;
        }

        return convert_esec_status_to_psa_status(esec_status);
    } else {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}

static psa_status_t psa_asymmetric_decrypt_internal(
        const psa_esec_key *slot, psa_algorithm_t alg, const uint8_t *input,
        size_t input_length, const uint8_t *salt, size_t salt_length, uint8_t *output,
        size_t output_size, size_t *output_length)
{
    psa_status_t status;

    (void)salt;

    /* Empty Slot */
    if (slot->attributes.core.bits == 0) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    status = psa_check_key_policy(&slot->attributes, PSA_KEY_USAGE_DECRYPT, 0);
    if (status != PSA_SUCCESS) {
        return status;
    }

    *output_length = 0;

    if (!PSA_ALG_IS_RSA_OAEP(alg) && salt_length != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!PSA_KEY_TYPE_IS_KEY_PAIR(slot->attributes.core.type)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (slot->attributes.core.type == PSA_KEY_TYPE_RSA_KEY_PAIR) {
        uint32_t esec_status;
        if (input_length != slot->attributes.core.bits / 8) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        if (alg == PSA_ALG_RSA_PKCS1V15_CRYPT) {
            /*
             * esec_rsa_decrypt functions does not check for the output length
             * so it may overflow the output buffer if the output buffer is small
             * To solve that, we get plaintext into big enough buffer first, and then we copy
             * the plain text to the proper output buffer if outbut buffer big enough.
             */
            uint32_t *tmp_output;
            if (input_length > ESECURE_RSA_MAX_KEY_CONTENT_SIZE) {
                return PSA_ERROR_BUFFER_TOO_SMALL;
            }
            /* Let re-use the esec_rsa_key_content buffer */
            tmp_output = esec_rsa_key_content;

            esec_status = esec_rsa_decrypt(ESEC_RSA_PADDING_EME_PKCS, slot->eseckey.rsakey, input, (uint8_t*)tmp_output, output_length, ESEC_HASH_ALGO_SHA256);

            if (*output_length > output_size) {
                return PSA_ERROR_BUFFER_TOO_SMALL;
            }

            memcpy(output, tmp_output, *output_length);
        } else {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        return convert_esec_status_to_psa_status(esec_status);
    } else {
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t psa_asymmetric_encrypt(
        psa_key_id_t key, psa_algorithm_t alg, const uint8_t *input,
        size_t input_length, const uint8_t *salt, size_t salt_length,
        uint8_t *output, size_t output_size, size_t *output_length)
{
    CHECK_INIT();

    if (key >= NUMBER_OF_KEY_SLOTS) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    return psa_asymmetric_encrypt_internal(&psa_keys[key], alg, input, input_length, salt, salt_length, output, output_size, output_length);
}

psa_status_t psa_asymmetric_decrypt(
        psa_key_id_t key, psa_algorithm_t alg, const uint8_t *input,
        size_t input_length, const uint8_t *salt, size_t salt_length,
        uint8_t *output, size_t output_size, size_t *output_length)
{
    CHECK_INIT();

    if (key >= NUMBER_OF_KEY_SLOTS) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    return psa_asymmetric_decrypt_internal(&psa_keys[key], alg, input, input_length, salt, salt_length, output, output_size, output_length);
}
