#include "psa/crypto.h"

#include "psa_esec_platform.h"
#include "psa_crypto_internal.h"

/* Helper function to perform common nonce length checks. */
static psa_status_t psa_aead_check_nonce_length(psa_algorithm_t alg, size_t nonce_length )
{
    psa_algorithm_t base_alg = PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(alg);

    switch (base_alg)
    {
    case PSA_ALG_GCM:
        /* Not checking max nonce size here as GCM spec allows almost
        * arbitrarily large nonces. Please note that we do not generally
        * recommend the usage of nonces of greater length than
        * PSA_AEAD_NONCE_MAX_SIZE, as large nonces are hashed to a shorter
        * size, which can then lead to collisions if you encrypt a very
        * large number of messages.*/
        if (nonce_length != 0)
            return PSA_SUCCESS;
        break;
    case PSA_ALG_CCM:
        if (nonce_length >= 7 && nonce_length <= 13)
            return PSA_SUCCESS;
        break;
    case PSA_ALG_CHACHA20_POLY1305:
        if (nonce_length == 12)
            return PSA_SUCCESS ;
        else if (nonce_length == 8)
            return PSA_ERROR_NOT_SUPPORTED;
        break;
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_ERROR_INVALID_ARGUMENT;
}

static psa_algorithm_t get_aead_core_alg(psa_algorithm_t alg)
{
    switch (PSA_ALG_AEAD_WITH_SHORTENED_TAG(alg, 0)) {
    case PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 0):
        return PSA_ALG_CCM;
    case PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, 0):
        return PSA_ALG_GCM;
    case PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CHACHA20_POLY1305, 0):
        return PSA_ALG_CHACHA20_POLY1305;
    default:
        break;
    }

    return PSA_ALG_NONE;
}

static psa_status_t aead_unpadded_locate_tag(size_t tag_length, const uint8_t *ciphertext, size_t ciphertext_length, size_t plaintext_size, const uint8_t **p_tag)
{
    size_t payload_length;
    if (tag_length > ciphertext_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    payload_length = ciphertext_length - tag_length;
    if (payload_length > plaintext_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    *p_tag = ciphertext + payload_length;
    return PSA_SUCCESS;
}

static psa_status_t aead_setup_internal(psa_aead_operation_t *operation, psa_key_id_t handle, psa_key_usage_t usage, psa_algorithm_t alg)
{
    psa_status_t status;
    size_t key_bits;

    CHECK_INIT();

    if (handle >= NUMBER_OF_KEY_SLOTS) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    const psa_esec_key *slot = &psa_keys[handle];

    if (!PSA_KEY_SLOT_OCCUPIED(slot->attributes.core.type)) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    if (usage == PSA_KEY_USAGE_ENCRYPT) {
        operation->encrypt = true;
    }

    status = psa_check_key_policy(&slot->attributes, usage, 0);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    if (PSA_ALG_AEAD_GET_TAG_LENGTH(slot->attributes.core.policy.alg) !=
        PSA_ALG_AEAD_GET_TAG_LENGTH(alg)) {
        status = PSA_ERROR_NOT_PERMITTED;
        goto cleanup;
    }

    key_bits = slot->attributes.core.bits;

    switch (PSA_ALG_AEAD_WITH_SHORTENED_TAG(alg, 0)) {
    case PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 0):
        operation->full_tag_length = 16;
        operation->nonce_size = 16;

        /* Block length must be 16 for CCM */
        if (PSA_BLOCK_CIPHER_BLOCK_LENGTH(slot->attributes.core.type) != 16) {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto cleanup;
        }
        break;
    case PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, 0):
        operation->full_tag_length = 16;
        operation->nonce_size = 12;

        /* Block length must be 16 for GCM */
        if (PSA_BLOCK_CIPHER_BLOCK_LENGTH(slot->attributes.core.type) != 16) {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto cleanup;
        }
        break;
    case PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CHACHA20_POLY1305, 0):
        operation->full_tag_length = 16;

        /* We only support the default tag length. */
        if (alg != PSA_ALG_CHACHA20_POLY1305) {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto cleanup;

        }
        break;
    default:
        status = PSA_ERROR_NOT_SUPPORTED;
        goto cleanup;
    }

    if (PSA_ALG_AEAD_GET_TAG_LENGTH(alg) > operation->full_tag_length) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }

    operation->alg = alg;
    operation->tag_length = PSA_ALG_AEAD_GET_TAG_LENGTH(alg);
    operation->key_id = handle;

    return PSA_SUCCESS;

cleanup:
    psa_aead_abort(operation);
    return status;
}

static psa_status_t aead_encrypt(bool is_update, psa_aead_operation_t *operation, const uint8_t *nonce, size_t nonce_length, const uint8_t *additional_data, size_t additional_data_length, const uint8_t *plaintext, size_t plaintext_length, uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length)
{
    psa_status_t status;
    uint8_t *tag;

    const psa_esec_key *slot = &psa_keys[operation->key_id];

    if (operation->tag_length == 0) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    /* For all currently supported modes, the tag is at the end of the
     * ciphertext. */
    if (ciphertext_size < (plaintext_length + operation->tag_length)) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    tag = ciphertext + plaintext_length;

    uint32_t esec_status;
    psa_algorithm_t core_alg = get_aead_core_alg(operation->alg);
    switch (core_alg) {
    case PSA_ALG_GCM:
        esec_status = esec_aes_gcm_encrypt(slot->eseckey.skey, plaintext, nonce, ciphertext, plaintext_length, additional_data, additional_data_length, operation->ctx.GCM.tag, operation->tag_length);
        memcpy(&ciphertext[plaintext_length], operation->ctx.GCM.tag, operation->tag_length);
        break;
    case PSA_ALG_CCM:
        esec_status = esec_aes_ccm_encrypt(slot->eseckey.skey, plaintext, ciphertext, plaintext_length, additional_data, additional_data_length, nonce, nonce_length, operation->ctx.CCM.tag, operation->tag_length);
        /*  Attach tag to the cipher text */
        memcpy(&ciphertext[plaintext_length], operation->ctx.CCM.tag, operation->tag_length);
        break;
    case PSA_ALG_CHACHA20_POLY1305:
        if (nonce_length != 12 || operation->tag_length != 16) {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }
        esec_status = esec_chachapoly_encrypt(slot->eseckey.skey, plaintext, nonce, ciphertext, plaintext_length, additional_data, additional_data_length, operation->ctx.ChaChaPoly.tag);
        /*  Attach tag to the cipher text */
        memcpy(&ciphertext[plaintext_length], operation->ctx.ChaChaPoly.tag, operation->tag_length);
        break;
    default:
        status = PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }

    status = convert_esec_status_to_psa_status(esec_status);

    if (status != PSA_SUCCESS && ciphertext_size != 0) {
        memset(ciphertext, 0, ciphertext_size);
    }

exit:
    *ciphertext_length = 0;

    if (status == PSA_SUCCESS) {
        *ciphertext_length = plaintext_length;
        if (!is_update) {
            *ciphertext_length += operation->tag_length;
        }
    }

    return status;
}

static psa_status_t aead_decrypt(psa_aead_operation_t *operation, const uint8_t *nonce, size_t nonce_length, const uint8_t *additional_data, size_t additional_data_length, const uint8_t *ciphertext, size_t ciphertext_length, uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length)
{
    psa_status_t status;
    uint8_t *tag;

    const psa_esec_key *slot = &psa_keys[operation->key_id];

    status = aead_unpadded_locate_tag(operation->tag_length, ciphertext, ciphertext_length, plaintext_size, (const uint8_t**)&tag);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    uint32_t esec_status;
    psa_algorithm_t core_alg = get_aead_core_alg(operation->alg);

    switch (core_alg) {
    case PSA_ALG_GCM:
        memcpy(operation->ctx.GCM.tag, &ciphertext[ciphertext_length-operation->tag_length], operation->tag_length);
        esec_status = esec_aes_gcm_decrypt(slot->eseckey.skey, ciphertext, nonce, plaintext, ciphertext_length-operation->tag_length, additional_data, additional_data_length, operation->ctx.GCM.tag, operation->tag_length);
        break;
    case PSA_ALG_CCM:
        if (operation->tag_length == 0) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }

        memcpy(operation->ctx.CCM.tag, &ciphertext[ciphertext_length-operation->tag_length], operation->tag_length);
        esec_status = esec_aes_ccm_decrypt(slot->eseckey.skey, ciphertext, plaintext, ciphertext_length-operation->tag_length, additional_data, additional_data_length, nonce, nonce_length, operation->ctx.CCM.tag, operation->tag_length);
        break;
    case PSA_ALG_CHACHA20_POLY1305:
        if (nonce_length != 12 || operation->tag_length != 16) {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }
        memcpy(operation->ctx.ChaChaPoly.tag, &ciphertext[ciphertext_length-operation->tag_length], operation->tag_length);
        esec_status = esec_chachapoly_decrypt(slot->eseckey.skey, ciphertext, nonce, plaintext, ciphertext_length-operation->tag_length, additional_data, additional_data_length, operation->ctx.ChaChaPoly.tag);
        break;
    default:
        status = PSA_ERROR_NOT_SUPPORTED;
        goto exit;

    }

    status = convert_esec_status_to_psa_status(esec_status);

    if (status != PSA_SUCCESS && plaintext_size != 0) {
        memset(plaintext, 0, plaintext_size);
    }

exit:
    if (status == PSA_SUCCESS) {
        *plaintext_length = ciphertext_length - operation->tag_length;
    }

    return status;
}

psa_status_t psa_aead_encrypt(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *nonce,
                              size_t nonce_length, const uint8_t *additional_data,
                              size_t additional_data_length, const uint8_t *plaintext,
                              size_t plaintext_length, uint8_t *ciphertext, size_t ciphertext_size,
                              size_t *ciphertext_length)
{
    psa_status_t status;
    psa_aead_operation_t operation;

    *ciphertext_length = 0;

    status = aead_setup_internal(&operation, key, PSA_KEY_USAGE_ENCRYPT, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (nonce_length == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = aead_encrypt(false, &operation, nonce, nonce_length, additional_data, additional_data_length, plaintext, plaintext_length, ciphertext, ciphertext_size, ciphertext_length);

    psa_aead_abort(&operation);

    return status;
}

psa_status_t psa_aead_decrypt(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *nonce,
                              size_t nonce_length, const uint8_t *additional_data,
                              size_t additional_data_length, const uint8_t *ciphertext,
                              size_t ciphertext_length, uint8_t *plaintext,
                              size_t plaintext_size, size_t *plaintext_length)
{
    psa_status_t status;
    psa_aead_operation_t operation;
    const uint8_t *tag = NULL;

    *plaintext_length = 0;

    status = aead_setup_internal(&operation, key, PSA_KEY_USAGE_DECRYPT, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (nonce_length == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = aead_decrypt(&operation, nonce, nonce_length, additional_data, additional_data_length, ciphertext, ciphertext_length, plaintext, plaintext_size, plaintext_length);

    return status;
}

psa_status_t psa_aead_encrypt_setup(psa_aead_operation_t *operation,
                                    psa_key_id_t key, psa_algorithm_t alg)
{
    return aead_setup_internal(operation, key, PSA_KEY_USAGE_ENCRYPT, alg);
}

psa_status_t psa_aead_decrypt_setup(psa_aead_operation_t *operation,
                                    psa_key_id_t key, psa_algorithm_t alg)
{
    return aead_setup_internal(operation, key, PSA_KEY_USAGE_DECRYPT, alg);
}

psa_status_t psa_aead_generate_nonce(psa_aead_operation_t *operation, uint8_t *nonce,
                                     size_t nonce_size, size_t *nonce_length)
{
    if (operation->alg == 0 || operation->nonce_size == 0 || operation->nonce_set || !operation->encrypt) {
        psa_aead_abort(operation);
        return PSA_ERROR_BAD_STATE;
    }

    if (nonce_size < operation->nonce_size) {
        psa_aead_abort(operation);
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    psa_status_t status = psa_generate_random(nonce, operation->nonce_size);

    if (status == PSA_SUCCESS) {
        memcpy(operation->nonce, nonce, operation->nonce_size);
        operation->nonce_set = true;
        *nonce_length = operation->nonce_size;
    }

    return status;
}

psa_status_t psa_aead_set_nonce(psa_aead_operation_t *operation, const uint8_t *nonce,
                                size_t nonce_length)
{
    psa_status_t status;

    if (operation->alg == 0 || operation->nonce_size == 0 || operation->nonce_set) {
        psa_aead_abort(operation);
        return PSA_ERROR_BAD_STATE;
    }

    status = psa_aead_check_nonce_length(operation->alg, nonce_length);
    if (status != PSA_SUCCESS) {
        psa_aead_abort(operation);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    operation->nonce_size = (uint8_t)nonce_length;
    memcpy(operation->nonce, nonce, operation->nonce_size);
    operation->nonce_set = true;

    return PSA_SUCCESS;
}

psa_status_t psa_aead_set_lengths(psa_aead_operation_t *operation, size_t ad_length,
                                  size_t plaintext_length)
{
    if (operation->alg == 0 || operation->nonce_size == 0) {
        psa_aead_abort(operation);
        return PSA_ERROR_BAD_STATE;
    }

    if (operation->lengths_set || operation->ad_started || operation->body_started) {
        psa_aead_abort(operation);
        return PSA_ERROR_BAD_STATE;
    }

    switch(operation->alg) {
    case PSA_ALG_CCM:
        if (ad_length > 0xFF00) {
            psa_aead_abort(operation);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        break;
    case PSA_ALG_CHACHA20_POLY1305:
        /* No length restrictions for ChaChaPoly. */
        break;
    default:
        break;
    }

    operation->ad_offset = 0;
    operation->ad_remaining = ad_length;
    operation->body_remaining = 0;
    operation->body_remaining = plaintext_length;
    operation->lengths_set = 1;

    return PSA_SUCCESS;
}

psa_status_t psa_aead_update_ad(psa_aead_operation_t *operation,
                                const uint8_t *input,
                                size_t input_length)
{
    if (operation->alg == 0 || operation->nonce_size == 0) {
        psa_aead_abort(operation);
        return PSA_ERROR_BAD_STATE;
    }

    if (operation->ad_remaining > 0 && operation->ad_remaining < input_length) {
        psa_aead_abort(operation);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (operation->lengths_set) {
        if (operation->ad_remaining < input_length) {
            psa_aead_abort(operation);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        operation->ad_remaining -= input_length;
    }

    if (operation->ad_started) {
        psa_aead_abort(operation);
        return PSA_ERROR_BAD_STATE;
    }

    operation->ad_started = true;
    memcpy(&operation->ad[operation->ad_offset], input, input_length);
    operation->ad_offset += input_length;

    return PSA_SUCCESS;
}

psa_status_t psa_aead_update(psa_aead_operation_t *operation, const uint8_t *input,
                             size_t input_length, uint8_t *output,
                             size_t output_size, size_t *output_length)
{
    if (operation->alg == 0 || operation->nonce_size == 0) {
        psa_aead_abort(operation);
        return PSA_ERROR_BAD_STATE;
    }

    if (operation->lengths_set) {
        /* Additional data length was supplied, but not all the additional
           data was supplied.*/
        if (operation->ad_remaining != 0) {
            psa_aead_abort(operation);
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        /* Too much data provided. */
        if (operation->body_remaining < input_length) {
            psa_aead_abort(operation);
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        operation->body_offset += input_length;
        operation->body_remaining -= input_length;
    }

    psa_status_t status = aead_encrypt(true, operation, operation->nonce, operation->nonce_size,
                                       operation->ad, operation->ad_offset, input, input_length,
                                       output, output_size, output_length);

    if (status != PSA_SUCCESS) {
        psa_aead_abort(operation);
    }

    operation->body_started = 1;

    return status;
}

psa_status_t psa_aead_finish(psa_aead_operation_t *operation, uint8_t *ciphertext,
                             size_t ciphertext_size, size_t *ciphertext_length,
                             uint8_t *tag, size_t tag_size, size_t *tag_length)
{
    psa_status_t status;

    *tag_length = 0;
    *ciphertext_length = 0;

    if (operation->alg == 0 || !operation->nonce_set) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->lengths_set &&
        (operation->ad_remaining != 0 || operation->body_remaining != 0)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    if (ciphertext_size < operation->full_tag_length) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    if (tag_size < operation->tag_length) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    psa_algorithm_t core_alg = get_aead_core_alg(operation->alg);

    switch (core_alg) {
    case PSA_ALG_GCM:
        memcpy(tag, operation->ctx.GCM.tag, operation->tag_length);
        break;
    case PSA_ALG_CCM:
        memcpy(tag, operation->ctx.CCM.tag, operation->tag_length);
        break;
    case PSA_ALG_CHACHA20_POLY1305:
        memcpy(tag, operation->ctx.ChaChaPoly.tag, operation->tag_length);
        break;
    default:
        status = PSA_ERROR_NOT_SUPPORTED;
        goto exit;

    }

    *tag_length = operation->tag_length;

    status = PSA_SUCCESS;
exit:
    /* In case the operation fails and the user fails to check for failure or
     * the zero tag size, make sure the tag is set to something implausible.
     * Even if the operation succeeds, make sure we clear the rest of the
     * buffer to prevent potential leakage of anything previously placed in
     * the same buffer.*/
    if (tag != NULL) {
        if (status != PSA_SUCCESS) {
            memset(tag, '!', tag_size);
        }  else if(*tag_length < tag_size) {
            memset(tag + *tag_length, '!', ( tag_size - *tag_length));
        }
    }

    if (status != PSA_SUCCESS) {
        *tag_length = 0;
    }

    psa_aead_abort(operation);

    return status;
}

psa_status_t psa_aead_verify(psa_aead_operation_t *operation,  uint8_t *plaintext,
                             size_t plaintext_size, size_t *plaintext_length,
                             const uint8_t *tag, size_t tag_length)
{
    psa_status_t status;
    *plaintext_length = 0;

    if (operation->alg == 0 || !operation->nonce_set) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->lengths_set &&
        (operation->ad_remaining != 0 || operation->body_remaining != 0)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    if (plaintext_size < operation->full_tag_length) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

exit:
    psa_aead_abort(operation);

    return status;
}

psa_status_t psa_aead_abort(psa_aead_operation_t *operation)
{
    memset(operation, 0, sizeof(psa_aead_operation_t));
    return PSA_SUCCESS;
}
