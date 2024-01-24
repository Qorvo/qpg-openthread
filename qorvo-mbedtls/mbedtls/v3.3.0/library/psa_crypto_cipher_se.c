#include "psa/crypto.h"

#include "psa_esec_platform.h"
#include "psa_crypto_internal.h"

static uint32_t psa_aes_enc(psa_cipher_operation_t *operation, bool encrypt, const psa_esec_key *slot,
    struct esec_aes_state *state, struct esec_skey skey, const uint8_t iv[16], const uint8_t *intext,
    uint8_t *outtext, size_t len)
{
    uint32_t esec_status;

    if ((operation->alg == PSA_ALG_CTR) && (len % 16 != 0)) {
        esec_status = encrypt ? 
                        esec_aes_ctr_encrypt(skey, intext, iv, outtext, len) :
                        esec_aes_ctr_decrypt(skey, intext, iv, outtext, len);
    } else if (!operation->ctx.aes.started) {
        switch (operation->alg) {
        case PSA_ALG_CBC_NO_PADDING:
            esec_status = encrypt ?
                            esec_aes_cbc_enc_start(state, skey, iv, intext, outtext, len) :
                            esec_aes_cbc_dec_start(state, skey, iv, intext, outtext, len); 
            break;
        case PSA_ALG_CTR:
            esec_status = encrypt ? 
                            esec_aes_ctr_enc_start(state, skey, iv, intext, outtext, len) :
                            esec_aes_ctr_dec_start(state, skey, iv, intext, outtext, len);
            break;
        default:
            return PSA_ERROR_NOT_SUPPORTED;
        }
 
        if (esec_status == ESEC_OKAY) {
            operation->ctx.aes.started = true;
        }
    } else {
        if (encrypt) {
            esec_status = esec_aes_enc(state, intext, outtext, len);
        } else {
            esec_status = esec_aes_dec(state, intext, outtext, len);
        }
    }

    return esec_status;
}

static psa_status_t psa_cipher_init(psa_cipher_operation_t *operation, psa_algorithm_t alg)
{
    memset(operation, 0, sizeof(psa_cipher_operation_t));

    if (!PSA_ALG_IS_CIPHER(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    operation->alg = alg;
    operation->iv_required = 1;

    return PSA_SUCCESS;
}

static psa_status_t psa_cipher_setup(psa_cipher_operation_t *operation, psa_key_id_t handle, psa_algorithm_t alg, bool encrypt)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    size_t key_bits;
    psa_key_usage_t usage = (encrypt ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT);

    if (handle >= NUMBER_OF_KEY_SLOTS) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    const psa_esec_key *slot = &psa_keys[handle];

    if (slot->attributes.core.bits == 0) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    /* A context must be freshly initialized before it can be set up. */
    if (operation->alg != 0) {
        return PSA_ERROR_BAD_STATE;
    }

    status = psa_cipher_init(operation, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_check_key_policy(&slot->attributes, usage, alg);
    if (status != PSA_SUCCESS) {
        psa_cipher_abort(operation);
        return status;
    }

    key_bits = slot->attributes.core.bits;

    bool valid = psa_check_cipher_arguments(alg, slot->attributes.core.type);
    if (!valid) {
        status = PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }

    operation->key_set = 1;
    operation->block_size = (PSA_ALG_IS_STREAM_CIPHER(alg) ? 1 : PSA_BLOCK_CIPHER_BLOCK_LENGTH(slot->attributes.core.type));
    if (alg & PSA_ALG_CIPHER_FROM_BLOCK_FLAG) {
        operation->iv_size = PSA_BLOCK_CIPHER_BLOCK_LENGTH(slot->attributes.core.type);
    } else {
        if (alg == PSA_ALG_CHACHA20_POLY1305) {
            operation->iv_size = 12;
        }
    }

    operation->key_handle = handle;
    operation->encrypt = encrypt;

exit:
    if (status != PSA_SUCCESS)
        psa_cipher_abort(operation);

    return status;
}

psa_status_t psa_cipher_encrypt(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *input,
                                size_t input_length, uint8_t *output, size_t output_size,
                                size_t *output_length)
{
    psa_status_t status;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    uint8_t iv[PSA_IV_MAX_LENGTH];
    size_t iv_len;
    size_t iv_size;
    size_t temp_output_len = 0;

    status = psa_cipher_encrypt_setup(&operation, key, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* Let us get a backup for iv_size as operation instance will be released in psa_cipher_finish */
    iv_size = operation.iv_size;

    status = psa_cipher_generate_iv(&operation, iv, sizeof(iv), &iv_len);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (operation.iv_size > output_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Include IV as prefix */
    memcpy(output, operation.iv, operation.iv_size);
    output_size -= operation.iv_size;
    output += operation.iv_size;

    status = psa_cipher_update(&operation, input, input_length, output, output_size, &temp_output_len);
    if (status != PSA_SUCCESS) {
        return status;
    }

    output += temp_output_len;
    output_size -= temp_output_len;
    *output_length = temp_output_len;

    temp_output_len = 0;
    status = psa_cipher_finish(&operation, output, output_size, &temp_output_len);
    if (status != PSA_SUCCESS) {
        return status;
    }

    *output_length += temp_output_len;

    /* Add IV size if success */
    *output_length += iv_size;

    return PSA_SUCCESS;
}

psa_status_t psa_cipher_decrypt(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *input,
                                size_t input_length, uint8_t *output, size_t output_size,
                                size_t *output_length)
{
    psa_status_t status;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    size_t temp_output_len = 0;

    status = psa_cipher_decrypt_setup(&operation, key, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (operation.iv_size > input_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = psa_cipher_set_iv(&operation, input, operation.iv_size);
    if (status != PSA_SUCCESS) {
        return status;
    }

    input += operation.iv_size;
    input_length -= operation.iv_size;

    status = psa_cipher_update(&operation, input, input_length, output, output_size, &temp_output_len);
    if (status != PSA_SUCCESS) {
        return status;
    }

    input += temp_output_len;
    output_size -= temp_output_len;
    *output_length = temp_output_len;

    temp_output_len = 0;

    status = psa_cipher_finish(&operation, output, output_size, &temp_output_len);
    if (status != PSA_SUCCESS) {
        return status;
    }

    *output_length += temp_output_len;

    return PSA_SUCCESS;
}

psa_status_t psa_cipher_encrypt_setup(psa_cipher_operation_t *operation,
                                      psa_key_id_t key, psa_algorithm_t alg)
{
    return psa_cipher_setup(operation, key, alg, true);
}

psa_status_t psa_cipher_decrypt_setup(psa_cipher_operation_t *operation,
                                      psa_key_id_t key, psa_algorithm_t alg)
{
    return psa_cipher_setup(operation, key, alg, false);
}

psa_status_t psa_cipher_generate_iv(psa_cipher_operation_t *operation, uint8_t *iv,
                                    size_t iv_size, size_t *iv_length)
{
    psa_status_t status = PSA_SUCCESS;
    CHECK_INIT();

    if (operation->iv_set || !operation->iv_required) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (iv_size < operation->iv_size) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    psa_generate_random(iv, operation->iv_size);

    *iv_length = operation->iv_size;
    status = psa_cipher_set_iv(operation, iv, *iv_length);

exit:
    if (status != PSA_SUCCESS)
        psa_cipher_abort(operation);

    return status;
}

psa_status_t psa_cipher_set_iv(psa_cipher_operation_t *operation,
                               const uint8_t *iv, size_t iv_length)
{
    psa_status_t status = PSA_SUCCESS;
    CHECK_INIT();
    if (operation->iv_set || !operation->iv_required) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (iv_length != operation->iv_size) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    if (operation->key_handle >= NUMBER_OF_KEY_SLOTS) {
        status = PSA_ERROR_INVALID_HANDLE;
        goto exit;
    }

    const psa_esec_key *slot = &psa_keys[operation->key_handle];

    switch (slot->attributes.core.type) {
    case PSA_KEY_TYPE_AES:
    case PSA_KEY_TYPE_DES:
        if (iv_length > sizeof(operation->iv)) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        } else {
            memcpy(operation->iv, iv, iv_length);
        }
        break;
    default:
        status = PSA_ERROR_NOT_SUPPORTED;
        break;
    }

exit:
    if (status == PSA_SUCCESS) {
        operation->iv_set = 1;
    } else {
        psa_cipher_abort(operation);
    }

    return status;
}

psa_status_t psa_cipher_update(psa_cipher_operation_t *operation, const uint8_t *input,
                               size_t input_length, uint8_t *output, size_t output_size,
                               size_t *output_length)
{
    psa_status_t status = PSA_SUCCESS;
    size_t expected_output_size;
    const psa_esec_key *slot;
    uint32_t esec_status = 0;

    CHECK_INIT();

    if (operation->alg == 0) {
        return PSA_ERROR_BAD_STATE;
    }

    if (!PSA_ALG_IS_STREAM_CIPHER(operation->alg)) {
        /* Take the unprocessed partial block left over from previous
         * update calls, if any, plus the input to this call. Remove
         * the last partial block, if any. You get the data that will be
         * output in this call. */
        expected_output_size = (operation->unprocessedLength + input_length) / operation->block_size * operation->block_size;
    } else {
        expected_output_size = input_length;
    }

    if (output_size < expected_output_size) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    if (operation->key_handle >= NUMBER_OF_KEY_SLOTS) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    slot = &psa_keys[operation->key_handle];

    *output_length = 0;
    switch (slot->attributes.core.type) {
    case PSA_KEY_TYPE_AES:
    {
        if (operation->unprocessedLength == 0) {
            if (input_length > 0) {
                if (input_length % operation->block_size == 0) {
                    esec_status = psa_aes_enc(operation, operation->encrypt, slot, &operation->ctx.aes.state, slot->eseckey.skey, operation->iv, input, output, input_length);
                    if (esec_status == ESEC_OKAY) {
                        *output_length = input_length;
                    }
                } else {
                    uint32_t in_len = (input_length / operation->block_size) * operation->block_size;
                    uint32_t remaining_len = input_length - in_len;
                    if (in_len >= operation->block_size) {
                        esec_status = psa_aes_enc(operation, operation->encrypt, slot, &operation->ctx.aes.state, slot->eseckey.skey, operation->iv, input, output, in_len);
                        if (esec_status == ESEC_OKAY) {
                            *output_length = in_len;
                        }
                    }
                    memcpy(operation->ctx.aes.unprocessed_data, &input[in_len], remaining_len);
                    operation->unprocessedLength += remaining_len;
                }
            } else {
                esec_status = ESEC_OKAY;
            }
        } else {
            if (input_length <= operation->block_size - operation->unprocessedLength) {
                memcpy(&operation->ctx.aes.unprocessed_data[operation->unprocessedLength], input, input_length);
                operation->unprocessedLength += input_length;
                if (operation->unprocessedLength == operation->block_size) {
                    esec_status = psa_aes_enc(operation, operation->encrypt, slot, &operation->ctx.aes.state, slot->eseckey.skey, operation->iv, operation->ctx.aes.unprocessed_data, output, operation->block_size);
                    if (esec_status == ESEC_OKAY) {
                        *output_length = operation->block_size;
                    }
                    operation->unprocessedLength = 0;
                }
            } else {
                const uint8_t *in_ptr = input;
                uint32_t remaining = operation->block_size - operation->unprocessedLength;
                memcpy(&operation->ctx.aes.unprocessed_data[operation->unprocessedLength], in_ptr, remaining);
                operation->unprocessedLength += remaining;

                esec_status = psa_aes_enc(operation, operation->encrypt, slot, &operation->ctx.aes.state, slot->eseckey.skey, operation->iv, operation->ctx.aes.unprocessed_data, output, operation->block_size);
                operation->unprocessedLength = 0;
                *output_length = operation->block_size;

                in_ptr += remaining;
                remaining = input_length - remaining;

                if (remaining % operation->block_size == 0) {
                    esec_status = psa_aes_enc(operation, operation->encrypt, slot, &operation->ctx.aes.state, slot->eseckey.skey, operation->iv, in_ptr, output, remaining);
                    if (esec_status == ESEC_OKAY) {
                        *output_length += remaining;
                    }
                } else {
                    uint32_t in_len = (remaining / operation->block_size) * operation->block_size;
                    uint32_t remaining_len = remaining - in_len;
                    if (in_len >= operation->block_size) {
                        esec_status = psa_aes_enc(operation, operation->encrypt, slot, &operation->ctx.aes.state, slot->eseckey.skey, operation->iv, in_ptr, output, in_len);
                        if (esec_status == ESEC_OKAY) {
                            *output_length += in_len;
                        }
                    }
                    in_ptr += in_len;
                    memcpy(operation->ctx.aes.unprocessed_data, in_ptr, remaining_len);
                    operation->unprocessedLength += remaining_len;
                }
            }
        }
    }
    break;
    case PSA_KEY_TYPE_DES:
    {
        if (operation->encrypt) {
            esec_status = esec_3des_cbc_encrypt(slot->eseckey.skey, operation->iv, input, input_length, output);
        } else {
            esec_status = esec_3des_cbc_decrypt(slot->eseckey.skey, operation->iv, input, input_length, output);
        }
    }
    break;
    default:
        status = PSA_ERROR_NOT_SUPPORTED;
        goto exit;
        break;
    }

    status = convert_esec_status_to_psa_status(esec_status);
    if (status == PSA_SUCCESS) {
        switch (slot->attributes.core.type) {
        case PSA_KEY_TYPE_AES:
        case PSA_KEY_TYPE_DES:
            if (input_length == expected_output_size) {
                *output_length = expected_output_size;
            } else {
                *output_length = 0;
            }
            break;
        default:
            *output_length = 0;
            break;
        }
    }

exit:
    if (status != PSA_SUCCESS) {
        psa_cipher_abort(operation);
    }
    return status;
}

psa_status_t psa_cipher_finish(psa_cipher_operation_t *operation, uint8_t *output,
                               size_t output_size, size_t *output_length)
{
    uint32_t esec_status;
    psa_status_t status = PSA_SUCCESS;
    const psa_esec_key *slot;

    CHECK_INIT();

    if (!operation->key_set) {
        status = PSA_ERROR_BAD_STATE;
        goto error;
    }
    if (operation->iv_required && !operation->iv_set) {
        status = PSA_ERROR_BAD_STATE;
        goto error;
    }
    if (operation->key_handle >= NUMBER_OF_KEY_SLOTS) {
        status = PSA_ERROR_INVALID_HANDLE;
        goto error;
    }

    if (operation->encrypt &&
        operation->alg == PSA_ALG_CBC_NO_PADDING &&
        operation->unprocessedLength != 0) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto error;
    }

    if (!operation->encrypt &&
        operation->unprocessedLength != 0) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto error;
    }

    slot = &psa_keys[operation->key_handle];

    *output_length = 0;

    switch (slot->attributes.core.type) {
        case PSA_KEY_TYPE_AES:
            if (operation->unprocessedLength > 0) {
                esec_status = psa_aes_enc(operation, operation->encrypt, slot, &operation->ctx.aes.state,
                                slot->eseckey.skey, operation->iv, operation->ctx.aes.unprocessed_data,
                                output, operation->unprocessedLength);
            
                status = convert_esec_status_to_psa_status(esec_status);

                if (status == PSA_SUCCESS) {
                    *output_length = operation->block_size;
                }
            }
            break;
        case PSA_KEY_TYPE_DES:
            if (operation->unprocessedLength > 0) {
                status = PSA_ERROR_INVALID_ARGUMENT;
                goto error;
            }
        break;
        default:
            status = PSA_ERROR_NOT_SUPPORTED;
            goto error;
            break;
    }

error:
    if (status != PSA_SUCCESS) {
        *output_length = 0;
    }

    (void)psa_cipher_abort(operation);

    return status;
}

psa_status_t psa_cipher_abort(psa_cipher_operation_t *operation)
{
    CHECK_INIT();

    if (operation->alg == 0) {
        /* The object has (apparently) been initialized but it is not
         * in use. It's ok to call abort on such an object, and there's
         * nothing to do. */
        return PSA_SUCCESS;
    }

    /* Sanity check (shouldn't happen: operation->alg should
     * always have been initialized to a valid value). */
    if (!PSA_ALG_IS_CIPHER(operation->alg)) {
        return PSA_ERROR_BAD_STATE;
    }

    memset(operation, 0, sizeof(psa_cipher_operation_t));

    return PSA_SUCCESS;
}
