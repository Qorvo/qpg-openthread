#include "psa/crypto.h"

#include "psa_esec_platform.h"
#include "psa_crypto_internal.h"

static psa_status_t psa_mac_init(psa_mac_operation_t *operation, psa_algorithm_t alg)
{
    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;

    operation->alg = alg;
    operation->key_set = 0;
    operation->iv_set = 0;
    operation->iv_required = 0;
    operation->has_input = 0;
    operation->is_sign = 0;

    if (alg == PSA_ALG_CMAC) {
        operation->iv_required = 0;
        status = PSA_SUCCESS;
    } else if (PSA_ALG_IS_HMAC(operation->alg)) {
        /* We'll set up the hash operation later in psa_hmac_setup_internal. */
        status = PSA_SUCCESS;
    } else {
        if (!PSA_ALG_IS_MAC(alg)) {
            status = PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    if (status != PSA_SUCCESS) {
        memset(operation, 0, sizeof(*operation));
    }

    return status;
}

static psa_status_t psa_mac_setup(psa_mac_operation_t *operation, psa_key_id_t key, psa_algorithm_t alg, int is_sign)
{
    psa_status_t status;
    size_t key_bits;
    psa_key_usage_t usage = is_sign ? PSA_KEY_USAGE_SIGN_MESSAGE : PSA_KEY_USAGE_VERIFY_MESSAGE;
    uint8_t truncated = PSA_MAC_TRUNCATED_LENGTH(alg);
    psa_algorithm_t full_length_alg = PSA_ALG_FULL_LENGTH_MAC(alg);

    if (key >= NUMBER_OF_KEY_SLOTS) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    const psa_esec_key* slot = &psa_keys[key];

    if (!PSA_KEY_SLOT_OCCUPIED(slot->attributes.core.type)) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    /* A context must be freshly initialized before it can be set up. */
    if (operation->alg != 0) {
        return PSA_ERROR_BAD_STATE;
    }

    status = psa_mac_init(operation, full_length_alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (is_sign) {
        operation->is_sign = 1;
    }

    status = psa_check_key_policy(&slot->attributes, usage, alg);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    key_bits = slot->attributes.core.bits;

    if (full_length_alg == PSA_ALG_CMAC) {
        bool valid = psa_check_cipher_arguments(full_length_alg, slot->attributes.core.type);
        if (!valid) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }

        operation->key_handle = key;
        operation->mac_size = 16;
    } else if (PSA_ALG_IS_HMAC(full_length_alg)) {
        psa_algorithm_t hash_alg = PSA_ALG_HMAC_GET_HASH(alg);
        if (hash_alg == 0) {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }

        operation->mac_size = PSA_HASH_LENGTH(hash_alg);
        /* Sanity check. This shouldn't fail on a valid configuration. */
        if (operation->mac_size == 0 || operation->mac_size > PSA_HMAC_MAX_HASH_BLOCK_SIZE) {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }

        if (slot->attributes.core.type != PSA_KEY_TYPE_HMAC) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }

        operation->key_handle = key;
    } else {
        (void)key_bits;
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    if (truncated == 0) {
        /* The "normal" case: untruncated algorithm. Nothing to do. */
    } else if (truncated < 4) {
        /* A very short MAC is too short for security since it can be
         * brute-forced. Ancient protocols with 32-bit MACs do exist,
         * so we make this our minimum, even though 32 bits is still
         * too small for security. */
        status = PSA_ERROR_NOT_SUPPORTED;
    } else if (truncated > operation->mac_size) {
        /* It's impossible to "truncate" to a larger length. */
        status = PSA_ERROR_INVALID_ARGUMENT;
    } else {
        operation->mac_size = truncated;
    }

exit:
    if (status != PSA_SUCCESS) {
        psa_mac_abort(operation);
    } else {
        operation->key_set = 1;
    }
    return status;
}

static psa_status_t psa_mac_finish_internal(psa_mac_operation_t *operation, uint8_t *mac, size_t mac_size)
{
    CHECK_INIT();
    if (!operation->key_set) {
        return PSA_ERROR_BAD_STATE;
    }
    if (operation->iv_required && !operation->iv_set) {
        return PSA_ERROR_BAD_STATE;
    }

    if (mac_size < operation->mac_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (operation->alg == PSA_ALG_CMAC) {
        memcpy(mac, operation->ctx.cmac.tag, operation->mac_size);
        return PSA_SUCCESS;
    } else if (PSA_ALG_IS_HMAC(operation->alg)) {
        memcpy(mac, operation->ctx.hmac.digest, operation->mac_size);
        return PSA_SUCCESS;
    } else {
        /* This shouldn't happen if `operation` was initialized by a setup function. */
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_mac_compute(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *input,
                             size_t input_length, uint8_t *mac, size_t mac_size,
                             size_t *mac_length)
{
    psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
    psa_status_t status;
    psa_esec_key *slot;

    if (key >= NUMBER_OF_KEY_SLOTS) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    slot = &psa_keys[key];

    if (slot->attributes.core.type == PSA_KEY_TYPE_RAW_DATA) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = psa_mac_sign_setup(&operation, key, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_mac_update(&operation, input, input_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return psa_mac_sign_finish(&operation, mac, mac_size, mac_length);
}

psa_status_t psa_mac_verify(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *input,
                            size_t input_length, const uint8_t *mac, size_t mac_length)
{
    psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
    psa_status_t status;
    psa_esec_key *slot;

    if (key >= NUMBER_OF_KEY_SLOTS) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    slot = &psa_keys[key];

    if (slot->attributes.core.type == PSA_KEY_TYPE_RAW_DATA) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = psa_mac_verify_setup(&operation, key, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_mac_update(&operation, input, input_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return psa_mac_verify_finish(&operation, mac, mac_length);
}

psa_status_t psa_mac_sign_setup(psa_mac_operation_t *operation, psa_key_id_t key, psa_algorithm_t alg)
{
    return psa_mac_setup(operation, key, alg, 1);
}

psa_status_t psa_mac_verify_setup(psa_mac_operation_t *operation, psa_key_id_t key, psa_algorithm_t alg)
{
    return psa_mac_setup(operation, key, alg, 0);
}

psa_status_t psa_mac_update(psa_mac_operation_t *operation, const uint8_t *input, size_t input_length)
{
    psa_status_t status = PSA_ERROR_BAD_STATE;
    const psa_esec_key *slot;

    CHECK_INIT();
    if (!operation->key_set) {
        return PSA_ERROR_BAD_STATE;
    }
    if (operation->iv_required && !operation->iv_set) {
        return PSA_ERROR_BAD_STATE;
    }
    operation->has_input = 1;

    if (operation->key_handle >= NUMBER_OF_KEY_SLOTS) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    slot = &psa_keys[operation->key_handle];

    if (operation->alg == PSA_ALG_CMAC) {
        uint32_t esec_status = esec_cmac_generate(slot->eseckey.skey, input, input_length, operation->ctx.cmac.tag);
        status = convert_esec_status_to_psa_status(esec_status);
    } else if (PSA_ALG_IS_HMAC(operation->alg)) {
        uint32_t hashAlgo = 0; 
        switch (operation->alg) {
        case PSA_ALG_HMAC(PSA_ALG_SHA_224):
            hashAlgo = ESEC_HASH_ALGO_SHA224;
            break;
        case PSA_ALG_HMAC(PSA_ALG_SHA_256):
            hashAlgo = ESEC_HASH_ALGO_SHA256;
            break;
        case PSA_ALG_HMAC(PSA_ALG_SHA_512):
            hashAlgo = ESEC_HASH_ALGO_SHA512;
            break;
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        uint32_t esec_status = esec_hmac(hashAlgo, slot->eseckey.skey, input, input_length, operation->ctx.hmac.digest);
        status = convert_esec_status_to_psa_status(esec_status);
    } else {
        /* This shouldn't happen if `operation` was initialized by
            * a setup function. */
        return PSA_ERROR_BAD_STATE;
    }

    if (status != PSA_SUCCESS) {
        psa_mac_abort(operation);
    }

    return status;
}

psa_status_t psa_mac_sign_finish(psa_mac_operation_t *operation, uint8_t *mac, size_t mac_size,
                                 size_t *mac_length)
{
    psa_status_t status;

    CHECK_INIT();

    if (operation->alg == 0) {
        return PSA_ERROR_BAD_STATE;
    }

    /* Fill the output buffer with something that isn't a valid mac
     * (barring an attack on the mac and deliberately-crafted input),
     * in case the caller doesn't check the return status properly. */
    *mac_length = mac_size;
    /* If mac_size is 0 then mac may be NULL and then the
     * call to memset would have undefined behavior. */
    if (mac_size != 0) {
        memset(mac, '!', mac_size);
    }

    if (!operation->is_sign) {
        return PSA_ERROR_BAD_STATE;
    }

    status = psa_mac_finish_internal(operation, mac, mac_size);

    if (status == PSA_SUCCESS) {
        uint32_t macLen = operation->mac_size;
        status = psa_mac_abort(operation);
        if (status == PSA_SUCCESS) {
            *mac_length = macLen;
        } else {
            memset(mac, '!', mac_size);
        }
    } else {
        psa_mac_abort(operation);
    }
    return status;
}


psa_status_t psa_mac_verify_finish(psa_mac_operation_t *operation, const uint8_t *mac,
                                   size_t mac_length)
{
    uint8_t actual_mac[PSA_MAC_MAX_SIZE];
    psa_status_t status;

    CHECK_INIT();
    if (operation->alg == 0) {
        return PSA_ERROR_BAD_STATE;
    }

    if (operation->is_sign) {
        return PSA_ERROR_BAD_STATE;
    }

    if (operation->mac_size != mac_length) {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto cleanup;
    }

    status = psa_mac_finish_internal(operation, actual_mac, sizeof(actual_mac));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    if (memcmp(mac, actual_mac, mac_length) != 0) {
        status = PSA_ERROR_INVALID_SIGNATURE;
    }

cleanup:
    if (status == PSA_SUCCESS) {
        status = psa_mac_abort(operation);
    } else {
        psa_mac_abort(operation);
    }

    memset(actual_mac, 0, sizeof(actual_mac));

    return status;
}

psa_status_t psa_mac_abort(psa_mac_operation_t *operation)
{
    CHECK_INIT();
    if (operation->alg == 0) {
        /* The object has (apparently) been initialized but it is not
         * in use. It's ok to call abort on such an object, and there's
         * nothing to do. */
        return PSA_SUCCESS;
    } else if (operation->alg == PSA_ALG_CMAC || PSA_ALG_IS_HMAC(operation->alg)) {
    } else {
        /* Sanity check (shouldn't happen: operation->alg should
            * always have been initialized to a valid value). */
        goto bad_state;
    }

    memset(operation, 0, sizeof(psa_mac_operation_t));

    return PSA_SUCCESS;

bad_state:
    /* If abort is called on an uninitialized object, we can't trust
     * anything. Wipe the object in case it contains confidential data.
     * This may result in a memory leak if a pointer gets overwritten,
     * but it's too late to do anything about this. */
    memset(operation, 0, sizeof(*operation));
    return PSA_ERROR_BAD_STATE;
}
