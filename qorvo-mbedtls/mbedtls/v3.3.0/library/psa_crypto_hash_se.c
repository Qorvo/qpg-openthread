#include "psa/crypto.h"

#include "psa_esec_platform.h"
#include "psa_crypto_internal.h"

extern psa_esec_key psa_keys[NUMBER_OF_KEY_SLOTS];

extern psa_esec_settings psa_settings;

static const uint8_t sx_sha1_initial_value[] =
    {0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba,
    0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76, 0xc3, 0xd2, 0xe1, 0xf0};

static const uint8_t sx_sha224_initial_value[] =
   {0xc1, 0x05, 0x9e, 0xd8, 0x36, 0x7c, 0xd5, 0x07, 0x30, 0x70, 0xdd, 0x17, 0xf7, 0x0e, 0x59, 0x39,
   0xff, 0xc0, 0x0b, 0x31, 0x68, 0x58, 0x15, 0x11, 0x64, 0xf9, 0x8f, 0xa7, 0xbe, 0xfa, 0x4f, 0xa4};

static const uint8_t sx_sha256_initial_value[] =
   {0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
   0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19};

static const uint8_t sx_sha384_initial_value[] =
   {0xcb, 0xbb, 0x9d, 0x5d, 0xc1, 0x05, 0x9e, 0xd8, 0x62, 0x9a, 0x29, 0x2a, 0x36, 0x7c, 0xd5, 0x07,
   0x91, 0x59, 0x01, 0x5a, 0x30, 0x70, 0xdd, 0x17, 0x15, 0x2f, 0xec, 0xd8, 0xf7, 0x0e, 0x59, 0x39,
   0x67, 0x33, 0x26, 0x67, 0xff, 0xc0, 0x0b, 0x31, 0x8e, 0xb4, 0x4a, 0x87, 0x68, 0x58, 0x15, 0x11,
   0xdb, 0x0c, 0x2e, 0x0d, 0x64, 0xf9, 0x8f, 0xa7, 0x47, 0xb5, 0x48, 0x1d, 0xbe, 0xfa, 0x4f, 0xa4};

static const uint8_t sx_sha512_initial_value[] =
   {0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb, 0x67, 0xae, 0x85, 0x84, 0xca, 0xa7, 0x3b,
   0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94, 0xf8, 0x2b, 0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1,
   0x51, 0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1, 0x9b, 0x05, 0x68, 0x8c, 0x2b, 0x3e, 0x6c, 0x1f,
   0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd, 0x6b, 0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79};

psa_status_t psa_hash_compute(psa_algorithm_t alg, const uint8_t *input,
                              size_t input_length, uint8_t *hash,
                              size_t hash_size, size_t *hash_length)
{
    uint16_t esec_algo;
    uint32_t expected_hash_size;

    CHECK_INIT();

    switch (alg) {
    case PSA_ALG_SHA_1:
        esec_algo = ESEC_HASH_ALGO_SHA1;
        expected_hash_size = 20;
        break;
    case PSA_ALG_SHA_224:
        esec_algo = ESEC_HASH_ALGO_SHA224;
        expected_hash_size = 28;
        break;
    case PSA_ALG_SHA_256:
        esec_algo = ESEC_HASH_ALGO_SHA256;
        expected_hash_size = 32;
        break;
    case PSA_ALG_SHA_384:
        esec_algo = ESEC_HASH_ALGO_SHA384;
        expected_hash_size = 48;
        break;
    case PSA_ALG_SHA_512:
       esec_algo = ESEC_HASH_ALGO_SHA512;
       expected_hash_size = 64;
       break;
    default:
       return PSA_ERROR_NOT_SUPPORTED;
       break;
    }

    if (hash_size < expected_hash_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    uint32_t esec_status = esec_hash(esec_algo, input, input_length, hash);
    if (esec_status == ESEC_OKAY) {
        *hash_length = expected_hash_size;
    }
    return convert_esec_status_to_psa_status(esec_status);
}

psa_status_t psa_hash_compare(psa_algorithm_t alg, const uint8_t *input,
                              size_t input_length, const uint8_t *hash,
                              size_t hash_length)
{
    uint8_t digest[64];
    size_t calc_hash_len;

    CHECK_INIT();

    psa_status_t psa_status = psa_hash_compute(alg, input, input_length, digest, sizeof(digest), &calc_hash_len);
    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }
        
    if (calc_hash_len != hash_length || memcmp_time_cst(digest, hash, calc_hash_len) != 0) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    return PSA_SUCCESS;

}

psa_status_t psa_hash_setup(psa_hash_operation_t *operation, psa_algorithm_t alg)
{
    uint32_t block_size;
    const uint8_t* initial_state;

    CHECK_INIT();

    if (operation->alg != 0) {
        return PSA_ERROR_BAD_STATE;
    }

    switch (alg) {
        case PSA_ALG_SHA_1:
            block_size = 20;
            initial_state = sx_sha1_initial_value;
            break;
        case PSA_ALG_SHA_224:
            block_size = 32;
            initial_state = sx_sha224_initial_value;
            break;
        case PSA_ALG_SHA_256:
            block_size = 32;
            initial_state = sx_sha256_initial_value;
            break;
        case PSA_ALG_SHA_384:
            block_size = 64;
            initial_state = sx_sha384_initial_value;
            break;
        case PSA_ALG_SHA_512:
            block_size = 64;
            initial_state = sx_sha512_initial_value;
            break;
        default: 
            return (PSA_ALG_IS_HASH(alg) ? PSA_ERROR_NOT_SUPPORTED : PSA_ERROR_INVALID_ARGUMENT);
    }

    operation->alg = alg;
    memcpy(operation->buffer, initial_state, block_size);
    operation->uncompleted_len = 0;
    operation->block_size = block_size; 

    return PSA_SUCCESS;
}

psa_status_t psa_hash_update(psa_hash_operation_t *operation, const uint8_t *input,
                             size_t input_length)
{
    psa_status_t retval = 0;
    uint32_t esec_algo;
    uint8_t actual_hash[PSA_HASH_MAX_SIZE_IN_BYTES];
    uint32_t esec_status;

    CHECK_INIT();

    /* Don't require hash implementations to behave correctly on a
     * zero-length input, which may have an invalid pointer. */
    if (input_length == 0) {
        return PSA_SUCCESS;
    }

    switch (operation->alg) {
    case PSA_ALG_SHA_1:
        esec_algo = ESEC_HASH_ALGO_SHA1;
        break;
    case PSA_ALG_SHA_224:
        esec_algo = ESEC_HASH_ALGO_SHA224;
        break;
    case PSA_ALG_SHA_256:
        esec_algo = ESEC_HASH_ALGO_SHA256;
        break;
    case PSA_ALG_SHA_384:
        esec_algo = ESEC_HASH_ALGO_SHA384;
        break;
    case PSA_ALG_SHA_512:
        esec_algo = ESEC_HASH_ALGO_SHA512;
        break;
    default:
      return PSA_ERROR_BAD_STATE;
    }

    const uint8_t* update_ptr = input;
    uint32_t remaining_len = input_length;

    if (operation->uncompleted_len > 0) {
        if (operation->uncompleted_len + remaining_len < (operation->block_size * 2)) {
            uint8_t* dest_ptr = (uint8_t*)operation->uncompleted_block;
            dest_ptr = &dest_ptr[operation->uncompleted_len];
            memcpy(dest_ptr, update_ptr, remaining_len);
            operation->uncompleted_len += remaining_len;
            remaining_len = 0;
        } else {
            uint32_t block_rem_len = (operation->block_size *2) - operation->uncompleted_len;
            uint8_t* dest_ptr = (uint8_t*)operation->uncompleted_block;
            dest_ptr = &dest_ptr[operation->uncompleted_len];
            memcpy(dest_ptr, update_ptr, block_rem_len);
            
            esec_status = esec_hash_update(esec_algo, operation->buffer, operation->uncompleted_block, operation->block_size * 2, actual_hash);
            retval = convert_esec_status_to_psa_status(esec_status);
            if (retval != PSA_SUCCESS) {
                psa_hash_abort(operation);
                return retval;
            }
            
            operation->total_len += operation->block_size *2;

            update_ptr += block_rem_len;
            remaining_len -= block_rem_len;
            
            memcpy(operation->buffer, actual_hash, operation->block_size);
            operation->uncompleted_len = 0;
        }
    }

    while (remaining_len >= ((int)operation->block_size * 2) && operation->block_size) {
        esec_status = esec_hash_update(esec_algo, operation->buffer, update_ptr, operation->block_size*2, actual_hash);

        retval = convert_esec_status_to_psa_status(esec_status);
        if (retval != PSA_SUCCESS) {
            psa_hash_abort(operation);
            return retval;
        }

        operation->total_len += operation->block_size *2;

        memcpy(operation->buffer, actual_hash, operation->block_size);

        update_ptr += operation->block_size * 2;
        remaining_len -= operation->block_size * 2;
    }

    if (remaining_len > 0) {
        memcpy((uint8_t*)operation->uncompleted_block, update_ptr, remaining_len);
        operation->uncompleted_len = remaining_len;
    }

    return retval;
}

psa_status_t psa_hash_finish(psa_hash_operation_t *operation, uint8_t *hash,
                             size_t hash_size, size_t *hash_length)
{
    psa_status_t status;
    size_t actual_hash_length = PSA_HASH_LENGTH(operation->alg);
    uint32_t esec_algo;

    CHECK_INIT();

    /* Fill the output buffer with something that isn't a valid hash
     * (barring an attack on the hash and deliberately-crafted input),
     * in case the caller doesn't check the return status properly. */
    *hash_length = hash_size;
    /* If hash_size is 0 then hash may be NULL and then the
     * call to memset would have undefined behavior. */
    if (hash_size != 0) {
        memset(hash, '!', hash_size);
    }

    if (hash_size < actual_hash_length) {
        psa_hash_abort(operation);
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    switch (operation->alg) {
    case PSA_ALG_SHA_1:
        esec_algo = ESEC_HASH_ALGO_SHA1;
        break;
    case PSA_ALG_SHA_224:
        esec_algo = ESEC_HASH_ALGO_SHA224;
        break;
    case PSA_ALG_SHA_256:
        esec_algo = ESEC_HASH_ALGO_SHA256;
        break;
    case PSA_ALG_SHA_384:
        esec_algo = ESEC_HASH_ALGO_SHA384;
        break;
    case PSA_ALG_SHA_512:
        esec_algo = ESEC_HASH_ALGO_SHA512;
        break;
    default:
        psa_hash_abort(operation);
        return PSA_ERROR_BAD_STATE;
    }

    if (operation->uncompleted_len > 0) {
        uint32_t esec_status;
        if (operation->total_len == 0) {
            esec_status = esec_hash(esec_algo, operation->uncompleted_block, operation->uncompleted_len, hash);
        } else {
            esec_status = esec_hash_finish(esec_algo, operation->buffer, operation->uncompleted_block, operation->uncompleted_len, operation->total_len + operation->uncompleted_len, hash);
        }
        operation->uncompleted_len = 0;
        status = convert_esec_status_to_psa_status(esec_status);
    } else {
        memcpy(hash, operation->buffer, actual_hash_length);
        status = PSA_SUCCESS;
    }

    if (status == PSA_SUCCESS) {
        *hash_length = actual_hash_length;
    }

    return (psa_hash_abort(operation));
}

psa_status_t psa_hash_verify(psa_hash_operation_t *operation, const uint8_t *hash,
                             size_t hash_length)
{
    uint8_t actual_hash[PSA_HASH_MAX_SIZE_IN_BYTES];
    size_t actual_hash_length;

    CHECK_INIT();

    psa_status_t status = psa_hash_finish(operation, actual_hash, sizeof(actual_hash), &actual_hash_length);
    if (status != PSA_SUCCESS) {
       return status;
    }
    if (actual_hash_length != hash_length) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }
    if (memcmp_time_cst(hash, actual_hash, actual_hash_length) != 0) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_hash_abort(psa_hash_operation_t *operation)
{
    CHECK_INIT();
    operation->alg = 0;
    return PSA_SUCCESS;
}

psa_status_t psa_hash_clone(const psa_hash_operation_t *source_operation,
                            psa_hash_operation_t *target_operation)
{
    CHECK_INIT();

    if (source_operation->alg == 0 || target_operation->alg != 0) {
        return PSA_ERROR_BAD_STATE;
    }

    *target_operation = *source_operation;

    return PSA_SUCCESS;
}
