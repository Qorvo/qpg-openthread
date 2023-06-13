#include "psa/crypto.h"

#include "psa_esec_platform.h"
#include "psa_crypto_internal.h"

/* We use mbedTLS for DER Encoding/Decoding */
#include "mbedtls/pk.h"
#include "mbedtls/error.h"

/*
 * @brief Toggles the endianess of an buffer
 *
 */
static void psa_toggle_endianess(uint8_t *array, uint32_t array_size)
{
    for (uint32_t i = 0; i < array_size / 2; i++) {
        uint8_t tmp = array[i];
        array[i] = array[(array_size - 1) - i];
        array[(array_size - 1) - i] = tmp;
    }
}

/*
 * @brief Parses a RSA Public Key data in DER encoding, and returns raw data in eSecure Format
 */
psa_status_t psa_crypto_rsa_keypair_der_parse(const uint8_t *der_input, uint32_t der_input_len, uint8_t *out, uint32_t out_size, uint32_t *key_len_out, bool *short_expo_out)
{
    mbedtls_pk_context pk;

    mbedtls_pk_init(&pk);

    int ret = mbedtls_pk_parse_key(&pk, der_input, der_input_len, NULL, 0, NULL, NULL);
    if (ret != 0) {
        return PSA_ERROR_DATA_INVALID;
    }

    mbedtls_rsa_context *rsa = ((mbedtls_rsa_context*)(pk).MBEDTLS_PRIVATE(pk_ctx));
    uint32_t key_len = rsa->MBEDTLS_PRIVATE(len);
    uint32_t key_content_len = 2 * key_len + 5 * key_len / 2;
    bool short_exp = (rsa->MBEDTLS_PRIVATE(E).MBEDTLS_PRIVATE(n) == 1);
    uint32_t expo_len = short_exp ? 4 : key_len;
    uint32_t out_len = key_len + expo_len + (5 * (key_len / 2));

    uint8_t *key_content_ptr = out;

    if (out_size < out_len) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    memset(out, 0, out_len);

    /*
    * mbedtls library parses the fiels in little-endian 
    * while esecure needs in big-endian, so toggle the endianess
    */
    psa_toggle_endianess(((uint8_t*)rsa->MBEDTLS_PRIVATE(N).MBEDTLS_PRIVATE(p)),  key_len);
    psa_toggle_endianess(((uint8_t*)rsa->MBEDTLS_PRIVATE(E).MBEDTLS_PRIVATE(p)),  expo_len);
    psa_toggle_endianess(((uint8_t*)rsa->MBEDTLS_PRIVATE(P).MBEDTLS_PRIVATE(p)),  (key_len / 2));
    psa_toggle_endianess(((uint8_t*)rsa->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(p)),  (key_len / 2));
    psa_toggle_endianess(((uint8_t*)rsa->MBEDTLS_PRIVATE(DP).MBEDTLS_PRIVATE(p)), (key_len / 2));
    psa_toggle_endianess(((uint8_t*)rsa->MBEDTLS_PRIVATE(DQ).MBEDTLS_PRIVATE(p)), (key_len / 2));
    psa_toggle_endianess(((uint8_t*)rsa->MBEDTLS_PRIVATE(QP).MBEDTLS_PRIVATE(p)), (key_len / 2));

    /* Domain & Public */
    memcpy(key_content_ptr, (uint8_t*)rsa->MBEDTLS_PRIVATE(N).MBEDTLS_PRIVATE(p), key_len);       key_content_ptr += key_len;
    memcpy(key_content_ptr, (uint8_t*)rsa->MBEDTLS_PRIVATE(E).MBEDTLS_PRIVATE(p), expo_len);      key_content_ptr += expo_len;
    
    /* Private Key with with CRT */
    memcpy(key_content_ptr, (uint8_t*)rsa->MBEDTLS_PRIVATE(P).MBEDTLS_PRIVATE(p),  key_len / 2);  key_content_ptr += key_len / 2;
    memcpy(key_content_ptr, (uint8_t*)rsa->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(p),  key_len / 2);  key_content_ptr += key_len / 2;
    memcpy(key_content_ptr, (uint8_t*)rsa->MBEDTLS_PRIVATE(DP).MBEDTLS_PRIVATE(p), key_len / 2);  key_content_ptr += key_len / 2;
    memcpy(key_content_ptr, (uint8_t*)rsa->MBEDTLS_PRIVATE(DQ).MBEDTLS_PRIVATE(p), key_len / 2);  key_content_ptr += key_len / 2;
    memcpy(key_content_ptr, (uint8_t*)rsa->MBEDTLS_PRIVATE(QP).MBEDTLS_PRIVATE(p), key_len / 2);

    *key_len_out = key_len;
    *short_expo_out = short_exp;

    return PSA_SUCCESS;
}

/*
 * @brief Parses a RSA Public Key data in DER encoding, and returns raw data in eSecure Format
 */
psa_status_t psa_crypto_rsa_public_key_der_parse(const uint8_t *der_input, uint32_t der_input_len, uint8_t *out, uint32_t out_size, uint32_t *key_len_out, bool *short_expo_out)
{
    /* RSA Keys are DER encoded so we parse the keys first */
    mbedtls_pk_context pk;

    mbedtls_pk_init(&pk);

    int ret = mbedtls_pk_parse_public_key(&pk, der_input, der_input_len);
    if (ret != 0) {
        return PSA_ERROR_DATA_INVALID;
    }

    mbedtls_rsa_context *rsa = ((mbedtls_rsa_context*)(pk).MBEDTLS_PRIVATE(pk_ctx));
    uint32_t key_len = rsa->MBEDTLS_PRIVATE(len);
    bool short_exp = (rsa->MBEDTLS_PRIVATE(E).MBEDTLS_PRIVATE(n) == 1);
    uint32_t expo_len = short_exp ? 4 : key_len;
    uint32_t out_len = key_len + expo_len;
    uint8_t *key_content_ptr = out;

    if (out_size < out_len) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    memset(out, 0, out_len);

    memcpy(key_content_ptr, (uint8_t*)rsa->MBEDTLS_PRIVATE(N).MBEDTLS_PRIVATE(p), key_len);  key_content_ptr += key_len;
    memcpy(key_content_ptr, (uint8_t*)rsa->MBEDTLS_PRIVATE(E).MBEDTLS_PRIVATE(p), expo_len);

    *key_len_out = key_len;
    *short_expo_out = short_exp;

    return PSA_SUCCESS;
}