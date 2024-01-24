#include "psa/crypto.h"

#include "psa_esec_platform.h"
#include "psa_crypto_internal.h"


/*
 * As there is no libesecure API to ask whether the volatile key slot is occupied, we retry
 * to import the key for KEY_RETRY_COUNT time if we fail to import the key into esecure
 */
#define ESEC_KEY_IMPORT_RETRY_COUNT             (NUMBER_OF_KEY_SLOTS)

/* PSA HKDF States */
#define PSA_HKDF_STATE_INIT                         0 /* no input yet */
#define PSA_HKDF_STATE_STARTED                      1 /* got salt */
#define PSA_HKDF_STATE_KEYED                        2 /* got key */
#define PSA_HKDF_STATE_OUTPUT                       3 /* output started */

/* Key Aggreement Flags */
#define PSA_KA_FLAG_HAS_SLOT_NUMBER                 ((psa_key_attributes_flag_t)0x0001)
#define PSA_KA_MASK_EXTERNAL_ONLY                   (PSA_KA_FLAG_HAS_SLOT_NUMBER | 0 )
#define PSA_KA_MASK_DUAL_USE                        (0)

/* The maximum size of groups, in bits. */
#define PSA_ECP_MAX_BITS                            521

#define PSA_ECP_MAX_BYTES                           ((PSA_ECP_MAX_BITS + 7) / 8)
#define PSA_KEY_AGREEMENT_MAX_SHARED_SECRET_SIZE    (PSA_ECP_MAX_BYTES * 2)

#define PSA_IS_VALID_DES_DATA_LEN(__len) \
            (((__len) ==  8) || \
             ((__len) == 16) || \
             ((__len) == 20) || \
             ((__len) == 24) || \
             ((__len) == 28) || \
             ((__len) == 32) || \
             ((__len) == 64))

#define PSA_IS_VALID_DES_KEY_SIZE_IN_BITS(__bits) \
            (((__bits) ==   0) || \
             ((__bits) ==  64) || \
             ((__bits) == 128) || \
             ((__bits) == 160) || \
             ((__bits) == 192) || \
             ((__bits) == 224) || \
             ((__bits) == 256) || \
             ((__bits) == 512))

/* The ECC Key Size = Bit[6:0] + 1 */
#define ESEC_GET_ECC_KEYLEN_FROM_KEYSPEC(__keyspec)     (((__keyspec) & 0x7F) + 1)

/* We need a buffer to serialise the RSA Key Content for eSecure */
uint32_t esec_rsa_key_content[ESECURE_RSA_MAX_KEY_CONTENT_SIZE / 4];

void platform_init(void);

/*
 * PSA Keys
 * This is a mapping between PSA and eSecure keys
 */
psa_esec_key psa_keys[NUMBER_OF_KEY_SLOTS];

/* PSA Global Settings */
psa_esec_settings psa_settings;

uint32_t memcmp_time_cst(const uint8_t *in1, const uint8_t *in2, uint32_t size)
{
  //Don't try to optimise this function for performance, it's time constant for security reasons
   uint32_t diff = 0;
   uint32_t i = 0;
   for(i = 0; i < size; i++) {
      diff |= (*(in1 + i)^(*(in2 + i)));
   }

   return (diff > 0);
}

/** Invalidates a slot in PSA Implementation.
 *
 *  There is no API in eSecure to ask for whether a key index is available so
 *  if the key import fails for an index in eSecure, we need to invalidate the
 *  same index in the PSA implementation to avoid any allocation in PSA
 *  Implementation.
 */
static void invalidate_key_slot(int key_index)
{
    if (key_index < NUMBER_OF_KEY_SLOTS) {
        psa_keys[key_index].attributes.core.type = PSA_KEY_SLOT_INVALID;
    }
}

static bool is_keyslot_available(uint32_t key_index)
{
    if (key_index >= NUMBER_OF_KEY_SLOTS)
        return false;

    return PSA_KEY_SLOT_AVAILABLE(psa_keys[key_index].attributes.core.type);
}

/** Finds an empty slot for a new key
 */
static int psa_get_empty_slot(void)
{
    int key_index;

    /* Index 0 not acceptable by PSA so start from 1 */
    for (key_index = 1; key_index < NUMBER_OF_KEY_SLOTS; key_index++) {
        if (PSA_KEY_SLOT_AVAILABLE(psa_keys[key_index].attributes.core.type)) {
            return key_index;
        }
    }

    return -1;
}

/** Flushes a persistent key to the persistent key storage.
 */
static psa_status_t psa_flush_key(const psa_esec_key* key)
{
    return psa_plat_crypto_flush_key(key);
}

/** Set a PSA Key slot with its attributes
 */
static psa_status_t psa_set_key_slot(psa_key_id_t key, const psa_key_attributes_t* attributes,
    const esec_key* esec_key, uint32_t key_len_in_bits)
{
    psa_esec_key* slot = &psa_keys[key];
    slot->attributes = *attributes;
    if (slot->attributes.core.bits == 0) {
        slot->attributes.core.bits = key_len_in_bits;
    }
    slot->eseckey = *esec_key;
    return psa_flush_key(slot);
}

/** Returns Storage instance for the esec key
 */
static psa_status_t psa_get_esec_key_storage(
    bool is_persistent_key, int32_t* key_index,
    uint32_t data_length, struct esec_key_storage* storage)
{
    if (*key_index >= 0) {
        invalidate_key_slot(*key_index);
    }

    *key_index = psa_get_empty_slot();
    if (*key_index < 0) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    if (is_persistent_key) {
        uint8_t* key_buffer = (uint8_t*)psa_plat_mem_alloc(data_length + ESEC_STOR_PROT_SIZE);
        if (key_buffer == NULL) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        *storage = (struct esec_key_storage)ESEC_STORAGE_WRAPPED(key_buffer, firmware_key_auth);
    } else {
        *storage = (struct esec_key_storage)ESEC_STORAGE_VOLATILE((*key_index)-1, firmware_key_auth);
    }

    return PSA_SUCCESS;
}

static int psa_is_key_id_valid(psa_key_id_t key_id, int vendor_ok)
{
    if (PSA_KEY_ID_USER_MIN <= key_id && key_id <= PSA_KEY_ID_USER_MAX) {
        return 1;
    } else if (vendor_ok && PSA_KEY_ID_VENDOR_MIN <= key_id && key_id <= PSA_KEY_ID_VENDOR_MAX) {
        return 1;
    } else {
        return 0;
    }
}

static psa_status_t psa_validate_persistent_key_parameters(psa_key_lifetime_t lifetime, psa_key_id_t id, int creating)
{
    if (lifetime != PSA_KEY_LIFETIME_PERSISTENT) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!psa_is_key_id_valid(id, !creating)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

static psa_status_t psa_validate_key_policy(const psa_key_policy_t* policy)
{
    if ((policy->usage & ~(PSA_KEY_USAGE_EXPORT |
                           PSA_KEY_USAGE_COPY |
                           PSA_KEY_USAGE_ENCRYPT |
                           PSA_KEY_USAGE_DECRYPT |
                           PSA_KEY_USAGE_SIGN_HASH |
                           PSA_KEY_USAGE_VERIFY_HASH |
                           PSA_KEY_USAGE_DERIVE)) != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

static psa_status_t psa_validate_key_attributes(const psa_key_attributes_t* attributes)
{
    psa_status_t status;

    if (attributes->core.lifetime != PSA_KEY_LIFETIME_VOLATILE) {
        status = psa_validate_persistent_key_parameters(attributes->core.lifetime, attributes->core.id, 1);
        if (status != PSA_SUCCESS) {
            return status;
        }
    }

    status = psa_validate_key_policy(&attributes->core.policy);
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* Refuse to create overly large keys.
     * Note that this doesn't trigger on import if the attributes don't
     * explicitly specify a size (so psa_get_key_bits returns 0), so
     * psa_import_key() needs its own checks. */
    if (psa_get_key_bits(attributes) > PSA_MAX_KEY_BITS) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Reject invalid flags. These should not be reachable through the API. */
    if (attributes->core.flags & ~(PSA_KA_MASK_EXTERNAL_ONLY | PSA_KA_MASK_DUAL_USE)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

static psa_status_t psa_validate_optional_attributes(const psa_esec_key *slot, const psa_key_attributes_t *attributes)
{
    if (attributes->core.type != 0) {
        if (attributes->core.type != slot->attributes.core.type) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    if (attributes->domain_parameters_size != 0) {
        if (PSA_KEY_TYPE_IS_RSA(slot->attributes.core.type)) {
            return PSA_ERROR_NOT_SUPPORTED;
        } else {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    if (attributes->core.bits != 0) {
        if (attributes->core.bits != slot->attributes.core.bits) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    return PSA_SUCCESS;
}

static psa_algorithm_t psa_key_policy_algorithm_intersection(psa_algorithm_t alg1, psa_algorithm_t alg2)
{
    /* Common case: both sides actually specify the same policy. */
    if (alg1 == alg2) {
        return alg1;
    }

    /* If the policies are from the same hash-and-sign family, check
     * if one is a wildcard. If so the other has the specific algorithm. */
    if (PSA_ALG_IS_HASH_AND_SIGN(alg1) && PSA_ALG_IS_HASH_AND_SIGN(alg2) &&
        (alg1 & ~PSA_ALG_HASH_MASK) == (alg2 & ~PSA_ALG_HASH_MASK)) {
        if (PSA_ALG_SIGN_GET_HASH(alg1) == PSA_ALG_ANY_HASH) {
            return alg2;
        }

        if (PSA_ALG_SIGN_GET_HASH(alg2) == PSA_ALG_ANY_HASH) {
            return alg1;
        }
    }

    /* If the policies are incompatible, allow nothing. */
    return PSA_ALG_NONE;
}

static psa_status_t psa_restrict_key_policy(psa_key_policy_t *policy, const psa_key_policy_t *constraint)
{
    psa_algorithm_t intersection_alg = psa_key_policy_algorithm_intersection(policy->alg, constraint->alg);
    psa_algorithm_t intersection_alg2 = psa_key_policy_algorithm_intersection(policy->alg2, constraint->alg2);

    if (intersection_alg == 0 && policy->alg != 0 && constraint->alg != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (intersection_alg2 == 0 && policy->alg2 != 0 && constraint->alg2 != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    policy->usage &= constraint->usage;
    policy->alg = intersection_alg;
    policy->alg2 = intersection_alg2;
    return PSA_SUCCESS;
}

static psa_status_t psa_sign_verify_check_alg(int input_is_message, psa_algorithm_t alg)
{
    if (input_is_message) {
        if (!PSA_ALG_IS_SIGN_MESSAGE(alg)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        if (PSA_ALG_IS_HASH_AND_SIGN(alg)) {
            if(!PSA_ALG_IS_HASH(PSA_ALG_SIGN_GET_HASH(alg))) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
        }
    } else {
        if (!PSA_ALG_IS_HASH_AND_SIGN(alg)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    return PSA_SUCCESS;
}

static psa_status_t import_skey(uint32_t key_policy_usage, bool is_persistent_key, int32_t* key_index, const uint8_t* key_data, size_t data_length, struct esec_key_storage storage, esec_key* volatile_key)
{
    psa_status_t retval;
    uint32_t esec_status;
    bool persistent_key_allocated = false;
    int32_t key_retry_count = ESEC_KEY_IMPORT_RETRY_COUNT;

    do {
        if (!persistent_key_allocated) {
            retval = psa_get_esec_key_storage(is_persistent_key, key_index, data_length, &storage);
            if (retval != PSA_SUCCESS) {
                return retval;
            }

            /* We allocate a slot in host, let us re-use it next time in case esec_import_key fails */
            persistent_key_allocated = true;
        }

        esec_status = esec_import_skey(key_data, (uint16_t)data_length, storage, key_policy_usage, &volatile_key->skey);
    } while (esec_status != ESEC_OKAY && key_retry_count-- > 0);

    return convert_esec_status_to_psa_status(esec_status);
}

static psa_status_t create_ecc_key(uint32_t domainspec, uint32_t key_policy_usage, bool is_persistent_key, int32_t* key_index, struct esec_key_storage storage, esec_key* volatile_key)
{
    psa_status_t retval;
    uint32_t esec_status;
    bool persistent_key_allocated = false;
    int32_t key_retry_count = ESEC_KEY_IMPORT_RETRY_COUNT;
    uint32_t key_len_in_bytes = ESEC_GET_ECC_KEYLEN_FROM_KEYSPEC(domainspec) * 3;

    do {
        if (!persistent_key_allocated) {
            retval = psa_get_esec_key_storage(is_persistent_key, key_index, key_len_in_bytes, &storage);
            if (retval != PSA_SUCCESS)
                return retval;

            /* We allocate a slot in host, let us re-use it next time in case esec_import_key fails */
            persistent_key_allocated = true;
        }

        esec_status = esec_ecc_create_key(domainspec, NULL, storage, key_policy_usage, &volatile_key->ecckey);
    } while (esec_status != ESEC_OKAY && key_retry_count-- > 0);

    return convert_esec_status_to_psa_status(esec_status);
}

static psa_status_t import_ecc_key(uint32_t domainspec, uint32_t key_policy_usage, bool is_persistent_key, int32_t* key_index, const uint8_t* key_data, size_t data_length, struct esec_key_storage storage, esec_key* volatile_key)
{
    psa_status_t retval;
    uint32_t esec_status;
    bool persistent_key_allocated = false;
    int32_t key_retry_count = ESEC_KEY_IMPORT_RETRY_COUNT;

    do {
        if (!persistent_key_allocated) {
            retval = psa_get_esec_key_storage(is_persistent_key, key_index, data_length, &storage);
            if (retval != PSA_SUCCESS) {
                return retval;
            }

            /* We allocate a slot in host, let us re-use it next time in case esec_import_key fails */
            persistent_key_allocated = true;
        }

        esec_status = esec_ecc_import_key(domainspec, key_data, storage, key_policy_usage, &volatile_key->ecckey);
    } while (esec_status != ESEC_OKAY && key_retry_count-- > 0);

    return convert_esec_status_to_psa_status(esec_status);
}

static psa_status_t import_rsa_key(uint32_t domainspec, uint32_t key_policy_usage, bool is_persistent_key, int32_t *key_index, uint8_t *data, size_t data_length, struct esec_key_storage storage, esec_key *volatile_key)
{
    psa_status_t retval;
    uint32_t esec_status;
    bool persistent_key_allocated = false;
    int32_t key_retry_count = ESEC_KEY_IMPORT_RETRY_COUNT;

    do {
        if (!persistent_key_allocated) {
            retval = psa_get_esec_key_storage(is_persistent_key, key_index, data_length, &storage);
            if (retval != PSA_SUCCESS) {
                return retval;
            }

            /* We allocate a slot in host, let us re-use it next time in case esec_import_key fails */
            persistent_key_allocated = true;
        }

        esec_status = esec_rsa_import_key(domainspec, data, storage, key_policy_usage, &volatile_key->rsakey);
    } while (esec_status != ESEC_OKAY && key_retry_count-- > 0);

    return convert_esec_status_to_psa_status(esec_status);
}

static psa_status_t transfer_rsa_key(struct esec_rsa_key source_key, bool is_persistent_key, uint32_t key_len, int32_t *key_index, struct esec_key_storage storage, esec_key *volatile_key)
{
    psa_status_t retval;
    uint32_t esec_status;
    bool persistent_key_allocated = false;
    int32_t key_retry_count = ESEC_KEY_IMPORT_RETRY_COUNT;

    do {
        if (!persistent_key_allocated) {
            retval = psa_get_esec_key_storage(is_persistent_key, key_index, key_len, &storage);
            if (retval != PSA_SUCCESS) {
                return retval;
            }

            /* We allocate a slot in host, let us re-use it next time in case esec_import_key fails */
            persistent_key_allocated = true;
        }

        esec_status = esec_rsa_transfer_key(source_key, storage, 0, &volatile_key->rsakey);
    } while (esec_status != ESEC_OKAY && key_retry_count-- > 0);

    return convert_esec_status_to_psa_status(esec_status);
}

static psa_status_t transfer_ecc_key(struct esec_ecc_key source_key, bool is_persistent_key, uint32_t key_len, int32_t *key_index, struct esec_key_storage storage, esec_key *volatile_key)
{
    psa_status_t retval;
    uint32_t esec_status;
    bool persistent_key_allocated = false;
    int32_t key_retry_count = ESEC_KEY_IMPORT_RETRY_COUNT;

    do {
        if (!persistent_key_allocated) {
            retval = psa_get_esec_key_storage(is_persistent_key, key_index, key_len, &storage);
            if (retval != PSA_SUCCESS) {
                return retval;
            }

            /* We allocate a slot in host, let us re-use it next time in case esec_import_key fails */
            persistent_key_allocated = true;
        }

        esec_status = esec_ecc_transfer_key(source_key, storage, 0, &volatile_key->ecckey);
    } while (esec_status != ESEC_OKAY && key_retry_count-- > 0);

    return convert_esec_status_to_psa_status(esec_status);
}

static psa_status_t transfer_skey(struct esec_skey source_key, bool is_persistent_key, uint32_t key_len, int32_t *key_index, struct esec_key_storage storage, esec_key *volatile_key)
{
    psa_status_t retval;
    uint32_t esec_status;
    bool persistent_key_allocated = false;
    int32_t key_retry_count = ESEC_KEY_IMPORT_RETRY_COUNT;

    do {
        if (!persistent_key_allocated) {
            retval = psa_get_esec_key_storage(is_persistent_key, key_index, key_len, &storage);
            if (retval != PSA_SUCCESS) {
                return retval;
            }

            /* We allocate a slot in host, let us re-use it next time in case esec_import_key fails */
            persistent_key_allocated = true;
        }

        esec_status = esec_transfer_skey(source_key, storage, 0, &volatile_key->skey);
    } while (esec_status != ESEC_OKAY && key_retry_count-- > 0);

    return convert_esec_status_to_psa_status(esec_status);
}

static psa_status_t derive_hkdf_skey(struct esec_skey source_key, bool is_persistent_key, int32_t *key_index, size_t data_length, psa_hkdf_key_derivation_t *hkdf, struct esec_key_storage storage, struct esec_skey *out_key)
{
    psa_status_t retval;
    uint32_t esec_status;
    bool persistent_key_allocated = false;
    int32_t key_retry_count = ESEC_KEY_IMPORT_RETRY_COUNT;

    if (is_persistent_key) {
        uint8_t *key_buffer = (uint8_t*)psa_plat_mem_alloc(data_length + ESEC_STOR_PROT_SIZE);
        if (key_buffer == NULL) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        esec_status = esec_derive_hkdf_skey(source_key, ESEC_HASH_ALGO_SHA256,
                                            hkdf->salt, hkdf->salt_length, hkdf->info, hkdf->info_length,
                                            (struct esec_key_storage)ESEC_STORAGE_WRAPPED(key_buffer, firmware_key_auth),
                                            data_length, out_key);

    } else {
        for (int32_t slot_index = 0; slot_index < NUMBER_OF_KEY_SLOTS; slot_index++) {
            if (!is_keyslot_available(slot_index)) {
                continue;
            }

            esec_status = esec_derive_hkdf_skey(source_key, ESEC_HASH_ALGO_SHA256,
                                                hkdf->salt, hkdf->salt_length, hkdf->info, hkdf->info_length,
                                                (struct esec_key_storage)ESEC_STORAGE_VOLATILE(slot_index - 1, firmware_key_auth),
                                                data_length, out_key);

            if (esec_status == ESEC_OKAY) {
                *key_index = slot_index;
                break;
            }

            /* Failed, the volatile key slot must be occupied in esecure side, so let us invalidate the slot in psa side */
            invalidate_key_slot(slot_index);
        }
    }

    return convert_esec_status_to_psa_status(esec_status);
}

static psa_status_t psa_import_key_asym(
    const psa_key_attributes_t *attributes, const uint8_t *data,
    size_t data_length, int32_t *key_index, esec_key *volatile_key,
    uint16_t *key_len_in_bits)
{
    psa_status_t retval = PSA_ERROR_INVALID_ARGUMENT;
    uint32_t key_policy_usage = 0;
    uint32_t domainspec = 0;
    bool is_persistent_key = attributes->core.lifetime == PSA_KEY_LIFETIME_PERSISTENT;
    struct esec_key_storage storage;

    if (attributes->core.policy.usage & PSA_KEY_USAGE_EXPORT) {
        key_policy_usage |= ESEC_KEY_EXPORTABLE;
    }

    if (attributes->core.policy.usage & PSA_KEY_USAGE_SIGN_MESSAGE ||
        attributes->core.policy.usage & PSA_KEY_USAGE_SIGN_HASH ||
        attributes->core.policy.usage & PSA_KEY_USAGE_VERIFY_MESSAGE ||
        attributes->core.policy.usage & PSA_KEY_USAGE_VERIFY_HASH) {
        domainspec |= ESEC_KEY_PERMS_SIGN;
    }

    switch (attributes->core.type) {
        case PSA_KEY_TYPE_RSA_PUBLIC_KEY: {
                uint32_t key_len;
                bool short_expo;

                retval = psa_crypto_rsa_public_key_der_parse(data, data_length, (uint8_t*)esec_rsa_key_content, sizeof(esec_rsa_key_content), &key_len, &short_expo);

                if (retval == PSA_SUCCESS) {
                    uint32_t short_exp_flag = short_expo ? ESEC_KEY_SHORT_EXP : 0;
                    /* Build the domainspec value for esecure */
                    domainspec = ESEC_KEY_RSA(key_len) | ESEC_KEY_PUB | short_exp_flag | domainspec;
                    retval = import_rsa_key(domainspec, key_policy_usage, is_persistent_key, key_index, (uint8_t*)esec_rsa_key_content, key_len * 2, storage, volatile_key);
                    if (retval == PSA_SUCCESS) {
                        *key_len_in_bits = (uint16_t)(key_len * 8);
                    }
                }
            }
            break;
        case PSA_KEY_TYPE_RSA_KEY_PAIR: {
                uint32_t esec_status;
                uint32_t key_len;
                bool short_exp;
                retval = psa_crypto_rsa_keypair_der_parse(data, data_length, (uint8_t*)esec_rsa_key_content, sizeof(esec_rsa_key_content), &key_len, &short_exp);

                if (retval == PSA_SUCCESS) {
                    uint32_t short_exp_flag = short_exp ? ESEC_KEY_SHORT_EXP : 0;
                    uint32_t key_content_len = 2 * key_len + 5 * key_len / 2;

                    /* Build the domainspec value for esecure */
                    domainspec = ESEC_KEY_RSA(key_len) | ESEC_KEY_PAIR | ESEC_KEY_PRIV_CRT | short_exp_flag | domainspec;

                    retval = import_rsa_key(domainspec, key_policy_usage, is_persistent_key, key_index, (uint8_t*)esec_rsa_key_content, key_content_len, storage, volatile_key);
                    if (retval == PSA_SUCCESS) {
                        *key_len_in_bits = (uint16_t)(key_len * 8);
                    }
                }
            }
            break;
        case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1): {
                /* API passes only private key for ECC Key Pairs, so we need to collect key pair before import into eSecure */
                uint8_t ecc_key_pair_data[PSA_BITS_TO_BYTES(ECC_MAX_KEY_SIZE_BITS) * 3];
                struct esec_ecc_key temp_ecc_key;
                uint8_t temp_material[PSA_BITS_TO_BYTES(ECC_MAX_KEY_SIZE_BITS) + ESEC_STOR_PROT_SIZE];
                domainspec |= ESEC_KEY_PRIV;
                switch (data_length) {
                case PSA_BITS_TO_BYTES(192):
                    domainspec |= ESEC_KEY_ECC_P192;
                    break;
                case PSA_BITS_TO_BYTES(224):
                    domainspec |= ESEC_KEY_ECC_P224;
                    break;
                case PSA_BITS_TO_BYTES(256):
                    domainspec |= ESEC_KEY_ECC_P256;
                    break;
                case PSA_BITS_TO_BYTES(384):
                    domainspec |= ESEC_KEY_ECC_P384;
                    break;
                case PSA_BITS_TO_BYTES(521):
                    domainspec |= ESEC_KEY_ECC_P521;
                    break;
                default:
                    return PSA_ERROR_INVALID_ARGUMENT;
                }

                retval = esec_ecc_import_key(domainspec, data,
                                (struct esec_key_storage)ESEC_STORAGE_WRAPPED(temp_material, firmware_key_auth),
                                ESEC_KEY_EXPORTABLE, &temp_ecc_key);
                if (retval == ESEC_OKAY) {
                    retval = esec_ecc_read_pub_key(temp_ecc_key, &ecc_key_pair_data[0]);
                }

                if (retval == ESEC_OKAY) {
                    /* Build the key pair */
                    memcpy(&ecc_key_pair_data[2 * data_length], data, data_length);
                    domainspec |= ESEC_KEY_PUB;
                    retval = import_ecc_key(domainspec, key_policy_usage, is_persistent_key, key_index, ecc_key_pair_data, 3 * data_length, storage, volatile_key);
                }

                *key_len_in_bits = (uint16_t)((data_length) * 8);
            }
            break;
        case PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1): {
                domainspec |= ESEC_KEY_PUB;
                switch ((data_length/2)) {
                case PSA_BITS_TO_BYTES(192):
                    domainspec |= ESEC_KEY_ECC_P192;
                    break;
                case PSA_BITS_TO_BYTES(224):
                    domainspec |= ESEC_KEY_ECC_P224;
                    break;
                case PSA_BITS_TO_BYTES(256):
                    domainspec |= ESEC_KEY_ECC_P256;
                    break;
                case PSA_BITS_TO_BYTES(384):
                    domainspec |= ESEC_KEY_ECC_P384;
                    break;
                case PSA_BITS_TO_BYTES(521):
                    domainspec |= ESEC_KEY_ECC_P521;
                    break;
                default:
                    return PSA_ERROR_INVALID_ARGUMENT;
                }

                /*
                 * Important : As PSA API requires old style ECC data format with 0x4 prefix, we ignore the prefix
                 * during importing into esecure
                 */
                const uint8_t *key_data = data + 1;

                retval = import_ecc_key(domainspec, key_policy_usage, is_persistent_key, key_index, key_data, data_length, storage, volatile_key);

                *key_len_in_bits = (uint16_t)(data_length / 2) * 8;
            }
            break;
        default:
            retval = PSA_ERROR_NOT_SUPPORTED;
            break;
    }

    return retval;
}

static psa_status_t psa_export_key_asym(const psa_esec_key *slot, uint8_t *data, size_t data_size, size_t *data_length)
{
    psa_status_t retval;
    uint32_t esec_status;
    *data_length = slot->attributes.core.bits / 8;
    switch (slot->attributes.core.type) {
        case PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1):
        case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1): {
                /*
                 * PSA API passes only private key for key pair, but we need to inject public key
                 * when we import. And we export the key, the PSA API also expect s only private
                 * key for key pair.
                 */
                uint8_t ecc_key_pair_data[PSA_BITS_TO_BYTES(ECC_MAX_KEY_SIZE_BITS) * 3];
                uint32_t key_len = ESEC_GET_ECC_KEYLEN_FROM_KEYSPEC(slot->eseckey.ecckey.keyspec);

                esec_status = esec_ecc_export_key(slot->eseckey.ecckey, ecc_key_pair_data);

                if ((slot->eseckey.ecckey.keyspec & ESEC_KEY_PRIV) == 0) {
                    /* PSA API requires old-style ECC Data that starts with 0x4 prefix */
                    data[0] = 0x4;
                    memcpy(&data[1], ecc_key_pair_data, 2 * key_len);
                    key_len = key_len * 2 + 1;
                } else {
                    memcpy(data, &ecc_key_pair_data[2 * key_len], key_len);
                }
                *data_length = key_len;
            }
            break;
        default:
            return PSA_ERROR_NOT_SUPPORTED;
            break;
    }

    if (esec_status == ESEC_OKAY) {
        retval = PSA_SUCCESS;
    } else {
        *data_length = 0;
        if (esec_status == ESEC_INVALID_PARAMETER && !(slot->attributes.core.policy.usage & PSA_KEY_USAGE_EXPORT)) {
            retval = PSA_ERROR_NOT_PERMITTED;
        } else {
            retval = convert_esec_status_to_psa_status(esec_status);
        }
    }

    return retval;
}

static psa_status_t psa_export_public_key_asym(const psa_esec_key *slot, uint8_t *data,
    size_t data_size, size_t *data_length)
{
    uint32_t esec_status;
    uint32_t retval;

    if (slot->attributes.core.bits == 0)
        return PSA_ERROR_INVALID_HANDLE;

    if ((size_t)slot->attributes.core.bits / 8 > data_size)
        return PSA_ERROR_BUFFER_TOO_SMALL;

    *data_length = slot->attributes.core.bits / 8;
    switch (slot->attributes.core.type) {
        case PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1):
        case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1): {
                    /* PSA API requires old-style ECC Data that starts with 0x4 prefix */
                data[0] = 0x4;
                esec_status = esec_ecc_read_pub_key(slot->eseckey.ecckey, data+1);

                if (esec_status == ESEC_OKAY) {
                    uint32_t key_len = ESEC_GET_ECC_KEYLEN_FROM_KEYSPEC(slot->eseckey.ecckey.keyspec);
                    key_len = key_len * 2 + 1;
                   *data_length = key_len;
                }
            }
            break;
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
            break;
    }

    if (esec_status == ESEC_OKAY) {
        retval = PSA_SUCCESS;
    } else {
        *data_length = 0;
        if (esec_status == ESEC_INVALID_PARAMETER &&
            !(slot->attributes.core.policy.usage & PSA_KEY_USAGE_EXPORT)) {
            retval = PSA_ERROR_NOT_PERMITTED;
        } else {
            retval = convert_esec_status_to_psa_status(esec_status);
        }
    }

    return retval;
}

static psa_status_t psa_generate_asym_key(const psa_key_attributes_t *attributes, int32_t *key_index, esec_key *volatile_key)
{
    psa_status_t retval = PSA_ERROR_INVALID_ARGUMENT;
    uint32_t key_policy_usage = 0;
    bool is_persistent_key = attributes->core.lifetime == PSA_KEY_LIFETIME_PERSISTENT;
    uint32_t domainspec = 0;
    struct esec_key_storage storage;

    key_policy_usage = 0;
    if (attributes->core.policy.usage & PSA_KEY_USAGE_EXPORT)
        key_policy_usage |= ESEC_KEY_EXPORTABLE;

    if (attributes->core.policy.usage & PSA_KEY_USAGE_SIGN_MESSAGE ||
        attributes->core.policy.usage & PSA_KEY_USAGE_SIGN_HASH ||
        attributes->core.policy.usage & PSA_KEY_USAGE_VERIFY_MESSAGE ||
        attributes->core.policy.usage & PSA_KEY_USAGE_VERIFY_HASH) {
        domainspec |= ESEC_KEY_PERMS_SIGN;
    }

    switch (attributes->core.type) {
    case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1): {
            uint32_t key_len_in_bytes = attributes->core.bits / 8;
            switch (key_len_in_bytes) {
            case PSA_BITS_TO_BYTES(192):
                domainspec |= ESEC_KEY_ECC_P192;
                break;
            case PSA_BITS_TO_BYTES(224):
                domainspec |= ESEC_KEY_ECC_P224;
                break;
            case PSA_BITS_TO_BYTES(256):
                domainspec |= ESEC_KEY_ECC_P256;
                break;
            case PSA_BITS_TO_BYTES(384):
                domainspec |= ESEC_KEY_ECC_P384;
                break;
            case PSA_BITS_TO_BYTES(521):
                domainspec |= ESEC_KEY_ECC_P521;
                break;
            default:
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            retval = create_ecc_key(domainspec, key_policy_usage, is_persistent_key, key_index, storage, volatile_key);
        }
        break;
    default:
        retval = PSA_ERROR_NOT_SUPPORTED;
        break;
    }

    return retval;
}

static psa_status_t psa_sign_internal(const psa_esec_key *slot, psa_key_usage_t usage, psa_algorithm_t alg, const uint8_t *hash, size_t hash_length, uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    psa_status_t status;
    uint32_t esec_status;
    int is_input_message = (usage == PSA_KEY_USAGE_SIGN_MESSAGE || usage == PSA_KEY_USAGE_VERIFY_MESSAGE);

    /* Empty Slot */
    if (slot->attributes.core.bits == 0) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    status = psa_sign_verify_check_alg(is_input_message, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_check_key_policy(&slot->attributes, usage, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (!(alg & PSA_ALG_RSA_PKCS1V15_SIGN_BASE)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    *signature_length = signature_size;

    if (!is_input_message) {
        if (alg & PSA_ALG_RSA_PKCS1V15_SIGN_RAW) {
            if (((alg & PSA_ALG_HASH_MASK) != 0) && ((hash_length % 32) != 0)) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
        }
    }

    if (!PSA_KEY_TYPE_IS_KEY_PAIR(slot->attributes.core.type)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    if (slot->attributes.core.type == PSA_KEY_TYPE_RSA_KEY_PAIR) {
        uint32_t key_len = (slot->eseckey.rsakey.keyspec & 0xFF) * 4 + 4;
        if (signature_size < key_len) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }

        if (!is_input_message) {
            esec_status = esec_rsa_sign_digest(slot->eseckey.rsakey, hash, hash_length, signature);
        } else {
            esec_status = esec_rsa_sign(ESEC_RSA_PADDING_EMSA_PKCS, ESEC_HASH_ALGO_SHA256, slot->eseckey.rsakey, hash, hash_length, signature, 0);
        }
        status = convert_esec_status_to_psa_status(esec_status);

        *signature_length = slot->attributes.core.bits/8;
    } else if (PSA_KEY_TYPE_IS_ECC(slot->attributes.core.type)) {
        if (PSA_ALG_IS_ECDSA(alg)) {
            uint32_t key_len = (slot->eseckey.ecckey.keyspec & 0x7F) + 1;

            if (signature_size < (2 * key_len)) {
                return PSA_ERROR_BUFFER_TOO_SMALL;
            }
            if (!is_input_message) {
                esec_status = esec_ecdsa_sign_digest(slot->eseckey.ecckey, hash, hash_length, signature);
            } else {
                esec_status = esec_ecdsa_sign(ESEC_HASH_ALGO_SHA256, slot->eseckey.ecckey, hash, hash_length, signature);
            }
            status = convert_esec_status_to_psa_status(esec_status);

            *signature_length = key_len * 2;
        } else {
            status = PSA_ERROR_INVALID_ARGUMENT;
        }
    } else {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

exit:
    /* Fill the unused part of the output buffer (the whole buffer on error,
     * the trailing part on success) with something that isn't a valid mac
     * (barring an attack on the mac and deliberately-crafted input),
     * in case the caller doesn't check the return status properly. */
    if (status == PSA_SUCCESS) {
        memset(signature + *signature_length, '!', signature_size - *signature_length);
    } else {
        memset(signature, '!', signature_size);
    }

    /* If signature_size is 0 then we have nothing to do. We must not call
     * memset because signature may be NULL in this case. */
    return status;
}

static psa_status_t psa_verify_internal(const psa_esec_key *slot, psa_key_usage_t usage, psa_algorithm_t alg, const uint8_t *hash, size_t hash_length, const uint8_t *signature, size_t signature_length)
{
    uint32_t esec_status;
    psa_status_t status;
    int is_input_message = (usage == PSA_KEY_USAGE_SIGN_MESSAGE || usage == PSA_KEY_USAGE_VERIFY_MESSAGE);

    /* Empty Slot */
    if (slot->attributes.core.bits == 0) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    status = psa_sign_verify_check_alg(is_input_message, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_check_key_policy(&slot->attributes, usage, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (!(alg & PSA_ALG_RSA_PKCS1V15_SIGN_BASE)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!(slot->attributes.core.type & PSA_KEY_TYPE_CATEGORY_PUBLIC_KEY)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Immediately reject a zero-length signature buffer. This guarantees
     * that signature must be a valid pointer. (On the other hand, the hash
     * buffer can in principle be empty since it doesn't actually have
     * to be a hash.) */
    if (signature_length == 0) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    if (!is_input_message) {
        if (alg & PSA_ALG_RSA_PKCS1V15_SIGN_RAW) {
            if (((alg & PSA_ALG_HASH_MASK) != 0) && ((hash_length % 32) != 0)) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
        }
    }

    if (PSA_KEY_TYPE_IS_RSA(slot->attributes.core.type)) {
        uint32_t key_len = (slot->eseckey.rsakey.keyspec & 0xFF) * 4 + 4;
        if (signature_length != key_len) {
            return PSA_ERROR_INVALID_SIGNATURE;
        }

        if (!is_input_message) {
            esec_status = esec_rsa_verify_digest(slot->eseckey.rsakey, hash, hash_length, signature);
        } else {
            esec_status = esec_rsa_verify(ESEC_RSA_PADDING_EMSA_PKCS, ESEC_HASH_ALGO_SHA256, slot->eseckey.rsakey, hash, hash_length, signature, 0);
        }
        return convert_esec_status_to_psa_status(esec_status);
    } else if (PSA_KEY_TYPE_IS_ECC(slot->attributes.core.type)) {
        if (PSA_ALG_IS_ECDSA(alg)) {
            uint32_t key_len = (slot->eseckey.ecckey.keyspec & 0x7F) + 1;
            uint32_t signature_size = key_len * 2;

            /*
             * esec_ecdsa_verify() could get the signature length but there is no parameter
             * so let us compare expected and passed parameters. Or we could calculate the signature by esec_ecdsa_sign
             * and then we could compare here.
             */
            if (signature_length != signature_size) {
                return PSA_ERROR_INVALID_SIGNATURE;
            }

            if (!is_input_message) {
                esec_status = esec_ecdsa_verify_digest(slot->eseckey.ecckey, hash, hash_length, signature);
            } else {
                esec_status = esec_ecdsa_verify(ESEC_HASH_ALGO_SHA256, slot->eseckey.ecckey, hash, hash_length, signature);
            }
            return convert_esec_status_to_psa_status(esec_status);
        } else {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    } else {
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

static psa_status_t psa_key_derivation_output_key_internal(
    const psa_key_attributes_t* attributes,
    psa_key_derivation_operation_t* operation,
    const psa_esec_key* source_slot,
    psa_esec_key* target_slot)
{
    psa_status_t status;

    if (operation->alg == 0) {
        psa_key_derivation_abort(operation);
        return PSA_ERROR_BAD_STATE;
    }

    if (operation->ctx.hkdf.state == PSA_HKDF_STATE_KEYED &&
        !PSA_KEY_SLOT_OCCUPIED(source_slot->attributes.core.type)) {
        /* Do not abort the operation */
        return PSA_ERROR_INSUFFICIENT_DATA;
    }

    if (psa_get_key_bits(attributes) == 0) {
        psa_key_derivation_abort(operation);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = psa_validate_key_attributes(attributes);
    if (status != PSA_SUCCESS) {
        psa_key_derivation_abort(operation);
        return status;
    }

    if (status == PSA_SUCCESS) {
        uint8_t* data = NULL;
        psa_key_bits_t bits = attributes->core.bits;
        size_t bytes = PSA_BITS_TO_BYTES(attributes->core.bits);
        uint32_t esec_status;
        struct esec_key_storage storage = { 0 };
        struct esec_skey okm = { 0 };
        esec_key source_key;
        psa_hkdf_key_derivation_t* hkdf = &operation->ctx.hkdf;
        uint8_t zerolen_buffer[1];
        struct esec_skey zerolen_key = { .keyspec = 0, .storage = ESEC_STORAGE_HOST(zerolen_buffer) };
        bool is_persistent_key = attributes->core.lifetime == PSA_KEY_LIFETIME_PERSISTENT;
        bool persistent_key_allocated = false;
        int32_t key_retry_count = 5;
        int32_t key_index = -1;

        if (operation->capacity < bytes) {
            operation->capacity = 0;
            return PSA_ERROR_INSUFFICIENT_DATA;
        }

        if (PSA_KEY_SLOT_OCCUPIED(source_slot->attributes.core.type) &&
            !PSA_KEY_TYPE_IS_UNSTRUCTURED(source_slot->attributes.core.type)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        if (attributes->core.bits % 8 != 0) {
            psa_key_derivation_abort(operation);
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        switch (attributes->core.type) {
        case PSA_KEY_TYPE_RAW_DATA:
        case PSA_KEY_TYPE_HMAC:
        case PSA_KEY_TYPE_DERIVE:
            break;
        case PSA_KEY_TYPE_AES:
            if (bits != 128 && bits != 192 && bits != 256) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        case PSA_KEY_TYPE_DES:
            if (bits != 64 && bits != 128 && bits != 192){
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        if (hkdf->state == PSA_HKDF_STATE_KEYED) {
            source_key = source_slot->eseckey;
        } else {
            source_key.skey = zerolen_key;
        }

        status = derive_hkdf_skey(source_key.skey, is_persistent_key, &key_index,
                                  attributes->core.bits / 8, hkdf, storage, &okm);

        status = convert_esec_status_to_psa_status(status);
        target_slot->attributes = *attributes;
        target_slot->eseckey.skey = okm;
        operation->capacity -= bytes;
    }

    return status;
}

static psa_status_t psa_key_agreement_raw_internal(psa_algorithm_t alg, psa_esec_key* private_key, const uint8_t* peer_key, size_t peer_key_length, uint8_t* shared_secret, size_t shared_secret_size, size_t* shared_secret_length)
{
    esec_key eseckey;
    psa_status_t status;

    switch (alg) {
    case PSA_ALG_ECDH: {
        size_t private_key_len = (size_t)private_key->attributes.core.bits / 8;
        size_t public_key_len = private_key_len * 2 + 1;
        if (!PSA_KEY_TYPE_IS_ECC_KEY_PAIR(private_key->attributes.core.type)){
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        if (public_key_len != peer_key_length) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        if (private_key_len > shared_secret_size) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }

        uint32_t esec_status = esec_genkey_ecdh(private_key->eseckey.ecckey, peer_key + 1,  (struct esec_key_storage)ESEC_STORAGE_HOST(shared_secret), ESEC_KEY_EXPORTABLE, &eseckey.skey);

        *shared_secret_length = private_key_len;
        status = convert_esec_status_to_psa_status(esec_status);
        }
        break;
    default:
        status = (PSA_ERROR_NOT_SUPPORTED);
        break;
    }

    return status;
}

static int psa_key_derivation_check_input_type(psa_key_derivation_step_t step, psa_key_type_t key_type)
{
    switch (step) {
    case PSA_KEY_DERIVATION_INPUT_SECRET:
        if (key_type == PSA_KEY_TYPE_NONE || key_type == PSA_KEY_TYPE_DERIVE) {
            return PSA_SUCCESS;
        }
        break;
    case PSA_KEY_DERIVATION_INPUT_LABEL:
    case PSA_KEY_DERIVATION_INPUT_SALT:
    case PSA_KEY_DERIVATION_INPUT_INFO:
    case PSA_KEY_DERIVATION_INPUT_SEED:
        if (key_type == PSA_KEY_TYPE_NONE || key_type == PSA_KEY_TYPE_RAW_DATA) {
            return PSA_SUCCESS;
        }
        break;
    }
    return PSA_ERROR_INVALID_ARGUMENT;
}

static psa_algorithm_t psa_key_derivation_get_kdf_alg(const psa_key_derivation_operation_t* operation)
{
    if (PSA_ALG_IS_KEY_AGREEMENT(operation->alg)) {
        return PSA_ALG_KEY_AGREEMENT_GET_KDF(operation->alg);
    } else {
        return operation->alg;
    }
}

static psa_status_t psa_hkdf_input(psa_hkdf_key_derivation_t* hkdf, psa_algorithm_t hash_alg, psa_key_derivation_step_t step, const uint8_t* data, size_t data_length)
{
    switch (step) {
    case PSA_KEY_DERIVATION_INPUT_SALT: {
        if (hkdf->state != PSA_HKDF_STATE_INIT) {
            return PSA_ERROR_BAD_STATE;
        }

        hkdf->salt = (uint8_t*)psa_plat_mem_alloc(data_length);
        if (hkdf->salt == NULL) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }

        hkdf->salt_length = data_length;

        hkdf->state = PSA_HKDF_STATE_STARTED;
        hkdf->salt_set = true;
        return PSA_SUCCESS;
    }
    case PSA_KEY_DERIVATION_INPUT_SECRET: {
        /* If no salt was provided, use an empty salt. */
        if (hkdf->state == PSA_HKDF_STATE_INIT) {
            hkdf->state = PSA_HKDF_STATE_STARTED;
        }
        if (hkdf->state != PSA_HKDF_STATE_STARTED) {
            return PSA_ERROR_BAD_STATE;
        }

        hkdf->offset_in_block = PSA_HASH_LENGTH(hash_alg);
        hkdf->block_number = 0;
        hkdf->state = PSA_HKDF_STATE_KEYED;
        return PSA_SUCCESS;
    }
    case PSA_KEY_DERIVATION_INPUT_INFO: {
        if (hkdf->state == PSA_HKDF_STATE_OUTPUT) {
            return PSA_ERROR_BAD_STATE;
        }
        if (hkdf->info_set) {
            return PSA_ERROR_BAD_STATE;
        }
        if (data_length != 0) {
            hkdf->info = (uint8_t*)psa_plat_mem_alloc(data_length);
            if (hkdf->info == NULL) {
                return PSA_ERROR_INSUFFICIENT_MEMORY;
            }
            hkdf->info_length = data_length;
        }
        hkdf->info_set = 1;
        return PSA_SUCCESS;
    }
    default:
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

static psa_status_t psa_key_derivation_input_internal(psa_key_derivation_operation_t* operation, psa_key_derivation_step_t step, psa_key_type_t key_type, const uint8_t* data, size_t data_length)
{
    psa_status_t status;
    psa_algorithm_t kdf_alg = psa_key_derivation_get_kdf_alg(operation);

    status = psa_key_derivation_check_input_type(step, key_type);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    if (PSA_ALG_IS_HKDF(kdf_alg)) {
        /* If PSA_KEY_DERIVATION_INPUT_SALT is provided, it must be before PSA_KEY_DERIVATION_INPUT_SECRET. */
        if (step == PSA_KEY_DERIVATION_INPUT_SALT && operation->ctx.hkdf.state == PSA_HKDF_STATE_KEYED) {
            return PSA_ERROR_BAD_STATE;
        }

        status = psa_hkdf_input(&operation->ctx.hkdf, PSA_ALG_HKDF_GET_HASH(kdf_alg), step, data, data_length);
    } else {
        /* This can't happen unless the operation object was not initialized */
        return PSA_ERROR_BAD_STATE;
    }

exit:
    if (status != PSA_SUCCESS) {
        psa_key_derivation_abort(operation);
    }

    return status;
}

static psa_status_t psa_key_agreement_internal(psa_key_derivation_operation_t* operation, psa_key_derivation_step_t step, psa_esec_key* private_key, const uint8_t* peer_key, size_t peer_key_length)
{
    psa_status_t status;
    uint8_t shared_secret[PSA_KEY_AGREEMENT_MAX_SHARED_SECRET_SIZE];
    size_t shared_secret_length = 0;
    psa_algorithm_t ka_alg = PSA_ALG_KEY_AGREEMENT_GET_BASE(operation->alg);

    /* Step 1: run the secret agreement algorithm to generate the shared
     * secret. */
    status = psa_key_agreement_raw_internal(ka_alg, private_key, peer_key, peer_key_length, shared_secret, sizeof(shared_secret), &shared_secret_length);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    /* Step 2: set up the key derivation to generate key material from
     * the shared secret. A shared secret is permitted wherever a key
     * of type DERIVE is permitted. */
    status = psa_key_derivation_input_internal(operation, step, PSA_KEY_TYPE_DERIVE, shared_secret, shared_secret_length);

exit:
    memset(shared_secret, 0, sizeof(shared_secret));
    return status;
}

static psa_status_t psa_key_derivation_key_agreement_internal(psa_key_derivation_operation_t* operation, psa_key_derivation_step_t step, psa_esec_key* slot, const uint8_t* peer_key, size_t peer_key_length)
{
    psa_status_t status;

    if (slot->attributes.core.bits == 0) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    status = psa_check_key_policy(&slot->attributes, PSA_KEY_USAGE_DERIVE, 0);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_key_agreement_internal(operation, step, slot, peer_key, peer_key_length);
    if (status != PSA_SUCCESS) {
        psa_key_derivation_abort(operation);
    }

    return status;
}

static psa_status_t psa_key_derivation_input_key_internal(psa_key_derivation_operation_t* operation, psa_key_derivation_step_t step, const psa_esec_key* slot)
{
    psa_status_t status;

    if (!PSA_KEY_SLOT_OCCUPIED(slot->attributes.core.type)) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    status = psa_check_key_policy(&slot->attributes, PSA_KEY_USAGE_DERIVE, operation->alg);
    if (status != PSA_SUCCESS) {
        psa_key_derivation_abort(operation);
        return status;
    }

    /* Passing a key object as a SECRET input unlocks the permission
     * to output to a key object. */
    if (step == PSA_KEY_DERIVATION_INPUT_SECRET) {
        operation->can_output_key = 1;
    }

    status = psa_key_derivation_check_input_type(step, slot->attributes.core.type);
    if (status != PSA_SUCCESS) {
        psa_key_derivation_abort(operation);
        return status;
    }

    return psa_key_derivation_input_internal(operation, step, slot->attributes.core.type, NULL, 0);
}

static psa_status_t psa_key_derivation_start_hmac(psa_mac_operation_t *operation, psa_algorithm_t hash_alg,
            psa_key_id_t mac_key)
{
    psa_status_t status;

    operation->is_sign = 1;
    operation->mac_size = PSA_HASH_LENGTH(hash_alg);

    return psa_mac_sign_setup(operation, mac_key, PSA_ALG_HMAC(hash_alg));
}

static psa_status_t psa_key_derivation_hkdf_read(psa_hkdf_key_derivation_t* hkdf, psa_algorithm_t hash_alg, uint8_t* output, size_t output_length)
{
    uint8_t hash_length = PSA_HASH_LENGTH(hash_alg);
    size_t hmac_output_length;
    psa_status_t status;

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t mac_key;

    if (hkdf->state < PSA_HKDF_STATE_KEYED || ! hkdf->info_set) {
        return PSA_ERROR_BAD_STATE ;
    }
    hkdf->state = PSA_HKDF_STATE_OUTPUT;

    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attributes, PSA_BYTES_TO_BITS(hash_length));
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(hash_alg));

    status = psa_import_key(&attributes, hkdf->prk, hash_length, &mac_key);
    if (status != PSA_SUCCESS) {
        return status;
    }

    while (output_length != 0) {
        /* Copy what remains of the current block */
        uint8_t n = hash_length - hkdf->offset_in_block;
        if (n > output_length) {
            n = (uint8_t) output_length;
        }
        memcpy(output, hkdf->output_block + hkdf->offset_in_block, n );
        output += n;
        output_length -= n;
        hkdf->offset_in_block += n;
        if (output_length == 0) {
            status = PSA_SUCCESS;
            goto exit;
        }

        /* We can't be wanting more output after block 0xff, otherwise
         * the capacity check in psa_key_derivation_output_bytes() would have
         * prevented this call. It could happen only if the operation
         * object was corrupted or if this function is called directly
         * inside the library. */
        if (hkdf->block_number == 0xff) {
            status = PSA_ERROR_BAD_STATE;
            goto exit;
        }

        /* We need a new block */
        ++hkdf->block_number;
        hkdf->offset_in_block = 0;

        status = psa_key_derivation_start_hmac(&hkdf->hmac, hash_alg, mac_key);
        if (status != PSA_SUCCESS) {
            goto exit;
        }

        if (hkdf->block_number != 1) {
            status = psa_mac_update(&hkdf->hmac, hkdf->output_block, hash_length);
            if (status != PSA_SUCCESS) {
                goto exit;
            }
        }

        status = psa_mac_update(&hkdf->hmac, hkdf->info, hkdf->info_length);
        if (status != PSA_SUCCESS) {
            goto exit;
        }

        status = psa_mac_update(&hkdf->hmac, &hkdf->block_number, 1);
        if (status != PSA_SUCCESS) {
            goto exit;
        }

        status = psa_mac_sign_finish(&hkdf->hmac, hkdf->output_block, sizeof(hkdf->output_block), &hmac_output_length);
        if (status != PSA_SUCCESS) {
            goto exit;
        }
    }

exit:
    psa_destroy_key(mac_key);
    psa_reset_key_attributes(&attributes);
    return status;
}

static psa_status_t psa_key_derivation_setup_kdf(psa_key_derivation_operation_t* operation, psa_algorithm_t kdf_alg)
{
    /* Make sure that operation->ctx is properly zero-initialised. (Macro
     * initialisers for this union leave some bytes unspecified.) */
    memset(&operation->ctx, 0, sizeof(operation->ctx));

    /* Make sure that kdf_alg is a supported key derivation algorithm. */
    if (PSA_ALG_IS_HKDF(kdf_alg)) {
        psa_algorithm_t hash_alg = PSA_ALG_HKDF_GET_HASH(kdf_alg);
        size_t hash_size = PSA_HASH_LENGTH(hash_alg);
        if (hash_size == 0) {
            return PSA_ERROR_NOT_SUPPORTED;
        }

        operation->capacity = 255 * hash_size;
        return PSA_SUCCESS;
    } else {
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

static psa_status_t psa_raw_key_agreement_internal(psa_algorithm_t alg, psa_esec_key* slot, const uint8_t* peer_key, size_t peer_key_length, uint8_t* output, size_t output_size, size_t* output_length)
{
    psa_status_t status;

    uint8_t shared_secret[PSA_KEY_AGREEMENT_MAX_SHARED_SECRET_SIZE];

    if (slot->attributes.core.bits == 0) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    status = psa_check_key_policy(&slot->attributes, PSA_KEY_USAGE_DERIVE, 0);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_key_agreement_raw_internal(alg, slot, peer_key, peer_key_length, shared_secret, output_size, output_length);

    if (status == PSA_SUCCESS) {
        memcpy(output, shared_secret, *output_length);
    }

    return status;
}

/**
 * Checks whether the cipher the arguments (algorithm and key type) are valid
 */
bool psa_check_cipher_arguments(psa_algorithm_t alg, psa_key_type_t key_type)
{
    if (PSA_ALG_IS_AEAD(alg)) {
        alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(alg, 0);
    }

    if (PSA_ALG_IS_CIPHER(alg) || PSA_ALG_IS_AEAD(alg)) {
        switch (alg) {
        case PSA_ALG_CTR:
        case PSA_ALG_CFB:
        case PSA_ALG_OFB:
        case PSA_ALG_CBC_NO_PADDING:
        case PSA_ALG_CBC_PKCS7:
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 0):
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, 0):
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CHACHA20_POLY1305, 0):
            break;
        default:
            return false;
        }
    } else if (alg == PSA_ALG_CMAC) {
    } else {
        return false;
    }

    switch (key_type) {
    case PSA_KEY_TYPE_AES:
    case PSA_KEY_TYPE_DES:
    case PSA_KEY_TYPE_CAMELLIA:
    case PSA_KEY_TYPE_CHACHA20:
        break;
    default:
        return false;
    }

    return true;
}

void psa_reset_key_attributes( psa_key_attributes_t *attributes )
{
    psa_plat_mem_free(attributes->domain_parameters);
    memset(attributes, 0, sizeof(*attributes));
}

psa_status_t psa_set_key_domain_parameters( psa_key_attributes_t *attributes,
                                            psa_key_type_t type,
                                            const uint8_t *data,
                                            size_t data_length )
{
    uint8_t *copy = NULL;

    if(data_length != 0) {
        copy = psa_plat_mem_alloc(data_length);
        if(copy == NULL) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        memcpy(copy, data, data_length);
    }
    /* After this point, this function is guaranteed to succeed, so it
     * can start modifying `*attributes`. */

    if (attributes->domain_parameters != NULL) {
        psa_plat_mem_free(attributes->domain_parameters);
        attributes->domain_parameters = NULL;
        attributes->domain_parameters_size = 0;
    }

    attributes->domain_parameters = copy;
    attributes->domain_parameters_size = data_length;
    attributes->core.type = type;
    return( PSA_SUCCESS );
}

psa_status_t psa_get_key_domain_parameters(
    const psa_key_attributes_t *attributes,
    uint8_t *data, size_t data_size, size_t *data_length )
{
    if (attributes->domain_parameters_size > data_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    *data_length = attributes->domain_parameters_size;

    if (attributes->domain_parameters_size != 0) {
        memcpy(data, attributes->domain_parameters,
                attributes->domain_parameters_size);
    }

    return (PSA_SUCCESS);
}

static int psa_key_algorithm_permits(psa_algorithm_t policy_alg, psa_algorithm_t requested_alg)
{
    /* Common case: the policy only allows requested_alg. */
    if (requested_alg == policy_alg) {
        return 1;
    }

    /* If policy_alg is a hash-and-sign with a wildcard for the hash,
     * and requested_alg is the same hash-and-sign family with any hash,
     * then requested_alg is compliant with policy_alg. */
    if (PSA_ALG_IS_HASH_AND_SIGN(requested_alg) && PSA_ALG_SIGN_GET_HASH(policy_alg) == PSA_ALG_ANY_HASH) {
        return ((policy_alg & ~PSA_ALG_HASH_MASK) == (requested_alg & ~PSA_ALG_HASH_MASK));
    }

    /* If it isn't permitted, it's forbidden. */
    return 0;
}

static int psa_key_policy_permits(const psa_key_policy_t* policy, psa_algorithm_t alg)
{
    return psa_key_algorithm_permits(policy->alg, alg) || psa_key_algorithm_permits(policy->alg2, alg);
}

psa_status_t psa_check_key_policy(const psa_key_attributes_t* attr, psa_key_usage_t usage, psa_algorithm_t alg)
{
    /* Enforce that usage policy for the key slot contains all the flags
     * required by the usage parameter. There is one exception: public
     * keys can always be exported, so we treat public key objects as
     * if they had the export flag. */
    if (PSA_KEY_TYPE_IS_PUBLIC_KEY(attr->core.type)) {
        usage &= ~PSA_KEY_USAGE_EXPORT;
    }

    if ((attr->core.policy.usage & usage) != usage) {
        return PSA_ERROR_NOT_PERMITTED;
    }

    /* Enforce that the usage policy permits the requested algortihm. */
    if (alg != 0 && !psa_key_policy_permits(&attr->core.policy, alg)) {
        return PSA_ERROR_NOT_PERMITTED;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_crypto_init(void)
{
    if (!psa_settings.flags.initialised) {
        psa_settings.flags.initialised = 1;

        psa_keys[0].attributes.core.type = PSA_KEY_SLOT_INVALID;

        /* Initialise the platform here when needed */
        platform_init();
    }

    return PSA_SUCCESS;
}

psa_status_t psa_get_key_attributes(psa_key_id_t key,
                                    psa_key_attributes_t *attributes)
{
    CHECK_INIT();

    memset(attributes, 0, sizeof(psa_key_attributes_t));

    if (key >= NUMBER_OF_KEY_SLOTS) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    if (psa_keys[key].attributes.core.bits == 0) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    *attributes = psa_keys[key].attributes;

    return PSA_SUCCESS;
}

psa_status_t psa_copy_key(psa_key_id_t source_key, const psa_key_attributes_t *attributes, psa_key_id_t *target_key)
{
    psa_status_t status;
    psa_esec_key *target_slot = NULL;
    psa_key_attributes_t actual_attributes = *attributes;
    esec_key volatile_key;
    struct esec_key_storage storage;
    bool is_persistent_key = attributes->core.lifetime == PSA_KEY_LIFETIME_PERSISTENT;
    int32_t key_index = -1;
    int target_slot_index;
    psa_esec_key *slot;
    uint32_t esec_status = 0;
    uint32_t key_len = attributes->core.bits / 8;

    CHECK_INIT();
    if (source_key > NUMBER_OF_KEY_SLOTS) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    slot = &psa_keys[source_key];

    if (slot->attributes.core.lifetime == PSA_KEY_LIFETIME_VOLATILE &&
        attributes->core.lifetime == PSA_KEY_LIFETIME_PERSISTENT) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (slot->attributes.core.type == 0) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    status = psa_check_key_policy(&slot->attributes, PSA_KEY_USAGE_COPY, 0);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status = psa_validate_optional_attributes(slot, attributes);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status = psa_restrict_key_policy(&actual_attributes.core.policy, &slot->attributes.core.policy);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    target_slot_index = psa_get_empty_slot();
    if (target_slot_index < 0) {
        status = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto exit;
    }

    target_slot = &psa_keys[target_slot_index];

    switch (attributes->core.type) {
        case PSA_KEY_TYPE_RAW_DATA:
        case PSA_KEY_TYPE_HMAC:
        case PSA_KEY_TYPE_DERIVE:
        case PSA_KEY_TYPE_AES:
        case PSA_KEY_TYPE_DES:
            status = transfer_skey(slot->eseckey.skey, is_persistent_key, key_len, &key_index, storage, &volatile_key);
            break;
        case PSA_KEY_TYPE_RSA_PUBLIC_KEY:
        case PSA_KEY_TYPE_RSA_KEY_PAIR: {
            uint32_t data_len = attributes->core.type == PSA_KEY_TYPE_RSA_PUBLIC_KEY ?  2 * key_len : 2 * key_len + 5 * key_len / 2;
            status = transfer_rsa_key(slot->eseckey.rsakey, is_persistent_key, data_len, &key_index, storage, &volatile_key);
            break;
        }
        case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1):
        case PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1):
            status = transfer_ecc_key(slot->eseckey.ecckey, is_persistent_key, key_len * 3, &key_index, storage, &volatile_key);
            break;
        default:
            status = PSA_ERROR_NOT_SUPPORTED;
            break;
    }

    if (PSA_SUCCESS == status) {
        status = psa_set_key_slot(target_slot_index, &actual_attributes, &volatile_key, slot->attributes.core.bits);

        *target_key = target_slot_index;
    }

exit:
    if (status != PSA_SUCCESS) {
        if (target_slot != NULL) {
            memset(target_slot, 0, sizeof(psa_esec_key));
        }
        *target_key = 0;
    }

    return status;
}

psa_status_t psa_destroy_key(psa_key_id_t key)
{
    uint32_t esec_status;

    CHECK_INIT();

    if (key >= NUMBER_OF_KEY_SLOTS) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    psa_esec_key* slot = &psa_keys[key];

    /* Empty Slot */
    if (!PSA_KEY_SLOT_OCCUPIED(slot->attributes.core.type)) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    switch (slot->attributes.core.type) {
    case PSA_KEY_TYPE_RAW_DATA:
    case PSA_KEY_TYPE_HMAC:
    case PSA_KEY_TYPE_DERIVE:
    case PSA_KEY_TYPE_AES:
    case PSA_KEY_TYPE_DES:
        esec_status = esec_delete_skey(slot->eseckey.skey);
        if (slot->attributes.core.lifetime == PSA_KEY_LIFETIME_PERSISTENT) {
            esec_status = ESEC_OKAY;
        }
        break;
    case PSA_KEY_TYPE_RSA_PUBLIC_KEY:
    case PSA_KEY_TYPE_RSA_KEY_PAIR:
        esec_status = esec_rsa_delete_key(slot->eseckey.rsakey);
        if (slot->attributes.core.lifetime == PSA_KEY_LIFETIME_PERSISTENT) {
            esec_status = ESEC_OKAY;
        }
        break;
    case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1):
    case PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1):
        esec_status = esec_ecc_delete_key(slot->eseckey.ecckey);
        if (slot->attributes.core.lifetime == PSA_KEY_LIFETIME_PERSISTENT) {
            esec_status = ESEC_OKAY;
        }
        break;
    default:
        return PSA_ERROR_NOT_SUPPORTED;
        break;
    }

    (void)psa_plat_crypto_delete_key(slot);

    memset(slot, 0, sizeof(psa_esec_key));


    return convert_esec_status_to_psa_status(esec_status);
}

psa_status_t psa_import_key(const psa_key_attributes_t *attributes,
                            const uint8_t *data,
                            size_t data_length,
                            psa_key_id_t *key)
{
    psa_status_t retval = PSA_ERROR_INVALID_ARGUMENT;
    uint32_t key_policy_usage = 0;
    esec_key volatile_key;
    int32_t key_index = -1;
    bool is_persistent_key = attributes->core.lifetime == PSA_KEY_LIFETIME_PERSISTENT;
    struct esec_key_storage storage;
    uint16_t key_len_in_bits = (uint16_t)(data_length * 8);

    *key = 0;

    CHECK_INIT();

    if (attributes->core.policy.usage & PSA_KEY_USAGE_ENCRYPT ||
        attributes->core.policy.usage & PSA_KEY_USAGE_DECRYPT ||
        attributes->core.policy.usage & PSA_KEY_USAGE_COPY) {
    }

    key_policy_usage = 0;

    if (attributes->core.policy.usage & PSA_KEY_USAGE_EXPORT)
         key_policy_usage |= ESEC_KEY_EXPORTABLE;

    switch (attributes->core.type) {
        case PSA_KEY_TYPE_RAW_DATA:
        case PSA_KEY_TYPE_HMAC:
        case PSA_KEY_TYPE_DERIVE:
        case PSA_KEY_TYPE_AES:
        case PSA_KEY_TYPE_DES: {
            if (!PSA_IS_VALID_DES_DATA_LEN(data_length) ||
                !PSA_IS_VALID_DES_KEY_SIZE_IN_BITS(attributes->core.bits)) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            size_t bit_size = PSA_BYTES_TO_BITS(data_length);
            /* Ensure that the bytes-to-bit conversion didn't overflow. */
            if (data_length > SIZE_MAX / 8) {
                return PSA_ERROR_NOT_SUPPORTED;
            }

            /* Enforce a size limit, and in particular ensure that the bit
                * size fits in its representation type. */
            if (bit_size > PSA_MAX_KEY_BITS) {
                return PSA_ERROR_NOT_SUPPORTED;
            }

            retval = import_skey(key_policy_usage, is_persistent_key, &key_index, data, data_length, storage, &volatile_key);
            break;
        }
        case PSA_KEY_TYPE_RSA_PUBLIC_KEY:
        case PSA_KEY_TYPE_RSA_KEY_PAIR:
        case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1):
        case PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1):
            retval = psa_import_key_asym(attributes, data, data_length, &key_index, &volatile_key, &key_len_in_bits);
            break;
        default:
            return PSA_ERROR_NOT_SUPPORTED;
            break;
    }

    if (PSA_SUCCESS == retval) {
        retval = psa_set_key_slot((psa_key_id_t)key_index, attributes, &volatile_key, key_len_in_bits);

        *key = (psa_key_id_t)key_index;

    }

    return retval;
}


psa_status_t psa_export_key(psa_key_id_t key,
                            uint8_t *data,
                            size_t data_size,
                            size_t *data_length)
{
    uint32_t retval;
    CHECK_INIT();

    if (key >= NUMBER_OF_KEY_SLOTS) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    const psa_esec_key* slot = &psa_keys[key];

    if (slot->attributes.core.bits == 0) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    if ((size_t)slot->attributes.core.bits / 8 > data_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (!(slot->attributes.core.policy.usage & PSA_KEY_USAGE_EXPORT)) {
        return PSA_ERROR_NOT_PERMITTED;
    }

    uint32_t esec_status;

    *data_length = slot->attributes.core.bits / 8;
    switch (slot->attributes.core.type) {
        case PSA_KEY_TYPE_AES:
        case PSA_KEY_TYPE_DES: {
            esec_status = esec_export_skey(slot->eseckey.skey, data);
            if (esec_status == ESEC_OKAY) {
                retval = PSA_SUCCESS;
            } else {
                *data_length = 0;
                if (esec_status == ESEC_INVALID_PARAMETER && !(slot->attributes.core.policy.usage & PSA_KEY_USAGE_EXPORT)) {
                    retval = PSA_ERROR_NOT_PERMITTED;
                } else {
                    retval = convert_esec_status_to_psa_status(esec_status);
                }
            }
        }
        break;
        case PSA_KEY_TYPE_RSA_KEY_PAIR:
        case PSA_KEY_TYPE_RSA_PUBLIC_KEY:
        case PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1):
        case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1):
            retval = psa_export_key_asym(slot, data, data_size, data_length);
            break;
        default:
            return PSA_ERROR_NOT_SUPPORTED;
            break;
    }
    return retval;
}

psa_status_t psa_export_public_key(psa_key_id_t key,
                                   uint8_t *data,
                                   size_t data_size,
                                   size_t *data_length)
{
    CHECK_INIT();

    if (key >= NUMBER_OF_KEY_SLOTS) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    const psa_esec_key* slot = &psa_keys[key];

    return psa_export_public_key_asym(slot, data, data_size, data_length);

}

/**@}*/

/** \defgroup asymmetric Asymmetric cryptography
 * @{
 */

psa_status_t psa_sign_message(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *input, size_t input_length,
                               uint8_t *signature, size_t signature_size, size_t *signature_length )
{
    if (key >= NUMBER_OF_KEY_SLOTS) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    return psa_sign_internal(&psa_keys[key], PSA_KEY_USAGE_SIGN_MESSAGE, alg, input, input_length, signature, signature_size, signature_length);
}


psa_status_t psa_verify_message(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *input, size_t input_length,
                                 const uint8_t *signature, size_t signature_length )
{
    if (key >= NUMBER_OF_KEY_SLOTS) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    return psa_verify_internal(&psa_keys[key], PSA_KEY_USAGE_VERIFY_MESSAGE, alg, input, input_length, signature, signature_length);
}

psa_status_t psa_sign_hash(psa_key_id_t key, psa_algorithm_t alg,
                           const uint8_t *hash, size_t hash_length,
                           uint8_t *signature, size_t signature_size,
                           size_t *signature_length)
{
    CHECK_INIT();

    if (key >= NUMBER_OF_KEY_SLOTS) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    return psa_sign_internal(&psa_keys[key], PSA_KEY_USAGE_SIGN_HASH, alg, hash, hash_length, signature, signature_size, signature_length);
}

psa_status_t psa_verify_hash(psa_key_id_t key, psa_algorithm_t alg,
                             const uint8_t *hash, size_t hash_length,
                             const uint8_t *signature, size_t signature_length)
{
    CHECK_INIT();

    if (key >= NUMBER_OF_KEY_SLOTS) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    return psa_verify_internal(&psa_keys[key], PSA_KEY_USAGE_VERIFY_HASH, alg, hash, hash_length, signature, signature_length);
}

/**@}*/

/** \defgroup key_derivation Key derivation and pseudorandom generation
 * @{
 */

psa_status_t psa_key_derivation_setup(
    psa_key_derivation_operation_t *operation,
    psa_algorithm_t alg)
{
    psa_status_t status;

    if (operation->alg != 0) {
        return PSA_ERROR_BAD_STATE;
    }

    if (PSA_ALG_IS_RAW_KEY_AGREEMENT(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    } else if (PSA_ALG_IS_KEY_AGREEMENT(alg)) {
        psa_algorithm_t kdf_alg = PSA_ALG_KEY_AGREEMENT_GET_KDF(alg);
        status = psa_key_derivation_setup_kdf(operation, kdf_alg);
    } else if (PSA_ALG_IS_KEY_DERIVATION(alg)) {
        status = psa_key_derivation_setup_kdf(operation, alg);
    } else
        return PSA_ERROR_INVALID_ARGUMENT;

    if (status == PSA_SUCCESS) {
        operation->alg = alg;
    }

    return status;
}


psa_status_t psa_key_derivation_get_capacity(
    const psa_key_derivation_operation_t *operation,
    size_t *capacity)
{
    if (operation->alg == 0) {
        /* This is a blank key derivation operation. */
        return PSA_ERROR_BAD_STATE;
    }

    *capacity = operation->capacity;
    return PSA_SUCCESS;
}


psa_status_t psa_key_derivation_set_capacity(
    psa_key_derivation_operation_t *operation,
    size_t capacity)
{
    if (operation->alg == 0) {
        return PSA_ERROR_BAD_STATE;
    }
    if (capacity > operation->capacity) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    operation->capacity = capacity;
    return PSA_SUCCESS;
}


psa_status_t psa_key_derivation_input_bytes(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    const uint8_t *data,
    size_t data_length)
{
    return psa_key_derivation_input_internal(operation, step, PSA_KEY_TYPE_NONE, data, data_length);
}


psa_status_t psa_key_derivation_input_integer(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    uint64_t value)
{
    return PSA_ERROR_NOT_SUPPORTED;
}


psa_status_t psa_key_derivation_input_key(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    psa_key_id_t key)
{
    CHECK_INIT();

   if (key >= NUMBER_OF_KEY_SLOTS) {
        return PSA_ERROR_INVALID_HANDLE;
   }

    operation->source_key_handle = key;

    return psa_key_derivation_input_key_internal(operation, step, &psa_keys[key]);
}


psa_status_t psa_key_derivation_key_agreement(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    psa_key_id_t private_key,
    const uint8_t *peer_key,
    size_t peer_key_length)
{
    if (!PSA_ALG_IS_KEY_AGREEMENT(operation->alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (private_key > NUMBER_OF_KEY_SLOTS) {
        return PSA_ERROR_INVALID_HANDLE;
    }

    return psa_key_derivation_key_agreement_internal(operation, step, &psa_keys[private_key], peer_key, peer_key_length);
}


psa_status_t psa_key_derivation_output_bytes(
    psa_key_derivation_operation_t *operation,
    uint8_t *output,
    size_t output_length)
{
    psa_status_t status;
    psa_algorithm_t kdf_alg = psa_key_derivation_get_kdf_alg(operation);

    if (operation->alg == 0) {
        /* This is a blank operation. */
        return PSA_ERROR_BAD_STATE;
    }

    if (!operation->ctx.hkdf.info_set) {
        return PSA_ERROR_BAD_STATE;
    }

    if (output_length > operation->capacity) {
        operation->capacity = 0;
        /* Go through the error path to wipe all confidential data now
         * that the operation object is useless. */
        status = PSA_ERROR_INSUFFICIENT_DATA;
        goto exit;
    }

    if (output_length == 0 && operation->capacity == 0) {
        /* Edge case: this is a finished operation, and 0 bytes
         * were requested. The right error in this case could
         * be either INSUFFICIENT_CAPACITY or BAD_STATE. Return
         * INSUFFICIENT_CAPACITY, which is right for a finished
         * operation, for consistency with the case when
         * output_length > 0. */
        return PSA_ERROR_INSUFFICIENT_DATA;
    }
    operation->capacity -= output_length;

    if (PSA_ALG_IS_HKDF(kdf_alg)) {
        psa_algorithm_t hash_alg = PSA_ALG_HKDF_GET_HASH(kdf_alg);
        status = psa_key_derivation_hkdf_read(&operation->ctx.hkdf, hash_alg, output, output_length);
    } else {
        return PSA_ERROR_BAD_STATE;
    }

exit:
    if (status != PSA_SUCCESS) {
        /* Preserve the algorithm upon errors, but clear all sensitive state.
         * This allows us to differentiate between exhausted operations and
         * blank operations, so we can return PSA_ERROR_BAD_STATE on blank
         * operations. */
        psa_algorithm_t alg = operation->alg;
        psa_key_derivation_abort(operation);
        operation->alg = alg;
        memset(output, '!', output_length);
    }
    return status;
}

psa_status_t psa_key_derivation_output_key(
    const psa_key_attributes_t *attributes,
    psa_key_derivation_operation_t *operation,
    psa_key_id_t *key)
{
    int32_t target_slot_index = psa_get_empty_slot();

    if (target_slot_index < 0) {
        /* Do not abort the operation */
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    const psa_esec_key* source_slot = &psa_keys[operation->source_key_handle];
    psa_esec_key* target_slot = &psa_keys[target_slot_index];

    *key = target_slot_index;

    return psa_key_derivation_output_key_internal(attributes, operation, source_slot, target_slot);
}


psa_status_t psa_key_derivation_verify_bytes(
    psa_key_derivation_operation_t *operation,
    const uint8_t *expected_output,
    size_t output_length)
{
    return PSA_ERROR_NOT_SUPPORTED;
}


psa_status_t psa_key_derivation_verify_key(
    psa_key_derivation_operation_t *operation,
    psa_key_id_t expected)
{
    return PSA_ERROR_NOT_SUPPORTED;
}


psa_status_t psa_key_derivation_abort(
    psa_key_derivation_operation_t *operation)
{
    psa_status_t status = PSA_SUCCESS;

    psa_algorithm_t kdf_alg = psa_key_derivation_get_kdf_alg(operation);
    if (kdf_alg == 0 || PSA_ALG_IS_HKDF(kdf_alg)) {
        /* The object has (apparently) been initialized but it is not
         * in use. It's ok to call abort on such an object, and there's
         * nothing to do. */
    }
    else {
        status = PSA_ERROR_BAD_STATE;
    }

    if (operation->ctx.hkdf.info_length > 0) {
        psa_plat_mem_free(operation->ctx.hkdf.info);
    }

    if (operation->ctx.hkdf.salt_length > 0) {
        psa_plat_mem_free(operation->ctx.hkdf.salt);
    }

    memset(operation, 0, sizeof(*operation));
    return status;
}

psa_status_t psa_raw_key_agreement(psa_algorithm_t alg,
                                   psa_key_id_t private_key,
                                   const uint8_t *peer_key,
                                   size_t peer_key_length,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *output_length)
{
    psa_status_t status;

    CHECK_INIT();

    if (!PSA_ALG_IS_KEY_AGREEMENT(alg)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    if (private_key > NUMBER_OF_KEY_SLOTS)
        return PSA_ERROR_INVALID_HANDLE;

    status = psa_raw_key_agreement_internal(alg, &psa_keys[private_key], peer_key, peer_key_length, output, output_size, output_length);
exit:
    if (status != PSA_SUCCESS) {
        /*
         * If an error happens and is not handled properly, the output may be
         * used as a key to protect sensitive data. Arrange for such a key to
         * be random, which is likely to result in decryption or verification
         * errors. This is better than filling the buffer with some constant
         * data such as zeros, which would result in the data being protected
         * with a reproducible, easily knowable key.
         */
        psa_generate_random(output, output_size);
        *output_length = output_size;
    }

    return status;
}

/**@}*/

/** \defgroup random Random generation
 * @{
 */
psa_status_t psa_generate_random(uint8_t *output,
                                 size_t output_size)
{
    CHECK_INIT();

    esec_get_random_bytes(output, output_size);

    return PSA_SUCCESS;
}

psa_status_t psa_generate_key(const psa_key_attributes_t *attributes,
                              psa_key_id_t *key)
{
    psa_status_t retval = PSA_ERROR_INVALID_ARGUMENT;
    uint32_t key_policy_usage = 0;
    esec_key volatile_key;
    int32_t key_index = -1;
    bool is_persistent_key = attributes->core.lifetime == PSA_KEY_LIFETIME_PERSISTENT;
    struct esec_key_storage storage;

    CHECK_INIT();

    if (psa_get_key_bits(attributes) == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (attributes->core.policy.usage & PSA_KEY_USAGE_COPY ||
        attributes->core.policy.usage & PSA_KEY_USAGE_ENCRYPT ||
        attributes->core.policy.usage & PSA_KEY_USAGE_DECRYPT ||
        attributes->core.policy.usage & PSA_KEY_USAGE_DERIVE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_policy_usage = 0;
    if (attributes->core.policy.usage & PSA_KEY_USAGE_EXPORT) {
        key_policy_usage |= ESEC_KEY_EXPORTABLE;
    }

    switch (attributes->core.type) {
    case PSA_KEY_TYPE_AES:
    case PSA_KEY_TYPE_DES: {
            uint8_t random_key[64];
            uint32_t key_len_in_bytes = attributes->core.bits / 8;

            psa_generate_random(random_key, key_len_in_bytes);

            retval = import_skey(key_policy_usage, is_persistent_key, &key_index, random_key, key_len_in_bytes, storage, &volatile_key);
        }
        break;
    case PSA_KEY_TYPE_RSA_KEY_PAIR:
    case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1):
         retval = psa_generate_asym_key(attributes, &key_index, &volatile_key);
         break;
    default:
         return PSA_ERROR_NOT_SUPPORTED;
         break;
    }

    if (PSA_SUCCESS == retval) {
        *key = (psa_key_id_t)key_index;

        retval = psa_set_key_slot(*key, attributes, &volatile_key, 0);
    }

    return retval;
}

psa_status_t psa_purge_key(psa_key_id_t key)
{
    return PSA_ERROR_NOT_SUPPORTED;
}
