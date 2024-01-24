/**
 * \file psa/crypto_struct.h
 *
 * \brief PSA cryptography module: Structured type implementations
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 */

#ifndef PSA_CRYPTO_STRUCT_H
#define PSA_CRYPTO_STRUCT_H

#ifdef __cplusplus
extern "C" {
#endif

#define PSA_HASH_MAX_SIZE_IN_BYTES              (64)        // SHA512

/** Maximum length of any IV, in Bytes. */
#define PSA_IV_MAX_LENGTH                       (16)

/** Maximum block size of any cipher, in Bytes. */
#define PSA_BLOCK_MAX_LENGTH                    (16)

struct psa_hash_operation_s
{
    psa_algorithm_t alg;
    uint8_t buffer[PSA_HASH_MAX_SIZE_IN_BYTES];
    uint32_t total_len;
    uint32_t block_size;
    uint8_t uncompleted_block[128];
    uint32_t uncompleted_len;
};

#define PSA_HASH_OPERATION_INIT { 0 }
static inline struct psa_hash_operation_s psa_hash_operation_init( void )
{
    const struct psa_hash_operation_s v = PSA_HASH_OPERATION_INIT;
    return( v );
}

struct psa_cipher_operation_s
{
    psa_key_id_t key_handle;
    psa_algorithm_t alg;
    uint32_t key_set : 1;
    uint32_t iv_required : 1;
    uint32_t iv_set : 1;
    uint32_t encrypt : 1;

    uint8_t iv[PSA_IV_MAX_LENGTH];
    uint8_t iv_size;
    uint8_t block_size;
    uint32_t unprocessedLength;
    union {
        struct {
            struct esec_aes_state state;
            uint32_t started : 1;
            uint8_t unprocessed_data[16];
        } aes;
    } ctx;
};

#define PSA_CIPHER_OPERATION_INIT { 0, 0, 0, 0 }
static inline struct psa_cipher_operation_s psa_cipher_operation_init( void )
{
    const struct psa_cipher_operation_s v = PSA_CIPHER_OPERATION_INIT;
    return( v );
}

struct psa_mac_operation_s
{
    psa_key_id_t key_handle;
    psa_algorithm_t alg;
    unsigned int key_set : 1;
    unsigned int iv_required : 1;
    unsigned int iv_set : 1;
    unsigned int has_input : 1;
    unsigned int is_sign : 1;
    uint8_t mac_size;
    union
    {
        struct
        {
            uint8_t digest[PSA_HASH_MAX_SIZE_IN_BYTES];
        } hmac;
        struct
        {
            uint8_t tag[16];
        } cmac;
    } ctx;
};

#define PSA_MAC_OPERATION_INIT { 0, 0, 0 }
static inline struct psa_mac_operation_s psa_mac_operation_init(void)
{
    const struct psa_mac_operation_s v = PSA_MAC_OPERATION_INIT;
    return( v );
}

struct psa_aead_operation_s
{
    int32_t key_id;
    psa_algorithm_t alg;
    uint32_t key_set : 1;
    uint32_t nonce_set : 1;
    uint32_t encrypt : 1;
    uint32_t lengths_set : 1;
    uint32_t ad_started : 1;
    uint32_t body_started : 1;
    uint8_t nonce_size;
    uint8_t full_tag_length;
    uint8_t tag_length;
    uint8_t nonce[16];
    size_t ad_offset;
    size_t ad_remaining;
    size_t body_offset;
    size_t body_remaining;
    size_t input_length;
    uint8_t ad[32];
    union {
        struct {
            uint8_t tag[ESEC_TAG_SIZE_AES_GCM];
        } GCM;
        struct {
            uint8_t tag[16];
        } CCM;
        struct {
            uint8_t tag[16];
        } ChaChaPoly;
    } ctx;
};

#define PSA_AEAD_OPERATION_INIT { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, { 0 }, 0, 0, 0, 0, 0, { 0 }, { 0 } }
static inline struct psa_aead_operation_s psa_aead_operation_init( void )
{
    const struct psa_aead_operation_s v = PSA_AEAD_OPERATION_INIT;
    return( v );
}

typedef struct
{
    uint8_t *info;
    size_t info_length;
    uint8_t *salt;
    size_t salt_length;
    uint8_t prk[PSA_HASH_MAX_SIZE];
    uint8_t output_block[PSA_HASH_MAX_SIZE];
    uint8_t offset_in_block;
    uint8_t block_number;
    psa_mac_operation_t hmac;
    unsigned int state : 2;
    unsigned int info_set : 1;
    unsigned int salt_set : 1;
} psa_hkdf_key_derivation_t;

struct psa_key_derivation_s
{
    psa_algorithm_t alg;
    unsigned int can_output_key : 1;
    size_t capacity;
    psa_key_id_t source_key_handle;
    union
    {
        psa_hkdf_key_derivation_t hkdf;
    } ctx;
};

/* This only zeroes out the first byte in the union, the rest is unspecified. */
#define PSA_KEY_DERIVATION_OPERATION_INIT { 0, 0, 0, 0, { 0 } }
static inline struct psa_key_derivation_s psa_key_derivation_operation_init(
        void )
{
    const struct psa_key_derivation_s v = PSA_KEY_DERIVATION_OPERATION_INIT;
    return( v );
}

struct psa_key_policy_s
{
    psa_key_usage_t usage;
    psa_algorithm_t alg;
    psa_algorithm_t alg2;
};
typedef struct psa_key_policy_s psa_key_policy_t;

#define PSA_KEY_POLICY_INIT { 0, 0, 0 }
static inline struct psa_key_policy_s psa_key_policy_init( void )
{
    const struct psa_key_policy_s v = PSA_KEY_POLICY_INIT;
    return( v );
}

/* The type used internally for key sizes.
 * Public interfaces use size_t, but internally we use a smaller type. */
typedef uint16_t psa_key_bits_t;
/* The maximum value of the type used to represent bit-sizes.
 * This is used to mark an invalid key size. */
#define PSA_KEY_BITS_TOO_LARGE          ( ( psa_key_bits_t ) -1 )
/* The maximum size of a key in bits.
 * Currently defined as the maximum that can be represented, rounded down
 * to a whole number of bytes.
 * This is an uncast value so that it can be used in preprocessor
 * conditionals. */
#define PSA_MAX_KEY_BITS 0xfff8

/** A mask of flags that can be stored in key attributes.
 *
 * This type is also used internally to store flags in slots. Internal
 * flags are defined in library/psa_crypto_core.h. Internal flags may have
 * the same value as external flags if they are properly handled during
 * key creation and in psa_get_key_attributes.
 */
typedef uint16_t psa_key_attributes_flag_t;

typedef struct
{
    psa_key_type_t type;
    psa_key_bits_t bits;
    psa_key_lifetime_t lifetime;
    psa_key_id_t id;
    psa_key_policy_t policy;
    psa_key_attributes_flag_t flags;
} psa_core_key_attributes_t;

#define PSA_CORE_KEY_ATTRIBUTES_INIT { PSA_KEY_TYPE_NONE, 0,            \
                                       PSA_KEY_LIFETIME_VOLATILE,       \
                                       ( (psa_key_id_t)0 ),         \
                                       PSA_KEY_POLICY_INIT, 0 }

struct psa_key_attributes_s
{
    psa_core_key_attributes_t core;
    void *domain_parameters;
    size_t domain_parameters_size;
};

#define PSA_KEY_ATTRIBUTES_INIT { PSA_CORE_KEY_ATTRIBUTES_INIT, NULL, 0 }

static inline struct psa_key_attributes_s psa_key_attributes_init( void )
{
    const struct psa_key_attributes_s v = PSA_KEY_ATTRIBUTES_INIT;
    return( v );
}

static inline void psa_set_key_id( psa_key_attributes_t *attributes,
                                   psa_key_id_t key )
{
    psa_key_lifetime_t lifetime = attributes->core.lifetime;

    attributes->core.id = key;

    if( PSA_KEY_LIFETIME_IS_VOLATILE( lifetime ) )
    {
        attributes->core.lifetime =
            PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
                PSA_KEY_LIFETIME_PERSISTENT,
                PSA_KEY_LIFETIME_GET_LOCATION( lifetime ) );
    }
}

static inline psa_key_id_t psa_get_key_id(
    const psa_key_attributes_t *attributes )
{
    return( attributes->core.id );
}

static inline void psa_set_key_lifetime( psa_key_attributes_t *attributes,
                                        psa_key_lifetime_t lifetime )
{
    attributes->core.lifetime = lifetime;
    if( PSA_KEY_LIFETIME_IS_VOLATILE( lifetime ) )
    {
        attributes->core.id = 0;
    }
}

static inline psa_key_lifetime_t psa_get_key_lifetime(
    const psa_key_attributes_t *attributes )
{
    return( attributes->core.lifetime );
}

static inline void psa_extend_key_usage_flags( psa_key_usage_t *usage_flags )
{
    if( *usage_flags & PSA_KEY_USAGE_SIGN_HASH )
        *usage_flags |= PSA_KEY_USAGE_SIGN_MESSAGE;

    if( *usage_flags & PSA_KEY_USAGE_VERIFY_HASH )
        *usage_flags |= PSA_KEY_USAGE_VERIFY_MESSAGE;
}

static inline void psa_set_key_usage_flags(psa_key_attributes_t *attributes,
                                           psa_key_usage_t usage_flags)
{
    psa_extend_key_usage_flags( &usage_flags );
    attributes->core.policy.usage = usage_flags;
}

static inline psa_key_usage_t psa_get_key_usage_flags(
    const psa_key_attributes_t *attributes )
{
    return( attributes->core.policy.usage );
}

static inline void psa_set_key_algorithm( psa_key_attributes_t *attributes,
                                         psa_algorithm_t alg )
{
    attributes->core.policy.alg = alg;
}

static inline psa_algorithm_t psa_get_key_algorithm(
    const psa_key_attributes_t *attributes )
{
    return( attributes->core.policy.alg );
}

/* This function is declared in crypto_extra.h, which comes after this
 * header file, but we need the function here, so repeat the declaration. */
psa_status_t psa_set_key_domain_parameters( psa_key_attributes_t *attributes,
                                           psa_key_type_t type,
                                           const uint8_t *data,
                                           size_t data_length );

static inline void psa_set_key_type( psa_key_attributes_t *attributes,
                                    psa_key_type_t type )
{
    if( attributes->domain_parameters == NULL )
    {
        /* Common case: quick path */
        attributes->core.type = type;
    }
    else
    {
        /* Call the bigger function to free the old domain paramteres.
         * Ignore any errors which may arise due to type requiring
         * non-default domain parameters, since this function can't
         * report errors. */
        (void) psa_set_key_domain_parameters( attributes, type, NULL, 0 );
    }
}

static inline psa_key_type_t psa_get_key_type(
    const psa_key_attributes_t *attributes )
{
    return( attributes->core.type );
}

static inline void psa_set_key_bits( psa_key_attributes_t *attributes,
                                    size_t bits )
{
    if( bits > PSA_MAX_KEY_BITS )
        attributes->core.bits = PSA_KEY_BITS_TOO_LARGE;
    else
        attributes->core.bits = (psa_key_bits_t) bits;
}

static inline size_t psa_get_key_bits(
    const psa_key_attributes_t *attributes )
{
    return( attributes->core.bits );
}

#ifdef __cplusplus
}
#endif

#endif /* PSA_CRYPTO_STRUCT_H */
