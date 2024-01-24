#if defined(PSA_CRYPTO_IMPLEMENTED)
#include "psa_crypto_hash_se.c"
#else
#include "psa_crypto_hash_mbedtls.c"
#endif
