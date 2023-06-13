#if defined(PSA_CRYPTO_IMPLEMENTED)
#include "psa_crypto_aead_se.c"
#else
#include "psa_crypto_aead_mbedtls.c"
#endif
