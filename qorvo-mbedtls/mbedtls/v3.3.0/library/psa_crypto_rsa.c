#if defined(PSA_CRYPTO_IMPLEMENTED)
#include "psa_crypto_rsa_se.c"
#else
#include "psa_crypto_rsa_mbedtls.c"
#endif
