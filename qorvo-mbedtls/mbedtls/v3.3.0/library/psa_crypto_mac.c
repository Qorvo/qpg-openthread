#if defined(PSA_CRYPTO_IMPLEMENTED)
#include "psa_crypto_mac_se.c"
#else
#include "psa_crypto_mac_mbedtls.c"
#endif
