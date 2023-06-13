#if defined(PSA_CRYPTO_IMPLEMENTED)
#include "psa_crypto_ecp_se.c"
#else
#include "psa_crypto_ecp_mbedtls.c"
#endif
