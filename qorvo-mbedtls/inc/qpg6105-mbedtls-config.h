// TODO - which Copyright

#ifndef QPG6105_MBEDTLS_CONFIG_H
#define QPG6105_MBEDTLS_CONFIG_H

#include "common-mbedtls-config.h"

#ifndef MBEDTLS_SW_ONLY
//#define MBEDTLS_CCM_ALT
#define MBEDTLS_ECP_ALT
#define MBEDTLS_ECDSA_VERIFY_ALT
#define MBEDTLS_ECDSA_SIGN_ALT
#define MBEDTLS_SHA256_ALT
#define MBEDTLS_ECDH_COMPUTE_SHARED_ALT
#endif

#define MBEDTLS_ENTROPY_HARDWARE_ALT

// Using Qorvo HW crypto engine
#undef MBEDTLS_ECP_WINDOW_SIZE
#undef MBEDTLS_ECP_FIXED_POINT_OPTIM

#define MBEDTLS_AES_ALT
#define MBEDTLS_ECJPAKE_ALT

#endif // QPG6105_MBEDTLS_CONFIG_H
