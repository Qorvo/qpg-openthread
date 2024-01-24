// TODO - which Copyright

#ifndef QPG6200_MBEDTLS_CONFIG_H
#define QPG6200_MBEDTLS_CONFIG_H

#include "common-mbedtls-config.h"

#ifndef MBEDTLS_SW_ONLY
#define MBEDTLS_ECP_ALT
#define MBEDTLS_SHA256_ALT
#endif

#endif // QPG6200_MBEDTLS_CONFIG_H
