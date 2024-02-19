#
#  Copyright (c) 2021, The OpenThread Authors.
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. Neither the name of the copyright holder nor the
#     names of its contributors may be used to endorse or promote products
#     derived from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#  POSSIBILITY OF SUCH DAMAGE.
#

add_library(qorvo-mbedtls)

set_target_properties(qorvo-mbedtls
    PROPERTIES
        C_STANDARD 99
        CXX_STANDARD 20
)

set(QORVO_MBEDTLS_ALT_DIR "${QORVO_MBEDTLS_SDK_DIR}/mbedtls_alt_3.3.0/")
set(QORVO_MBEDTLS_DIR "${QORVO_MBEDTLS_SDK_DIR}/mbedtls/v3.3.0/")

target_compile_definitions(qorvo-mbedtls
    PRIVATE
        ${OT_PLATFORM_DEFINES}
)

target_link_libraries(qorvo-mbedtls
    PRIVATE
        ot-config
        ${OT_PLATFORM_LIB_FTD}
)

target_include_directories(qorvo-mbedtls
    PUBLIC
        ${QORVO_MBEDTLS_DIR}/include
        ${QORVO_MBEDTLS_ALT_DIR}/
        ${QORVO_MBEDTLS_DIR}/include/mbedtls
        ${QORVO_MBEDTLS_DIR}/library
        ${PROJECT_SOURCE_DIR}/src/${PLATFORM_LOWERCASE}/crypto
    PRIVATE
        ${QORVO_MBEDTLS_DIR}/include/psa
)

set(QORVO_MBEDTLS_SOURCES
    # ${QORVO_MBEDTLS_DIR}/library/aes.c
    ${QORVO_MBEDTLS_DIR}/library/asn1parse.c
    ${QORVO_MBEDTLS_DIR}/library/asn1write.c
    ${QORVO_MBEDTLS_DIR}/library/base64.c
    ${QORVO_MBEDTLS_DIR}/library/bignum.c
    ${QORVO_MBEDTLS_DIR}/library/bignum_core.c
    ${QORVO_MBEDTLS_DIR}/library/constant_time.c
    ${QORVO_MBEDTLS_DIR}/library/ccm.c
    ${QORVO_MBEDTLS_DIR}/library/cipher_wrap.c
    ${QORVO_MBEDTLS_DIR}/library/cipher.c
    ${QORVO_MBEDTLS_DIR}/library/cmac.c
    ${QORVO_MBEDTLS_DIR}/library/ctr_drbg.c
    ${QORVO_MBEDTLS_DIR}/library/des.c
    ${QORVO_MBEDTLS_DIR}/library/ecdh.c
    ${QORVO_MBEDTLS_DIR}/library/ecdsa.c
    ${QORVO_MBEDTLS_DIR}/library/ecjpake.c
    ${QORVO_MBEDTLS_DIR}/library/ecp_curves.c
    ${QORVO_MBEDTLS_DIR}/library/ecp.c
    ${QORVO_MBEDTLS_DIR}/library/entropy.c
    ${QORVO_MBEDTLS_DIR}/library/error.c
    ${QORVO_MBEDTLS_DIR}/library/hmac_drbg.c
    ${QORVO_MBEDTLS_DIR}/library/hash_info.c
    ${QORVO_MBEDTLS_DIR}/library/md.c
    ${QORVO_MBEDTLS_DIR}/library/oid.c
    ${QORVO_MBEDTLS_DIR}/library/pem.c
    ${QORVO_MBEDTLS_DIR}/library/pk_wrap.c
    ${QORVO_MBEDTLS_DIR}/library/pk.c
    ${QORVO_MBEDTLS_DIR}/library/pkcs5.c
    ${QORVO_MBEDTLS_DIR}/library/pkparse.c
    ${QORVO_MBEDTLS_DIR}/library/pkwrite.c
    ${QORVO_MBEDTLS_DIR}/library/platform_util.c
    ${QORVO_MBEDTLS_DIR}/library/platform.c
    # ${QORVO_MBEDTLS_DIR}/library/rsa_internal.c
    # ${QORVO_MBEDTLS_DIR}/library/rsa.c
    ${QORVO_MBEDTLS_DIR}/library/sha256.c
    ${QORVO_MBEDTLS_DIR}/library/ssl_cache.c
    ${QORVO_MBEDTLS_DIR}/library/ssl_ciphersuites.c
    # ${QORVO_MBEDTLS_DIR}/library/ssl_cli.c
    ${QORVO_MBEDTLS_DIR}/library/ssl_client.c
    ${QORVO_MBEDTLS_DIR}/library/ssl_cookie.c
    ${QORVO_MBEDTLS_DIR}/library/ssl_msg.c
    # ${QORVO_MBEDTLS_DIR}/library/ssl_srv.c
    ${QORVO_MBEDTLS_DIR}/library/ssl_ticket.c
    ${QORVO_MBEDTLS_DIR}/library/ssl_tls.c
    ${QORVO_MBEDTLS_DIR}/library/ssl_tls12_client.c
    ${QORVO_MBEDTLS_DIR}/library/ssl_tls12_server.c
    ${QORVO_MBEDTLS_DIR}/library/threading.c
    ${QORVO_MBEDTLS_DIR}/library/x509_create.c
    ${QORVO_MBEDTLS_DIR}/library/x509_crl.c
    ${QORVO_MBEDTLS_DIR}/library/x509_crt.c
    ${QORVO_MBEDTLS_DIR}/library/x509_csr.c
    ${QORVO_MBEDTLS_DIR}/library/x509.c
    ${QORVO_MBEDTLS_DIR}/library/x509write_crt.c
    ${QORVO_MBEDTLS_DIR}/library/x509write_csr.c

    ${QORVO_MBEDTLS_SDK_DIR}/src/trng.c
)

if (OT_MBEDTLS_DEBUG)
    list(APPEND QORVO_MBEDTLS_SOURCES
        ${QORVO_MBEDTLS_DIR}/library/debug.c
        ${QORVO_MBEDTLS_DIR}/library/ssl_debug_helpers_generated.c)
endif()

set_source_files_properties(${QORVO_MBEDTLS_SOURCES} PROPERTIES LANGUAGE C)


target_sources(qorvo-mbedtls PRIVATE ${QORVO_MBEDTLS_SOURCES})
