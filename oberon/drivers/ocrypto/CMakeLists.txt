cmake_minimum_required(VERSION 3.13)

if(NOT DEFINED OCRYPTO_ROOT)
    set(OCRYPTO_ROOT ${CMAKE_CURRENT_LIST_DIR})
endif()
message(STATUS "Add ocrypto source: ${OCRYPTO_ROOT}")

project(ocrypto
        LANGUAGES C ASM)

add_library(${PROJECT_NAME} OBJECT)

set(OCRYPTO_SOURCES
        "${OCRYPTO_ROOT}/src/ocrypto_aes.h"
        "${OCRYPTO_ROOT}/src/ocrypto_aes_cbc_pkcs.c"
        "${OCRYPTO_ROOT}/src/ocrypto_aes_ccm.c"
        "${OCRYPTO_ROOT}/src/ocrypto_aes_cmac.c"
        "${OCRYPTO_ROOT}/src/ocrypto_aes_ctr.c"
        "${OCRYPTO_ROOT}/src/ocrypto_aes_gcm.c"
        "${OCRYPTO_ROOT}/src/ocrypto_bigint128.h"
        "${OCRYPTO_ROOT}/src/ocrypto_bigint192.h"
        "${OCRYPTO_ROOT}/src/ocrypto_bigint224.h"
        "${OCRYPTO_ROOT}/src/ocrypto_bigint256.h"
        "${OCRYPTO_ROOT}/src/ocrypto_bigint384.h"
        "${OCRYPTO_ROOT}/src/ocrypto_bigint448.h"
        "${OCRYPTO_ROOT}/src/ocrypto_bigint521.h"
        "${OCRYPTO_ROOT}/src/ocrypto_chacha20.c"
        "${OCRYPTO_ROOT}/src/ocrypto_chacha20_loop.h"
        "${OCRYPTO_ROOT}/src/ocrypto_chacha20_poly1305.c"
        "${OCRYPTO_ROOT}/src/ocrypto_curve25519.c"
        "${OCRYPTO_ROOT}/src/ocrypto_curve448.c"
        "${OCRYPTO_ROOT}/src/ocrypto_curve_p224.c"
        "${OCRYPTO_ROOT}/src/ocrypto_curve_p224.h"
        "${OCRYPTO_ROOT}/src/ocrypto_curve_p256.c"
        "${OCRYPTO_ROOT}/src/ocrypto_curve_p256.h"
        "${OCRYPTO_ROOT}/src/ocrypto_curve_p384.c"
        "${OCRYPTO_ROOT}/src/ocrypto_curve_p384.h"
        "${OCRYPTO_ROOT}/src/ocrypto_curve_p521.c"
        "${OCRYPTO_ROOT}/src/ocrypto_curve_p521.h"
        "${OCRYPTO_ROOT}/src/ocrypto_ecdh_p224.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ecdh_p256.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ecdh_p384.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ecdh_p521.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ecdsa_p224.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ecdsa_p256.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ecdsa_p384.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ecdsa_p521.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ecjpake_p256.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ed25519.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ed448.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ge25519.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ge448.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ge25519.h"
        "${OCRYPTO_ROOT}/src/ocrypto_ge448.h"
        "${OCRYPTO_ROOT}/src/ocrypto_load_store.h"
        "${OCRYPTO_ROOT}/src/ocrypto_mod25519.c"
        "${OCRYPTO_ROOT}/src/ocrypto_mod25519.h"
        "${OCRYPTO_ROOT}/src/ocrypto_mod448.c"
        "${OCRYPTO_ROOT}/src/ocrypto_mod448.h"
        "${OCRYPTO_ROOT}/src/ocrypto_mod_p224.c"
        "${OCRYPTO_ROOT}/src/ocrypto_mod_p224.h"
        "${OCRYPTO_ROOT}/src/ocrypto_mod_p256.c"
        "${OCRYPTO_ROOT}/src/ocrypto_mod_p256.h"
        "${OCRYPTO_ROOT}/src/ocrypto_mod_p384.c"
        "${OCRYPTO_ROOT}/src/ocrypto_mod_p384.h"
        "${OCRYPTO_ROOT}/src/ocrypto_mod_p521.c"
        "${OCRYPTO_ROOT}/src/ocrypto_mod_p521.h"
        "${OCRYPTO_ROOT}/src/ocrypto_poly1305.c"
        "${OCRYPTO_ROOT}/src/ocrypto_poly1305_mul.h"
        "${OCRYPTO_ROOT}/src/ocrypto_rsa_primitives.c"
        "${OCRYPTO_ROOT}/src/ocrypto_rsa_internal.h"
        "${OCRYPTO_ROOT}/src/ocrypto_sc25519.c"
        "${OCRYPTO_ROOT}/src/ocrypto_sc25519.h"
        "${OCRYPTO_ROOT}/src/ocrypto_sc448.c"
        "${OCRYPTO_ROOT}/src/ocrypto_sc448.h"
        "${OCRYPTO_ROOT}/src/ocrypto_sc_p224.c"
        "${OCRYPTO_ROOT}/src/ocrypto_sc_p224.h"
        "${OCRYPTO_ROOT}/src/ocrypto_sc_p256.c"
        "${OCRYPTO_ROOT}/src/ocrypto_sc_p256.h"
        "${OCRYPTO_ROOT}/src/ocrypto_sc_p384.c"
        "${OCRYPTO_ROOT}/src/ocrypto_sc_p384.h"
        "${OCRYPTO_ROOT}/src/ocrypto_sc_p521.c"
        "${OCRYPTO_ROOT}/src/ocrypto_sc_p521.h"
        "${OCRYPTO_ROOT}/src/ocrypto_sha1.c"
        "${OCRYPTO_ROOT}/src/ocrypto_sha256.c"
        "${OCRYPTO_ROOT}/src/ocrypto_sha256_loop.h"
        "${OCRYPTO_ROOT}/src/ocrypto_sha512.c"
        "${OCRYPTO_ROOT}/src/ocrypto_sha512_loop.h"
        "${OCRYPTO_ROOT}/src/ocrypto_sha3.c"
        "${OCRYPTO_ROOT}/src/ocrypto_sha3_loop.h"
        "${OCRYPTO_ROOT}/src/ocrypto_spake2p_p256.c"
        "${OCRYPTO_ROOT}/src/ocrypto_srp.c"
        "${OCRYPTO_ROOT}/src/ocrypto_srp_math.c"
        "${OCRYPTO_ROOT}/src/ocrypto_srp_math.h"
        "${OCRYPTO_ROOT}/src/ocrypto_wideint.h"
        "${OCRYPTO_ROOT}/src/ocrypto_wideint_inv.c"
        "${OCRYPTO_ROOT}/src/ocrypto_wideint_inv.h"
        "${OCRYPTO_ROOT}/src/ocrypto_wideint_mul.c"
        "${OCRYPTO_ROOT}/src/ocrypto_wideint_mul.h"
        )

set(OCRYPTO_PLATFORM_SOURCES
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_cpu_dep.h"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_aes.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_aes_dec.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_bigint128.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_bigint192.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_bigint224.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_bigint256.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_bigint384.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_bigint448.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_bigint521.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_chacha20_loop.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_constant_time.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_gf128_mul.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_load_store.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_mod25519_base.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_mod448_base.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_mod_p224_base.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_mod_p256_base.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_mod_p384_base.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_mod_p521_base.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_poly1305_mul.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_sha256_loop.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_sha512_loop.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_sha3_loop.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_wideint.c")

target_sources(${PROJECT_NAME} PRIVATE
        ${OCRYPTO_SOURCES}
        ${OCRYPTO_PLATFORM_SOURCES})

target_include_directories(${PROJECT_NAME} PUBLIC
        ${OCRYPTO_ROOT}/include)

target_include_directories(${PROJECT_NAME} PRIVATE
        ${OCRYPTO_ROOT}/src/platforms/Generic)

target_include_directories(${PROJECT_NAME} PRIVATE
        ${OCRYPTO_ROOT}/src)
