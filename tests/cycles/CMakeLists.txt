cmake_minimum_required(VERSION 3.13)

project(oberon-psa-crypto-lib
        LANGUAGES C ASM)

get_filename_component(OBERON_PSA_DIR "../../" REALPATH)

if(MSVC)
    add_compile_options(/std:c11)
endif()

# Expand the ocrypto root directory, if provided, or set to default
if(DEFINED OCRYPTO_ROOT)
    get_filename_component(OCRYPTO_ROOT "${OCRYPTO_ROOT}" REALPATH)
else()
    set(OCRYPTO_ROOT ${OBERON_PSA_DIR}/oberon/drivers/ocrypto)
endif()
if(NOT EXISTS "${OCRYPTO_ROOT}/include/ocrypto_types.h")
    message(FATAL_ERROR
            "Path ${OCRYPTO_ROOT} does not contain valid ocrypto sources. \
            Please provide -DOCRYPTO_ROOT=path/to/ocrypto/sources or copy \
            ocrypto sources to the following path: \
            ${CMAKE_CURRENT_LIST_DIR}/oberon/ocrypto")
endif()

# ocrypto library
add_library(ocrypto OBJECT)

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
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_wideint.c"
)

target_sources(ocrypto PRIVATE
        ${OCRYPTO_SOURCES}
        ${OCRYPTO_PLATFORM_SOURCES})

target_include_directories(ocrypto PUBLIC
        ${OCRYPTO_ROOT}/include)

target_include_directories(ocrypto PRIVATE
        ${OCRYPTO_ROOT}/src/platforms/Generic)

target_include_directories(ocrypto PRIVATE
        ${OCRYPTO_ROOT}/src)

# Oberon PSA Crypto library
add_library(${PROJECT_NAME} OBJECT)

# define sources used from Mbed TLS, modified and unmodified
set(MBED_SOURCES
        ${OBERON_PSA_DIR}/library/check_crypto_config.h
        ${OBERON_PSA_DIR}/library/common.h
        ${OBERON_PSA_DIR}/library/constant_time.c
        ${OBERON_PSA_DIR}/library/platform.c
        ${OBERON_PSA_DIR}/library/platform_util.c
        ${OBERON_PSA_DIR}/library/psa_crypto.c
        ${OBERON_PSA_DIR}/library/psa_crypto_client.c
        ${OBERON_PSA_DIR}/library/psa_crypto_core.h
        ${OBERON_PSA_DIR}/library/psa_crypto_driver_wrappers.h
        ${OBERON_PSA_DIR}/library/psa_crypto_driver_wrappers.c # platform-specific
        ${OBERON_PSA_DIR}/library/psa_crypto_invasive.h
        ${OBERON_PSA_DIR}/library/psa_crypto_its.h
        ${OBERON_PSA_DIR}/library/psa_crypto_random_impl.h
        ${OBERON_PSA_DIR}/library/psa_crypto_se.h
        ${OBERON_PSA_DIR}/library/psa_crypto_slot_management.h
        ${OBERON_PSA_DIR}/library/psa_crypto_slot_management.c
        ${OBERON_PSA_DIR}/library/psa_crypto_storage.h
        ${OBERON_PSA_DIR}/library/psa_crypto_storage.c
        ${OBERON_PSA_DIR}/library/psa_its_file.c
)

# Oberon drivers
set(OBERON_SOURCES
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_aead.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_aead.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_asymmetric_encrypt.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_asymmetric_encrypt.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_asymmetric_signature.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_asymmetric_signature.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_cipher.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_cipher.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_config.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_ctr_drbg.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_ctr_drbg.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_ecdh.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_ecdh.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_ecdsa.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_ecdsa.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_ec_keys.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_ec_keys.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_hash.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_hash.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_helpers.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_helpers.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_hmac_drbg.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_hmac_drbg.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_jpake.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_jpake.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_key_agreement.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_key_agreement.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_key_derivation.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_key_derivation.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_key_management.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_key_management.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_mac.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_mac.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_pake.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_pake.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_rsa.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_rsa.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_spake2p.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_spake2p.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_srp.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_srp.h
)

# Demo drivers
set(OBERON_DEMO_SOURCES
        ${OBERON_PSA_DIR}/oberon/platforms/demo/drivers/demo_entropy.c
        ${OBERON_PSA_DIR}/oberon/platforms/demo/drivers/demo_entropy.h
        ${OBERON_PSA_DIR}/oberon/platforms/demo/drivers/demo_hardware.c
        ${OBERON_PSA_DIR}/oberon/platforms/demo/drivers/demo_hardware.h
        ${OBERON_PSA_DIR}/oberon/platforms/demo/drivers/demo_opaque.c
        ${OBERON_PSA_DIR}/oberon/platforms/demo/drivers/demo_opaque.h
)

target_sources(${PROJECT_NAME} PRIVATE ${MBED_SOURCES})
target_sources(${PROJECT_NAME} PRIVATE ${OBERON_SOURCES})
target_sources(${PROJECT_NAME} PRIVATE ${OBERON_DEMO_SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE ${OCRYPTO_ROOT}/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/oberon/drivers)
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/oberon/platforms/demo/drivers)
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/library)

target_include_directories(${PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${OBERON_PSA_DIR}/include>
        $<INSTALL_INTERFACE:include>)

# Testing
include(CTest)
project("Cycles")
message(STATUS "Add test suite ${PROJECT_NAME}")
add_executable(${PROJECT_NAME})
target_sources(${PROJECT_NAME} PRIVATE cycle_test.c)
target_sources(${PROJECT_NAME} PRIVATE retarget.c)

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# add platform drivers
target_include_directories(${PROJECT_NAME} PRIVATE "${OBERON_PSA_DIR}/oberon/platforms/demo/drivers")
target_include_directories(${PROJECT_NAME} PRIVATE "${OBERON_PSA_DIR}/oberon/platforms/demo/include")

# add Oberon drivers
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/oberon/drivers)

target_link_libraries(${PROJECT_NAME} PRIVATE ocrypto)
target_link_libraries(${PROJECT_NAME} PRIVATE oberon-psa-crypto-lib)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
set_property(TEST ${PROJECT_NAME} PROPERTY LABELS "Cycles")
