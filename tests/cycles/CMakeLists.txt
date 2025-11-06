cmake_minimum_required(VERSION 3.13)

project(oberon-psa-crypto-lib
        LANGUAGES C ASM)

if(MSVC)
    add_compile_options(/std:c11)
endif()

if(CONFIG_TF_PSA_CRYPTO_DIRS)
    get_filename_component(OBERON_PSA_DIR "../../../" REALPATH)
    set(PATH_LEGACY_MBEDTLS_INC drivers/builtin/include)
    set(PATH_LEGACY_MBEDTLS_SRC drivers/builtin/src)
    set(PATH_CORE core)
    set(PATH_TESTS framework/tests)
else()
    get_filename_component(OBERON_PSA_DIR "../../" REALPATH)
    set(PATH_LEGACY_MBEDTLS_INC include)
    set(PATH_LEGACY_MBEDTLS_SRC library)
    set(PATH_CORE library)
    set(PATH_TESTS tests)
endif()


# Expand the ocrypto root directory, if provided, or set to default
if(DEFINED OCRYPTO_ROOT)
    get_filename_component(OCRYPTO_ROOT "${OCRYPTO_ROOT}" REALPATH)
else()
    set(OCRYPTO_ROOT ${OBERON_PSA_DIR}/oberon/drivers/ocrypto)
endif()
if(NOT EXISTS "${OCRYPTO_ROOT}/include/ocrypto_types_p256.h")
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
        "${OCRYPTO_ROOT}/src/ocrypto_aes_cbc.c"
        "${OCRYPTO_ROOT}/src/ocrypto_aes_cbc_pkcs.c"
        "${OCRYPTO_ROOT}/src/ocrypto_aes_ccm.c"
        "${OCRYPTO_ROOT}/src/ocrypto_aes_cmac.c"
        "${OCRYPTO_ROOT}/src/ocrypto_aes_ctr.c"
        "${OCRYPTO_ROOT}/src/ocrypto_aes_ecb.c"
        "${OCRYPTO_ROOT}/src/ocrypto_aes_gcm.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ascon_aead.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ascon_hash.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ascon_loop.h"
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
        "${OCRYPTO_ROOT}/src/ocrypto_curve_p256k1.c"
        "${OCRYPTO_ROOT}/src/ocrypto_curve_p256k1.h"
        "${OCRYPTO_ROOT}/src/ocrypto_curve_p384.c"
        "${OCRYPTO_ROOT}/src/ocrypto_curve_p384.h"
        "${OCRYPTO_ROOT}/src/ocrypto_curve_p521.c"
        "${OCRYPTO_ROOT}/src/ocrypto_curve_p521.h"
        "${OCRYPTO_ROOT}/src/ocrypto_ecdh_p224.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ecdh_p256.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ecdh_p256k1.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ecdh_p384.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ecdh_p521.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ecdsa_p224.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ecdsa_p256.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ecdsa_p256k1.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ecdsa_p384.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ecdsa_p521.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ecjpake_p256.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ed25519.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ed448.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ge25519.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ge448.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ge25519.h"
        "${OCRYPTO_ROOT}/src/ocrypto_ge448.h"
        "${OCRYPTO_ROOT}/src/ocrypto_hkdf_sha256.c"
        "${OCRYPTO_ROOT}/src/ocrypto_hmac_sha256.c"
        "${OCRYPTO_ROOT}/src/ocrypto_hmac_sha512.c"
        "${OCRYPTO_ROOT}/src/ocrypto_load_store.h"
        "${OCRYPTO_ROOT}/src/ocrypto_ml_dsa44.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ml_dsa65.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ml_dsa87.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ml_dsa_math.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ml_dsa_math.h"
        "${OCRYPTO_ROOT}/src/ocrypto_ml_kem512.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ml_kem768.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ml_kem1024.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ml_kem_math.c"
        "${OCRYPTO_ROOT}/src/ocrypto_ml_kem_math.h"
        "${OCRYPTO_ROOT}/src/ocrypto_mod25519.c"
        "${OCRYPTO_ROOT}/src/ocrypto_mod25519.h"
        "${OCRYPTO_ROOT}/src/ocrypto_mod448.c"
        "${OCRYPTO_ROOT}/src/ocrypto_mod448.h"
        "${OCRYPTO_ROOT}/src/ocrypto_mod_p224.c"
        "${OCRYPTO_ROOT}/src/ocrypto_mod_p224.h"
        "${OCRYPTO_ROOT}/src/ocrypto_mod_p256.c"
        "${OCRYPTO_ROOT}/src/ocrypto_mod_p256.h"
        "${OCRYPTO_ROOT}/src/ocrypto_mod_p256k1.c"
        "${OCRYPTO_ROOT}/src/ocrypto_mod_p256k1.h"
        "${OCRYPTO_ROOT}/src/ocrypto_mod_p384.c"
        "${OCRYPTO_ROOT}/src/ocrypto_mod_p384.h"
        "${OCRYPTO_ROOT}/src/ocrypto_mod_p521.c"
        "${OCRYPTO_ROOT}/src/ocrypto_mod_p521.h"
        "${OCRYPTO_ROOT}/src/ocrypto_pbkdf2_cmac_prf128.c"
        "${OCRYPTO_ROOT}/src/ocrypto_pbkdf2_sha256.c"
        "${OCRYPTO_ROOT}/src/ocrypto_poly1305.c"
        "${OCRYPTO_ROOT}/src/ocrypto_poly1305_mul.h"
        "${OCRYPTO_ROOT}/src/ocrypto_rsa_primitives.c"
        "${OCRYPTO_ROOT}/src/ocrypto_rsa_internal.h"
        "${OCRYPTO_ROOT}/src/ocrypto_rsa_operations.c"
        "${OCRYPTO_ROOT}/src/ocrypto_rsa_padding.c"
        "${OCRYPTO_ROOT}/src/ocrypto_sc25519.c"
        "${OCRYPTO_ROOT}/src/ocrypto_sc25519.h"
        "${OCRYPTO_ROOT}/src/ocrypto_sc448.c"
        "${OCRYPTO_ROOT}/src/ocrypto_sc448.h"
        "${OCRYPTO_ROOT}/src/ocrypto_sc_p224.c"
        "${OCRYPTO_ROOT}/src/ocrypto_sc_p224.h"
        "${OCRYPTO_ROOT}/src/ocrypto_sc_p256.c"
        "${OCRYPTO_ROOT}/src/ocrypto_sc_p256.h"
        "${OCRYPTO_ROOT}/src/ocrypto_sc_p256k1.c"
        "${OCRYPTO_ROOT}/src/ocrypto_sc_p256k1.h"
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
        "${OCRYPTO_ROOT}/src/ocrypto_wpa3_sae_p256.c"
)

set(OCRYPTO_PLATFORM_SOURCES
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_cpu_dep.h"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_aes.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_aes_dec.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_ascon_loop.c"
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
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_ml_dsa_base.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_ml_kem_base.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_load_store.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_mod25519_base.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_mod448_base.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_mod_p224_base.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_mod_p256_base.c"
        "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_mod_p256k1_base.c"
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
set(OBERON_MBED_SOURCES
        ${OBERON_PSA_DIR}/${PATH_CORE}/check_crypto_config.h
        ${OBERON_PSA_DIR}/${PATH_CORE}/common.h
        ${OBERON_PSA_DIR}/${PATH_LEGACY_MBEDTLS_SRC}/constant_time.c
        ${OBERON_PSA_DIR}/${PATH_LEGACY_MBEDTLS_SRC}/platform.c
        ${OBERON_PSA_DIR}/${PATH_LEGACY_MBEDTLS_SRC}/platform_util.c              # modified
        ${OBERON_PSA_DIR}/${PATH_CORE}/psa_crypto.c
        ${OBERON_PSA_DIR}/${PATH_CORE}/psa_crypto_client.c
        ${OBERON_PSA_DIR}/${PATH_CORE}/psa_crypto_core.h
        ${OBERON_PSA_DIR}/${PATH_CORE}/psa_crypto_driver_wrappers.h
        ${OBERON_PSA_DIR}/oberon/platforms/demo/library/psa_crypto_driver_wrappers.c # platform-specific
        ${OBERON_PSA_DIR}/${PATH_CORE}/psa_crypto_invasive.h
        ${OBERON_PSA_DIR}/${PATH_CORE}/psa_crypto_its.h
        ${OBERON_PSA_DIR}/${PATH_CORE}/psa_crypto_random_impl.h
        ${OBERON_PSA_DIR}/${PATH_CORE}/psa_crypto_se.h
        ${OBERON_PSA_DIR}/${PATH_CORE}/psa_crypto_slot_management.h
        ${OBERON_PSA_DIR}/${PATH_CORE}/psa_crypto_slot_management.c
        ${OBERON_PSA_DIR}/${PATH_CORE}/psa_crypto_storage.h
        ${OBERON_PSA_DIR}/${PATH_CORE}/psa_crypto_storage.c
        ${OBERON_PSA_DIR}/${PATH_CORE}/psa_its_file.c
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
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_key_encapsulation.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_key_encapsulation.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_key_management.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_key_management.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_key_wrap.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_key_wrap.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_lms.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_lms.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_mac.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_mac.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_ml_dsa.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_ml_dsa.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_ml_kem.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_ml_kem.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_pake.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_pake.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_rsa.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_rsa.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_spake2p.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_spake2p.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_srp.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_srp.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_wpa3_sae.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_wpa3_sae.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_xmss.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_xmss.h
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_xof.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_xof.h
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


target_sources(${PROJECT_NAME} PRIVATE ${OBERON_MBED_SOURCES})
target_sources(${PROJECT_NAME} PRIVATE ${OBERON_SOURCES})
target_sources(${PROJECT_NAME} PRIVATE ${OBERON_DEMO_SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE include)
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/oberon/platforms/demo/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/${PATH_LEGACY_MBEDTLS_SRC})
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/${PATH_LEGACY_MBEDTLS_INC})
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/${PATH_CORE})

target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/oberon/drivers)
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/oberon/platforms/demo/drivers)

target_include_directories(${PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${OCRYPTO_ROOT}/include>
        $<INSTALL_INTERFACE:include>)
target_include_directories(${PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${OBERON_PSA_DIR}/include>
        $<INSTALL_INTERFACE:include>)
target_include_directories(${PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${OBERON_PSA_DIR}/${PATH_LEGACY_MBEDTLS_INC}>
        $<INSTALL_INTERFACE:${PATH_LEGACY_MBEDTLS_INC}>)



# Testing
include(CTest)
project("Cycles-Oberon-PSA")
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
set_property(TEST ${PROJECT_NAME} PROPERTY LABELS ${PROJECT_NAME})


project("Cycles-Oberon-PSA-Drivers")
message(STATUS "Add test suite ${PROJECT_NAME}")
add_executable(${PROJECT_NAME})
target_sources(${PROJECT_NAME} PRIVATE cycle_test_psa_drivers.c)
target_sources(${PROJECT_NAME} PRIVATE retarget.c)

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/${PATH_CORE})

# add platform drivers
target_include_directories(${PROJECT_NAME} PRIVATE "${OBERON_PSA_DIR}/oberon/platforms/demo/drivers")
target_include_directories(${PROJECT_NAME} PRIVATE "${OBERON_PSA_DIR}/oberon/platforms/demo/include")

# add Oberon drivers
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/oberon/drivers)

target_link_libraries(${PROJECT_NAME} PRIVATE ocrypto)
target_link_libraries(${PROJECT_NAME} PRIVATE oberon-psa-crypto-lib)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
set_property(TEST ${PROJECT_NAME} PROPERTY LABELS ${PROJECT_NAME})

project("Cycles-TF-PSA-Crypto")
include(CTest)
message(STATUS "Add test suite ${PROJECT_NAME}")

# TF-PSA-Crypto 
if(DEFINED TF_PSA_CRYPTO_ROOT)

    add_executable(${PROJECT_NAME})

    target_sources(${PROJECT_NAME} PRIVATE cycle_test.c)
    target_sources(${PROJECT_NAME} PRIVATE retarget.c)
    target_sources(${PROJECT_NAME} PRIVATE tf-psa-crypto/minimal_rng.c)

    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tf-psa-crypto)
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

    # add TF-PSA-Crypto
    target_include_directories(${PROJECT_NAME} PRIVATE ${TF_PSA_CRYPTO_ROOT}/include)
    target_include_directories(${PROJECT_NAME} PRIVATE ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/include)

    # Option 1:
    #set(TF_PSA_CRYPTO_TARGET_PREFIX subproject_test_)
    #add_subdirectory(${TF_PSA_CRYPTO_ROOT} build)
    #target_link_libraries(${PROJECT_NAME} PRIVATE subproject_test_tfpsacrypto)

    # Option 2:
    set(TF_Core_Sources
        ${TF_PSA_CRYPTO_ROOT}/core/psa_crypto.c
        ${TF_PSA_CRYPTO_ROOT}/core/psa_crypto_client.c
        ${TF_PSA_CRYPTO_ROOT}/core/psa_crypto_slot_management.c
        ${TF_PSA_CRYPTO_ROOT}/core/psa_crypto_storage.c
        ${TF_PSA_CRYPTO_ROOT}/core/psa_its_file.c
    )

    set(TF_Driver_Sources
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/aes.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/aesce.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/aesni.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/aria.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/asn1parse.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/asn1write.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/base64.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/bignum.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/bignum_core.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/bignum_mod.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/bignum_mod_raw.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/block_cipher.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/camellia.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/ccm.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/chacha20.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/chachapoly.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/cipher.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/cipher_wrap.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/cmac.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/constant_time.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/ctr_drbg.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/des.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/ecdh.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/ecdsa.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/ecjpake.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/ecp.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/ecp_curves.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/ecp_curves_new.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/entropy.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/entropy_poll.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/gcm.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/hkdf.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/hmac_drbg.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/lmots.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/lms.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/md.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/md5.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/memory_buffer_alloc.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/nist_kw.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/oid.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/pem.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/pk.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/pk_ecc.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/pk_wrap.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/pkcs12.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/pkcs5.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/pkparse.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/pkwrite.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/platform.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/platform_util.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/poly1305.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/psa_crypto_aead.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/psa_crypto_cipher.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/psa_crypto_ecp.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/psa_crypto_ffdh.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/psa_crypto_hash.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/psa_crypto_mac.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/psa_crypto_pake.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/psa_crypto_rsa.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/psa_util.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/ripemd160.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/rsa.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/rsa_alt_helpers.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/sha1.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/sha256.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/sha3.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/sha512.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src/threading.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/p256-m/p256-m/p256-m.c
    )

    target_sources(${PROJECT_NAME} PRIVATE 
        ${TF_Core_Sources} 
        ${TF_Driver_Sources}
        ${OBERON_PSA_DIR}/tests/cycles/tf-psa-crypto/psa_crypto_driver_wrappers_no_static.c
    )
    target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/tests/cycles/tf-psa-crypto)
    target_include_directories(${PROJECT_NAME} PRIVATE ${TF_PSA_CRYPTO_ROOT}/core)
    target_include_directories(${PROJECT_NAME} PRIVATE ${TF_PSA_CRYPTO_ROOT}/drivers/builtin/src)

    add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
    set_property(TEST ${PROJECT_NAME} PROPERTY LABELS ${PROJECT_NAME})

endif()

project("Cycles-ocrypto")
include(CTest)
message(STATUS "Add test suite ${PROJECT_NAME}")
add_executable(${PROJECT_NAME})
target_sources(${PROJECT_NAME} PRIVATE cycle_test_ocrypto.c)
target_sources(${PROJECT_NAME} PRIVATE retarget.c)
target_sources(${PROJECT_NAME} PRIVATE ${OCRYPTO_SOURCES})
target_sources(${PROJECT_NAME} PRIVATE ${OCRYPTO_PLATFORM_SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(${PROJECT_NAME} PRIVATE ${OCRYPTO_ROOT}/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${OCRYPTO_ROOT}/src)
target_include_directories(${PROJECT_NAME} PRIVATE ${OCRYPTO_ROOT}/src/platforms)
target_include_directories(${PROJECT_NAME} PRIVATE ${OCRYPTO_ROOT}/src/platforms/Generic)

target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/library)

# add platform drivers
target_include_directories(${PROJECT_NAME} PRIVATE "${OBERON_PSA_DIR}/oberon/platforms/demo/drivers")
target_include_directories(${PROJECT_NAME} PRIVATE "${OBERON_PSA_DIR}/oberon/platforms/demo/include")

# add Oberon drivers
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/oberon/drivers)

# target_link_libraries(${PROJECT_NAME} PRIVATE ocrypto)
target_link_libraries(${PROJECT_NAME} PRIVATE oberon-psa-crypto-lib)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
set_property(TEST ${PROJECT_NAME} PROPERTY LABELS ${PROJECT_NAME})


project("Cycles-TinyCrypt")
include(CTest)
message(STATUS "Add test suite ${PROJECT_NAME}")

# TinyCrypt
if(DEFINED TINYCRYPT_ROOT)

    set(TINYCRYPT_SHA512_ROOT "${TINYCRYPT_ROOT}/../tinycrypt-sha512/")
    set(TINYCRYPT_SOURCES
        ${TINYCRYPT_ROOT}/lib/source/aes_encrypt.c
        ${TINYCRYPT_ROOT}/lib/source/aes_decrypt.c
        ${TINYCRYPT_ROOT}/lib/source/cbc_mode.c
        ${TINYCRYPT_ROOT}/lib/source/ccm_mode.c
        ${TINYCRYPT_ROOT}/lib/source/cmac_mode.c
        ${TINYCRYPT_ROOT}/lib/source/ctr_mode.c
        ${TINYCRYPT_ROOT}/lib/source/ctr_prng.c
        ${TINYCRYPT_ROOT}/lib/source/ecc.c
        ${TINYCRYPT_ROOT}/lib/source/ecc_dh.c
        ${TINYCRYPT_ROOT}/lib/source/ecc_dsa.c
        ${TINYCRYPT_ROOT}/lib/source/ecc_platform_specific.c
        ${TINYCRYPT_ROOT}/lib/source/hmac.c
        ${TINYCRYPT_ROOT}/lib/source/hmac_prng.c
        ${TINYCRYPT_ROOT}/lib/source/sha256.c
        ${TINYCRYPT_ROOT}/lib/source/utils.c
        ${TINYCRYPT_SHA512_ROOT}/lib/source/sha512.c
    )

    add_executable(${PROJECT_NAME})
    target_sources(${PROJECT_NAME} PRIVATE cycle_test_tinycrypt.c)
    target_sources(${PROJECT_NAME} PRIVATE retarget.c)

    target_sources(${PROJECT_NAME} PRIVATE ${TINYCRYPT_SOURCES})

    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_include_directories(${PROJECT_NAME} PRIVATE ${TINYCRYPT_ROOT}/lib/include)
    target_include_directories(${PROJECT_NAME} PUBLIC ${TINYCRYPT_SHA512_ROOT}/lib/include)

    target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/oberon/platforms/demo/include)
    target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/include)

    add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
    set_property(TEST ${PROJECT_NAME} PROPERTY LABELS ${PROJECT_NAME})

endif()
