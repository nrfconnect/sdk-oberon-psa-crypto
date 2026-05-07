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
if(NOT EXISTS "${OCRYPTO_ROOT}/include/ocrypto_types_p256.h")
    message(FATAL_ERROR
            "Path ${OCRYPTO_ROOT} does not contain valid ocrypto sources. \
            Please provide -DOCRYPTO_ROOT=path/to/ocrypto/sources or copy \
            ocrypto sources to the following path: \
            ${CMAKE_CURRENT_LIST_DIR}/oberon/ocrypto")
endif()

# ocrypto library
add_library(ocrypto OBJECT)
file(GLOB OCRYPTO_SOURCES LIST_DIRECTORIES false CONFIGURE_DEPENDS "${OCRYPTO_ROOT}/src/ocrypto_*.[c|h]")
file(GLOB OCRYPTO_PLATFORM_SOURCES LIST_DIRECTORIES false CONFIGURE_DEPENDS "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_*.[c|h]")

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
        ${OBERON_PSA_DIR}/core/check_crypto_config.h
        ${OBERON_PSA_DIR}/core/tf_psa_crypto_common.h
        ${OBERON_PSA_DIR}/core/psa_crypto.c
        ${OBERON_PSA_DIR}/core/psa_crypto_client.c
        ${OBERON_PSA_DIR}/core/psa_crypto_core.h
        ${OBERON_PSA_DIR}/core/psa_crypto_invasive.h
        ${OBERON_PSA_DIR}/core/psa_crypto_its.h
        ${OBERON_PSA_DIR}/core/psa_crypto_slot_management.h
        ${OBERON_PSA_DIR}/core/psa_crypto_slot_management.c
        ${OBERON_PSA_DIR}/core/psa_crypto_storage.h
        ${OBERON_PSA_DIR}/core/psa_crypto_storage.c
        ${OBERON_PSA_DIR}/core/psa_its_file.c
        ${OBERON_PSA_DIR}/dispatch/psa_crypto_driver_wrappers.h
        ${OBERON_PSA_DIR}/platform/platform.c
        ${OBERON_PSA_DIR}/platform/platform_util.c              # modified
        ${OBERON_PSA_DIR}/platform/threading.c
        ${OBERON_PSA_DIR}/utilities/constant_time.c
        ${OBERON_PSA_DIR}/oberon/platforms/demo/library/psa_crypto_driver_wrappers.c # platform-specific
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
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_eddsa.c
        ${OBERON_PSA_DIR}/oberon/drivers/oberon_eddsa.h
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
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/core)
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/dispatch)
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/platform)
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/utilities)
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/legacy_sub/src)
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/legacy_sub/include)

target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/oberon/drivers)
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/oberon/platforms/demo/drivers)

target_include_directories(${PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${OCRYPTO_ROOT}/include>
        $<INSTALL_INTERFACE:include>)
target_include_directories(${PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${OBERON_PSA_DIR}/include>
        $<INSTALL_INTERFACE:include>)
target_include_directories(${PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${OBERON_PSA_DIR}/legacy_sub/include>
        $<INSTALL_INTERFACE:legacy_sub/include>)



# Testing
include(CTest)
project("Cycles-Oberon-PSA")
message(STATUS "Add test suite ${PROJECT_NAME}")
add_executable(${PROJECT_NAME})
target_sources(${PROJECT_NAME} PRIVATE cycle_test.c)
target_sources(${PROJECT_NAME} PRIVATE retarget.c)

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# add platform drivers
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/dispatch)
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
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/core)

# add platform drivers
target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/dispatch)
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
    target_include_directories(${PROJECT_NAME} PRIVATE ${TF_PSA_CRYPTO_ROOT}/legacy_sub/include)

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
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/aes.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/aesce.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/aesni.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/aria.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/bignum.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/bignum_core.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/bignum_mod.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/bignum_mod_raw.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/block_cipher.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/camellia.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/ccm.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/chacha20.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/chachapoly.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/cipher.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/cipher_wrap.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/cmac.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/ctr_drbg.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/des.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/ecdh.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/ecdsa.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/ecjpake.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/ecp.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/ecp_curves.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/ecp_curves_new.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/entropy.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/entropy_poll.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/gcm.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/hkdf.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/hmac_drbg.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/lmots.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/lms.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/md.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/md5.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/memory_buffer_alloc.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/nist_kw.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/pk.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/pk_ecc.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/pk_wrap.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/pkcs12.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/pkparse.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/pkwrite.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/platform.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/platform_util.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/poly1305.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/psa_crypto_aead.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/psa_crypto_cipher.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/psa_crypto_ecp.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/psa_crypto_ffdh.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/psa_crypto_hash.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/psa_crypto_mac.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/psa_crypto_pake.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/psa_crypto_rsa.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/psa_util.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/ripemd160.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/rsa.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/rsa_alt_helpers.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/sha1.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/sha256.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/sha3.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/sha512.c
        ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src/threading.c
        ${TF_PSA_CRYPTO_ROOT}/drivers/p256-m/p256-m/p256-m.c
        ${TF_PSA_CRYPTO_ROOT}/utilities/asn1parse.c
        ${TF_PSA_CRYPTO_ROOT}/utilities/asn1write.c
        ${TF_PSA_CRYPTO_ROOT}/utilities/base64.c
        ${TF_PSA_CRYPTO_ROOT}/utilities/constant_time.c
        ${TF_PSA_CRYPTO_ROOT}/utilities/oid.c
        ${TF_PSA_CRYPTO_ROOT}/utilities/pem.c
        ${TF_PSA_CRYPTO_ROOT}/utilities/pkcs5.c
    )

    target_sources(${PROJECT_NAME} PRIVATE 
        ${TF_Core_Sources} 
        ${TF_Driver_Sources}
        ${OBERON_PSA_DIR}/tests/cycles/tf-psa-crypto/psa_crypto_driver_wrappers_no_static.c
    )
    target_include_directories(${PROJECT_NAME} PRIVATE ${OBERON_PSA_DIR}/tests/cycles/tf-psa-crypto)
    target_include_directories(${PROJECT_NAME} PRIVATE ${TF_PSA_CRYPTO_ROOT}/core)
    target_include_directories(${PROJECT_NAME} PRIVATE ${TF_PSA_CRYPTO_ROOT}/legacy_sub/src)

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
