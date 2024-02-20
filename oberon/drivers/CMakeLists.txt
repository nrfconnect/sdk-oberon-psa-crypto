cmake_minimum_required(VERSION 3.13)

set(OBERON_SOURCES
        oberon_aead.c
        oberon_aead.h
        oberon_asymmetric_encrypt.c
        oberon_asymmetric_encrypt.h
        oberon_asymmetric_signature.c
        oberon_asymmetric_signature.h
        oberon_cipher.c
        oberon_cipher.h
        oberon_config.h
        oberon_ctr_drbg.c
        oberon_ctr_drbg.h
        oberon_ecdh.c
        oberon_ecdh.h
        oberon_ecdsa.c
        oberon_ecdsa.h
        oberon_ec_keys.c
        oberon_ec_keys.h
        oberon_hash.c
        oberon_hash.h
        oberon_helpers.c
        oberon_helpers.h
        oberon_hmac_drbg.c
        oberon_hmac_drbg.h
        oberon_jpake.c
        oberon_jpake.h
        oberon_key_agreement.c
        oberon_key_agreement.h
        oberon_key_derivation.c
        oberon_key_derivation.h
        oberon_key_management.c
        oberon_key_management.h
        oberon_mac.c
        oberon_mac.h
        oberon_pake.c
        oberon_pake.h
        oberon_rsa.c
        oberon_rsa.h
        oberon_spake2p.c
        oberon_spake2p.h
        oberon_srp.c
        oberon_srp.h
)

target_sources(${PROJECT_NAME} PRIVATE ${OBERON_SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
