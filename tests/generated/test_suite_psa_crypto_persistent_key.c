#line 2 "suites/main_test.function"
/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script:
 * generate_test_code.py
 *
 * Test file      : ./test_suite_psa_crypto_persistent_key.c
 *
 * The following files were used to create this file.
 *
 *      Main code file      : tests/suites/main_test.function
 *      Platform code file  : tests/suites/host_test.function
 *      Helper file         : tests/suites/helpers.function
 *      Test suite file     : tests/suites/test_suite_psa_crypto_persistent_key.function
 *      Test suite data     : tests/suites/test_suite_psa_crypto_persistent_key.data
 *
 */

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L // for fileno() from <stdio.h>
#endif
#endif

/* On Mingw-w64, force the use of a C99-compliant printf() and friends.
 * This is necessary on older versions of Mingw and/or Windows runtimes
 * where snprintf does not always zero-terminate the buffer, and does
 * not support formats such as "%zu" for size_t and "%lld" for long long.
 */
#if !defined(__USE_MINGW_ANSI_STDIO)
#define __USE_MINGW_ANSI_STDIO 1
#endif

#include "mbedtls/build_info.h"

/* Test code may use deprecated identifiers only if the preprocessor symbol
 * MBEDTLS_TEST_DEPRECATED is defined. When building tests, set
 * MBEDTLS_TEST_DEPRECATED explicitly if MBEDTLS_DEPRECATED_WARNING is
 * enabled but the corresponding warnings are not treated as errors.
 */
#if !defined(MBEDTLS_DEPRECATED_REMOVED) && !defined(MBEDTLS_DEPRECATED_WARNING)
#define MBEDTLS_TEST_DEPRECATED
#endif

/*----------------------------------------------------------------------------*/
/* Common helper code */

#line 2 "suites/helpers.function"
/*----------------------------------------------------------------------------*/
/* Headers */

#include <test/arguments.h>
#include <test/helpers.h>
#include <test/macros.h>
#include <test/random.h>
#include <test/bignum_helpers.h>
#include <test/psa_crypto_helpers.h>
#include <test/threading_helpers.h>

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/private/error_common.h"
#include "mbedtls/platform.h"

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#endif

/*----------------------------------------------------------------------------*/
/* Status and error constants */

#define DEPENDENCY_SUPPORTED            0   /* Dependency supported by build */
#define KEY_VALUE_MAPPING_FOUND         0   /* Integer expression found */
#define DISPATCH_TEST_SUCCESS           0   /* Test dispatch successful */

#define KEY_VALUE_MAPPING_NOT_FOUND     -1  /* Integer expression not found */
#define DEPENDENCY_NOT_SUPPORTED        -2  /* Dependency not supported */
#define DISPATCH_TEST_FN_NOT_FOUND      -3  /* Test function not found */
#define DISPATCH_INVALID_TEST_DATA      -4  /* Invalid test parameter type.
                                               Only int, string, binary data
                                               and integer expressions are
                                               allowed */
#define DISPATCH_UNSUPPORTED_SUITE      -5  /* Test suite not supported by the
                                               build */

/*----------------------------------------------------------------------------*/
/* Global variables */

/*----------------------------------------------------------------------------*/
/* Helper flags for complex dependencies */


/*----------------------------------------------------------------------------*/
/* Helper Functions */

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
static int redirect_output(FILE *out_stream, const char *path)
{
    int out_fd, dup_fd;
    FILE *path_stream;

    out_fd = fileno(out_stream);
    dup_fd = dup(out_fd);

    if (dup_fd == -1) {
        return -1;
    }

    path_stream = fopen(path, "w");
    if (path_stream == NULL) {
        close(dup_fd);
        return -1;
    }

    fflush(out_stream);
    if (dup2(fileno(path_stream), out_fd) == -1) {
        close(dup_fd);
        fclose(path_stream);
        return -1;
    }

    fclose(path_stream);
    return dup_fd;
}

static int restore_output(FILE *out_stream, int dup_fd)
{
    int out_fd = fileno(out_stream);

    fflush(out_stream);
    if (dup2(dup_fd, out_fd) == -1) {
        close(out_fd);
        close(dup_fd);
        return -1;
    }

    close(dup_fd);
    return 0;
}
#endif /* __unix__ || __APPLE__ __MACH__ */


#line 52 "suites/main_test.function"


/*----------------------------------------------------------------------------*/
/* Test Suite Code */


#define TEST_SUITE_ACTIVE

#if defined(MBEDTLS_PSA_CRYPTO_C)
#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
#line 2 "tests/suites/test_suite_psa_crypto_persistent_key.function"

/* The tests in this module verify the contents of key store files. They
 * access internal key storage functions directly. Some of the tests depend
 * on the storage format. On the other hand, these tests treat the storage
 * subsystem as a black box, and in particular have no reliance on the
 * internals of the ITS implementation.
 *
 * Note that if you need to make a change that affects how files are
 * stored, this may indicate that the key store is changing in a
 * backward-incompatible way! Think carefully about backward compatibility
 * before changing how test data is constructed or validated.
 */

#include <stdint.h>

#include "mbedtls/private/ctr_drbg.h"
#include "psa_crypto_its.h"
#include "psa_crypto_slot_management.h"
#include "psa_crypto_storage.h"

#define KEY_ID_IN_USER_RANGE(id)                                        \
    (PSA_KEY_ID_USER_MIN <= (id) && (id) <= PSA_KEY_ID_USER_MAX)

#define KEY_ID_IN_VOLATILE_RANGE(id)                                    \
    (PSA_KEY_ID_VOLATILE_MIN <= (id) && (id) <= PSA_KEY_ID_VOLATILE_MAX)

#if defined(MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS)
#define KEY_ID_IN_BUILTIN_RANGE(id)                                     \
    (MBEDTLS_PSA_KEY_ID_BUILTIN_MIN <= (id) && (id) <= MBEDTLS_PSA_KEY_ID_BUILTIN_MAX)
#else
#define KEY_ID_IN_BUILTIN_RANGE(id) 0
#endif

/* Range of file UIDs reserved for uses other than storing a key.
 * Defined by the TF-PSA-Crypto storage specification
 * docs/architecture/mbed-crypto-storage-specification.md */
#define KEY_ID_IN_RESERVED_FILE_ID_RANGE(id) (0xffff0000 <= ((id) & 0xffffffff))

/* Define a key ID that is in none of the recognized ranges and not 0 */
#define KEY_ID_OUTSIDE_DEFINED_RANGES 0x7fffffffu

#define PSA_KEY_STORAGE_MAGIC_HEADER "PSA\0KEY"
#define PSA_KEY_STORAGE_MAGIC_HEADER_LENGTH (sizeof(PSA_KEY_STORAGE_MAGIC_HEADER))

/* Enforce the storage format for keys. The storage format is not a public
 * documented interface, but it must be preserved between versions so that
 * upgrades work smoothly, so it's a stable interface nonetheless.
 */
typedef struct {
    uint8_t magic[PSA_KEY_STORAGE_MAGIC_HEADER_LENGTH];
    uint8_t version[4];
    uint8_t lifetime[sizeof(psa_key_lifetime_t)];
    uint8_t type[4];
    uint8_t policy[sizeof(psa_key_policy_t)];
    uint8_t data_len[4];
    uint8_t key_data[];
} psa_persistent_key_storage_format;

const size_t persistent_key_payload_offset =
    offsetof(psa_persistent_key_storage_format, key_data);

#line 71 "tests/suites/test_suite_psa_crypto_persistent_key.function"
static void test_format_storage_data_check(data_t *key_data,
                               data_t *expected_file_data,
                               int key_lifetime, int key_type, int key_bits,
                               int key_usage, int key_alg, int key_alg2)
{
    uint8_t *file_data = NULL;
    size_t file_data_length =
        key_data->len + sizeof(psa_persistent_key_storage_format);
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_lifetime(&attributes, key_lifetime);
    psa_set_key_type(&attributes, key_type);
    psa_set_key_bits(&attributes, key_bits);
    psa_set_key_usage_flags(&attributes, key_usage);
    psa_set_key_algorithm(&attributes, key_alg);
    psa_set_key_enrollment_algorithm(&attributes, key_alg2);

#ifdef MBEDTLS_PSA_STATIC_KEY_SLOTS  /* !!OM */
    TEST_ASSUME(file_data_length <= MBEDTLS_PSA_STATIC_KEY_SLOT_BUFFER_SIZE - 16);
#endif
    TEST_CALLOC(file_data, file_data_length);
    psa_format_key_data_for_storage(key_data->x, key_data->len,
                                    &attributes,
                                    file_data);

    TEST_MEMORY_COMPARE(expected_file_data->x, expected_file_data->len,
                        file_data, file_data_length);

exit:
    mbedtls_free(file_data);
}

static void test_format_storage_data_check_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};
    data_t data2 = {(uint8_t *) params[2], ((mbedtls_test_argument_t *) params[3])->len};

    test_format_storage_data_check( &data0, &data2, ((mbedtls_test_argument_t *) params[4])->sint, ((mbedtls_test_argument_t *) params[5])->sint, ((mbedtls_test_argument_t *) params[6])->sint, ((mbedtls_test_argument_t *) params[7])->sint, ((mbedtls_test_argument_t *) params[8])->sint, ((mbedtls_test_argument_t *) params[9])->sint );
}
#line 102 "tests/suites/test_suite_psa_crypto_persistent_key.function"
static void test_parse_storage_data_check(data_t *file_data,
                              data_t *expected_key_data,
                              int expected_key_lifetime,
                              int expected_key_type,
                              int expected_key_bits,
                              int expected_key_usage,
                              int expected_key_alg,
                              int expected_key_alg2,
                              int expected_status)
{
    size_t key_data_length = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;

#ifdef MBEDTLS_PSA_STATIC_KEY_SLOTS  /* !!OM */
    uint8_t key_data[MBEDTLS_PSA_STATIC_KEY_SLOT_BUFFER_SIZE];
    status = psa_parse_key_data_from_storage_static(file_data->x, file_data->len,
                                                    key_data, &key_data_length,
                                                    &attributes);
#else
    uint8_t *key_data = NULL;
    status = psa_parse_key_data_from_storage(file_data->x, file_data->len,
                                             &key_data, &key_data_length,
                                             &attributes);
#endif

    TEST_EQUAL(status, expected_status);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    TEST_EQUAL(psa_get_key_lifetime(&attributes),
               (psa_key_type_t) expected_key_lifetime);
    TEST_EQUAL(psa_get_key_type(&attributes),
               (psa_key_type_t) expected_key_type);
    TEST_EQUAL(psa_get_key_bits(&attributes),
               (psa_key_bits_t) expected_key_bits);
    TEST_EQUAL(psa_get_key_usage_flags(&attributes),
               (uint32_t) expected_key_usage);
    TEST_EQUAL(psa_get_key_algorithm(&attributes),
               (uint32_t) expected_key_alg);
    TEST_EQUAL(psa_get_key_enrollment_algorithm(&attributes),
               (uint32_t) expected_key_alg2);
    TEST_MEMORY_COMPARE(expected_key_data->x, expected_key_data->len,
                        key_data, key_data_length);

exit:
#ifdef MBEDTLS_PSA_STATIC_KEY_SLOTS  /* !!OM */
    ;
#else
    mbedtls_free(key_data);
#endif
}

static void test_parse_storage_data_check_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};
    data_t data2 = {(uint8_t *) params[2], ((mbedtls_test_argument_t *) params[3])->len};

    test_parse_storage_data_check( &data0, &data2, ((mbedtls_test_argument_t *) params[4])->sint, ((mbedtls_test_argument_t *) params[5])->sint, ((mbedtls_test_argument_t *) params[6])->sint, ((mbedtls_test_argument_t *) params[7])->sint, ((mbedtls_test_argument_t *) params[8])->sint, ((mbedtls_test_argument_t *) params[9])->sint, ((mbedtls_test_argument_t *) params[10])->sint );
}
#line 147 "tests/suites/test_suite_psa_crypto_persistent_key.function"
static void test_key_id_ranges(void)
{
    /* PSA Crypto API specification */
    TEST_EQUAL(PSA_KEY_ID_NULL, 0x00000000);
    TEST_EQUAL(PSA_KEY_ID_USER_MIN, 0x00000001);
    TEST_EQUAL(PSA_KEY_ID_USER_MAX, 0x3fffffff);
    TEST_EQUAL(PSA_KEY_ID_VENDOR_MIN, 0x40000000);
    TEST_EQUAL(PSA_KEY_ID_VENDOR_MAX, 0x7fffffff);

    /* Volatile key IDs */
    TEST_LE_U(PSA_KEY_ID_VENDOR_MIN, PSA_KEY_ID_VOLATILE_MIN);
    TEST_LE_U(PSA_KEY_ID_VOLATILE_MAX, PSA_KEY_ID_VENDOR_MAX);
    TEST_LE_U(PSA_KEY_ID_VOLATILE_MIN, PSA_KEY_ID_VOLATILE_MAX);

    /* Built-in key IDs */
    /* Mbed TLS 2.27 reserved  0x7fff0000..0x7fffefff for built-in keys.
     * Integrators may have hard-coded built-in key IDs in this range,
     * so if this range starts conflicting with something else, it's
     * an incompatible change. */
#if defined(MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS)
    TEST_LE_U(MBEDTLS_PSA_KEY_ID_BUILTIN_MIN, 0x7fff0000);
    TEST_LE_U(MBEDTLS_PSA_KEY_ID_BUILTIN_MAX, 0x7fffefff);
    TEST_LE_U(PSA_KEY_ID_VENDOR_MIN, MBEDTLS_PSA_KEY_ID_BUILTIN_MIN);
    TEST_LE_U(MBEDTLS_PSA_KEY_ID_BUILTIN_MAX, PSA_KEY_ID_VENDOR_MAX);
#endif /* MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS */
    /* To avoid confusion, make sure we avoid the built-in key ID range
     * even in builds without built-in keys.. */
    if (PSA_KEY_ID_VOLATILE_MIN <= 0x7fff0000) {
        TEST_LE_U(PSA_KEY_ID_VOLATILE_MAX + 1, 0x7fff0000);
    } else {
        TEST_LE_U(0x7fffefff + 1, PSA_KEY_ID_VOLATILE_MIN);
    }

    /* Sanity check on test data */
    TEST_ASSERT(!KEY_ID_IN_USER_RANGE(KEY_ID_OUTSIDE_DEFINED_RANGES));
    TEST_ASSERT(!KEY_ID_IN_VOLATILE_RANGE(KEY_ID_OUTSIDE_DEFINED_RANGES));
    TEST_ASSERT(!KEY_ID_IN_BUILTIN_RANGE(KEY_ID_OUTSIDE_DEFINED_RANGES));
    TEST_ASSERT(!KEY_ID_IN_RESERVED_FILE_ID_RANGE(KEY_ID_OUTSIDE_DEFINED_RANGES));
exit:
    ;
}

static void test_key_id_ranges_wrapper( void ** params )
{
    (void)params;

    test_key_id_ranges(  );
}
#line 189 "tests/suites/test_suite_psa_crypto_persistent_key.function"
static void test_save_large_persistent_key(int data_length_arg, int expected_status)
{
    mbedtls_svc_key_id_t key_id = mbedtls_svc_key_id_make(1, 42);
    uint8_t *data = NULL;
    size_t data_length = data_length_arg;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

#ifdef MBEDTLS_PSA_STATIC_KEY_SLOTS  /* !!OM */
    TEST_ASSUME(data_length <= MBEDTLS_PSA_STATIC_KEY_SLOT_BUFFER_SIZE - 16);
#endif
    TEST_CALLOC(data, data_length);

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_id(&attributes, key_id);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RAW_DATA);

    TEST_EQUAL(psa_import_key(&attributes, data, data_length, &key_id),
               expected_status);

    if (expected_status == PSA_SUCCESS) {
        PSA_ASSERT(psa_destroy_key(key_id));
    }

exit:
    mbedtls_free(data);
    PSA_DONE();
    psa_destroy_persistent_key(key_id);
}

static void test_save_large_persistent_key_wrapper( void ** params )
{

    test_save_large_persistent_key( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint );
}
#line 218 "tests/suites/test_suite_psa_crypto_persistent_key.function"
static void test_persistent_key_destroy(int owner_id_arg, int key_id_arg, int restart,
                            int first_type_arg, data_t *first_data,
                            int second_type_arg, data_t *second_data)
{
    mbedtls_svc_key_id_t key_id =
        mbedtls_svc_key_id_make(owner_id_arg, key_id_arg);
    mbedtls_svc_key_id_t returned_key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_type_t first_type = (psa_key_type_t) first_type_arg;
    psa_key_type_t second_type = (psa_key_type_t) second_type_arg;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_id(&attributes, key_id);
    psa_set_key_type(&attributes, first_type);

    PSA_ASSERT(psa_import_key(&attributes, first_data->x, first_data->len,
                              &returned_key_id));

    if (restart) {
        psa_purge_key(key_id);
        PSA_DONE();
        PSA_ASSERT(psa_crypto_init());
    }
    TEST_EQUAL(psa_is_key_present_in_storage(key_id), 1);

    /* Destroy the key */
    PSA_ASSERT(psa_destroy_key(key_id));

    /* Check key slot storage is removed */
    TEST_EQUAL(psa_is_key_present_in_storage(key_id), 0);

    /* Shutdown and restart */
    PSA_DONE();
    PSA_ASSERT(psa_crypto_init());

    /* Create another key in the same slot */
    psa_set_key_id(&attributes, key_id);
    psa_set_key_type(&attributes, second_type);
    PSA_ASSERT(psa_import_key(&attributes, second_data->x, second_data->len,
                              &returned_key_id));

    PSA_ASSERT(psa_destroy_key(key_id));

exit:
    PSA_DONE();
    psa_destroy_persistent_key(key_id);
}

static void test_persistent_key_destroy_wrapper( void ** params )
{
    data_t data4 = {(uint8_t *) params[4], ((mbedtls_test_argument_t *) params[5])->len};
    data_t data7 = {(uint8_t *) params[7], ((mbedtls_test_argument_t *) params[8])->len};

    test_persistent_key_destroy( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, &data4, ((mbedtls_test_argument_t *) params[6])->sint, &data7 );
}
#line 269 "tests/suites/test_suite_psa_crypto_persistent_key.function"
static void test_persistent_key_import(int owner_id_arg, int key_id_arg, int type_arg,
                           data_t *data, int restart, int expected_status)
{
    mbedtls_svc_key_id_t key_id =
        mbedtls_svc_key_id_make(owner_id_arg, key_id_arg);
    mbedtls_svc_key_id_t returned_key_id;
    psa_key_type_t type = (psa_key_type_t) type_arg;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_id(&attributes, key_id);
    psa_set_key_type(&attributes, type);
    TEST_EQUAL(psa_import_key(&attributes, data->x, data->len, &returned_key_id),
               expected_status);

    if (expected_status != PSA_SUCCESS) {
        TEST_ASSERT(mbedtls_svc_key_id_is_null(returned_key_id));
        TEST_EQUAL(psa_is_key_present_in_storage(key_id), 0);
        goto exit;
    }

    TEST_ASSERT(mbedtls_svc_key_id_equal(returned_key_id, key_id));

    if (restart) {
        PSA_ASSERT(psa_purge_key(key_id));
        PSA_DONE();
        PSA_ASSERT(psa_crypto_init());
    }

    psa_reset_key_attributes(&attributes);
    PSA_ASSERT(psa_get_key_attributes(key_id, &attributes));
    TEST_ASSERT(mbedtls_svc_key_id_equal(psa_get_key_id(&attributes),
                                         key_id));
    TEST_EQUAL(psa_get_key_lifetime(&attributes),
               PSA_KEY_LIFETIME_PERSISTENT);
    TEST_EQUAL(psa_get_key_type(&attributes), type);
    TEST_EQUAL(psa_get_key_usage_flags(&attributes), 0);
    TEST_EQUAL(psa_get_key_algorithm(&attributes), 0);

    PSA_ASSERT(psa_destroy_key(key_id));

exit:
    /*
     * Key attributes may have been returned by psa_get_key_attributes()
     * thus reset them as required.
     */
    psa_reset_key_attributes(&attributes);

    psa_destroy_persistent_key(key_id);
    PSA_DONE();
}

static void test_persistent_key_import_wrapper( void ** params )
{
    data_t data3 = {(uint8_t *) params[3], ((mbedtls_test_argument_t *) params[4])->len};

    test_persistent_key_import( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, ((mbedtls_test_argument_t *) params[2])->sint, &data3, ((mbedtls_test_argument_t *) params[5])->sint, ((mbedtls_test_argument_t *) params[6])->sint );
}
#line 324 "tests/suites/test_suite_psa_crypto_persistent_key.function"
static void test_import_export_persistent_key(data_t *data, int type_arg,
                                  int expected_bits,
                                  int restart, int key_not_exist)
{
    mbedtls_svc_key_id_t key_id = mbedtls_svc_key_id_make(1, 42);
    psa_key_type_t type = (psa_key_type_t) type_arg;
    mbedtls_svc_key_id_t returned_key_id = MBEDTLS_SVC_KEY_ID_INIT;
    unsigned char *exported = NULL;
    size_t export_size = data->len;
    size_t exported_length;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

#ifdef MBEDTLS_PSA_STATIC_KEY_SLOTS  /* !!OM */
    TEST_ASSUME(export_size <= MBEDTLS_PSA_STATIC_KEY_SLOT_BUFFER_SIZE - 16);
#endif
    TEST_CALLOC(exported, export_size);

    PSA_ASSERT(psa_crypto_init());

    psa_set_key_id(&attributes, key_id);
    psa_set_key_type(&attributes, type);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);

    /* Import the key */
    PSA_ASSERT(psa_import_key(&attributes, data->x, data->len,
                              &returned_key_id));


    if (restart) {
        PSA_ASSERT(psa_purge_key(key_id));
        PSA_DONE();
        PSA_ASSERT(psa_crypto_init());
    }

    /* Test the key information */
    psa_reset_key_attributes(&attributes);
    PSA_ASSERT(psa_get_key_attributes(key_id, &attributes));
    TEST_ASSERT(mbedtls_svc_key_id_equal(
                    psa_get_key_id(&attributes), key_id));
    TEST_EQUAL(psa_get_key_lifetime(&attributes),
               PSA_KEY_LIFETIME_PERSISTENT);
    TEST_EQUAL(psa_get_key_type(&attributes), type);
    TEST_EQUAL(psa_get_key_bits(&attributes), (size_t) expected_bits);
    TEST_EQUAL(psa_get_key_usage_flags(&attributes), PSA_KEY_USAGE_EXPORT);
    TEST_EQUAL(psa_get_key_algorithm(&attributes), 0);

    TEST_EQUAL(psa_is_key_present_in_storage(key_id), 1);

    if (key_not_exist) {
        psa_destroy_persistent_key(key_id);
    }
    /* Export the key */
    PSA_ASSERT(psa_export_key(key_id, exported, export_size,
                              &exported_length));

    TEST_MEMORY_COMPARE(data->x, data->len, exported, exported_length);

    /* Destroy the key */
    PSA_ASSERT(psa_destroy_key(key_id));
    TEST_EQUAL(psa_is_key_present_in_storage(key_id), 0);

exit:
    /*
     * Key attributes may have been returned by psa_get_key_attributes()
     * thus reset them as required.
     */
    psa_reset_key_attributes(&attributes);

    mbedtls_free(exported);
    PSA_DONE();
    psa_destroy_persistent_key(key_id);
}

static void test_import_export_persistent_key_wrapper( void ** params )
{
    data_t data0 = {(uint8_t *) params[0], ((mbedtls_test_argument_t *) params[1])->len};

    test_import_export_persistent_key( &data0, ((mbedtls_test_argument_t *) params[2])->sint, ((mbedtls_test_argument_t *) params[3])->sint, ((mbedtls_test_argument_t *) params[4])->sint, ((mbedtls_test_argument_t *) params[5])->sint );
}
#line 396 "tests/suites/test_suite_psa_crypto_persistent_key.function"
static void test_destroy_nonexistent(int id_arg, int expected_status_arg)
{
    mbedtls_svc_key_id_t id = mbedtls_svc_key_id_make(1, id_arg);
    psa_status_t expected_status = expected_status_arg;

    PSA_INIT();

    TEST_EQUAL(expected_status, psa_destroy_key(id));

exit:
    PSA_DONE();
}

static void test_destroy_nonexistent_wrapper( void ** params )
{

    test_destroy_nonexistent( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint );
}
#line 411 "tests/suites/test_suite_psa_crypto_persistent_key.function"





static void test_load_primed_storage(int32_t owner_id,
                         int64_t key_id_arg,
                         data_t *content,
                         int expected_attributes_status_arg,
                         int expected_export_status_arg,
                         int expected_destroy_status_arg)
{
    mbedtls_svc_key_id_t key_id = mbedtls_svc_key_id_make(owner_id, key_id_arg);
    /* Storage UID (file name) for the given key ID, following the storage
     * specification. */
    psa_storage_uid_t uid = (uint64_t) owner_id << 32 | key_id_arg;
    psa_status_t expected_attributes_status = expected_attributes_status_arg;
    psa_status_t expected_export_status = expected_export_status_arg;
    psa_status_t expected_destroy_status = expected_destroy_status_arg;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t *key_data = NULL;
    struct psa_storage_info_t info;

    /* Sanity checks on the test data */
    /* The test framework doesn't support unsigned types, so check that
     * the key ID is in the actual valid range here. */
    TEST_LE_U(0, key_id_arg);
    TEST_LE_U(key_id_arg, 0xffffffff);
#if !defined(MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
    TEST_EQUAL(owner_id, 0);
#endif

    PSA_INIT();

    /* This is the start of the test case, so normally, no key exists.
     * The test data is based on the assumption that the key doesn't exist.
     * However, there are some cases where a key does exist:
     * - A volatile key used by the PSA RNG.
     * - A built-in key provided by the platform (in our test code:
     *   mbedtls_psa_platform_get_builtin_key() in platform_builtin_keys.c).
     * In such cases, we'll have different expectations.
     */
    int key_already_existed =
        psa_get_key_attributes(key_id, &attributes) == PSA_SUCCESS;
    if (key_already_existed) {
        expected_attributes_status = PSA_SUCCESS;
        expected_export_status =
            (psa_get_key_usage_flags(&attributes) & PSA_KEY_USAGE_EXPORT ?
             PSA_SUCCESS :
             PSA_KEY_TYPE_IS_PUBLIC_KEY(psa_get_key_type(&attributes)) ?
             PSA_SUCCESS :
             PSA_ERROR_NOT_PERMITTED);
    }
    /* In case this is a built-in key, psa_get_key_attributes()
     * loads it into the cache. Purge the cache to make sure the loading
     * code gets triggered. */
    psa_purge_key(key_id);

    /* Prime the storage. */
    psa_status_t file_status = psa_its_get_info(uid, &info);
    if (uid == 0) {
        /* 0 is not a valid file ID, according to the PSA secure storage
         * API specification. */
        if (file_status == PSA_ERROR_DOES_NOT_EXIST) {
            /* Our own partial storage implementation (psa_its_file.c)
             * is not compliant, it returns the wrong error code here.
             * That's not a problem, just let it go. */
        } else {
            TEST_EQUAL(file_status, PSA_ERROR_INVALID_ARGUMENT);
        }
    } else if (KEY_ID_IN_RESERVED_FILE_ID_RANGE(key_id_arg) &&
               file_status == PSA_SUCCESS) {
        /* The key ID corresponds to a reserved file (e.g. transaction
         * log or entropy seed). Don't corrupt that file. */
    } else {
        TEST_EQUAL(file_status, PSA_ERROR_DOES_NOT_EXIST);
        TEST_EQUAL(psa_its_set(uid, content->len, content->x, 0), PSA_SUCCESS);
    }

    /* Reading attributes should work for any valid key. */
    TEST_EQUAL(psa_get_key_attributes(key_id, &attributes),
               expected_attributes_status);
    if (expected_attributes_status == PSA_SUCCESS && !key_already_existed) {
        /* It's not our job here to validate the attributes, but do
         * sanity-check the attributes related to persistence. */
        TEST_ASSERT(mbedtls_svc_key_id_equal(key_id,
                                             psa_get_key_id(&attributes)));
        TEST_EQUAL(psa_get_key_lifetime(&attributes),
                   PSA_KEY_LIFETIME_PERSISTENT);
    }

    /* Extract the key material from the file.
     * We assume that the file uses the standard key representation in
     * storage, which is always the case at the time of writing.
     * If the file is truncated, there is no key material, and we just
     * declare an empty buffer here.
     */
    const uint8_t *payload = NULL;
    size_t payload_length = 0;
    if (content->len >= persistent_key_payload_offset) {
        payload = content->x + persistent_key_payload_offset;
        payload_length = content->len - persistent_key_payload_offset;
    }

    /* Exporting should work for a valid key that has export permission. */
    /* Allocate enough memory for the key data (assuming the key
     * representation in storage is not compressed compared to the
     * export format). */
    size_t key_data_size = content->len;
    size_t key_data_length = SIZE_MAX;
    TEST_CALLOC(key_data, key_data_size);
    TEST_EQUAL(psa_export_key(key_id,
                              key_data, key_data_size, &key_data_length),
               expected_export_status);
    if (expected_export_status == PSA_SUCCESS) {
        if (key_already_existed) {
            /* The key already existed. We don't know what it is,
             * but check that it is not what we put in storage. */
            TEST_ASSERT(key_data_length != payload_length ||
                        memcmp(key_data, payload, payload_length));
        } else {
            TEST_MEMORY_COMPARE(key_data, key_data_length,
                                payload, payload_length);
        }
    }
    /* Assert that the data length is sensible even if export failed.
     * This reduces the risk of memory corruption if an application
     * doesn't check the return status of export(). */
    TEST_LE_U(key_data_length, key_data_size);

    if (key_already_existed) {
        /* There was a key with the key ID under test, for example a key
         * used by the PSA RNG. Don't disrupt whatever is using that key.
         * Pure the key cache: this is necessary if the key was a built-in
         * key which got loaded into the cache by the get_attributes and
         * export calls above, otherwise PSA_DONE() would legitimately
         * complain about a non-empty cache.
         */
        psa_purge_key(key_id);
    } else {
        /* Destroying the key should work even for malformed content.
         * But it should not work for reserved file IDs. */
        TEST_EQUAL(psa_destroy_key(key_id), expected_destroy_status);
        if (uid == 0) {
            /* Invalid file UID. No point in asserting anything about the file. */
        } else if (expected_destroy_status == PSA_SUCCESS) {
            file_status = psa_its_get_info(uid, &info);
            if (key_id_arg == 0) {
                /* psa_destroy_key(0) is defined as a no-op, so it should not
                 * affect the file. */
                TEST_EQUAL(file_status, PSA_SUCCESS);
            } else {
                TEST_EQUAL(file_status, PSA_ERROR_DOES_NOT_EXIST);
            }
        }
    }

exit:
    psa_reset_key_attributes(&attributes);
    PSA_DONE();
    if (!KEY_ID_IN_RESERVED_FILE_ID_RANGE(key_id_arg)) {
        /* The key ID corresponds to a reserved file (e.g. transaction
         * log or entropy seed). Don't corrupt that file. */
        psa_its_remove(uid);
    }
    mbedtls_free(key_data);
}

static void test_load_primed_storage_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], ((mbedtls_test_argument_t *) params[3])->len};

    test_load_primed_storage( ((mbedtls_test_argument_t *) params[0])->sint, ((mbedtls_test_argument_t *) params[1])->sint, &data2, ((mbedtls_test_argument_t *) params[4])->sint, ((mbedtls_test_argument_t *) params[5])->sint, ((mbedtls_test_argument_t *) params[6])->sint );
}
#endif /* MBEDTLS_PSA_CRYPTO_STORAGE_C */
#endif /* MBEDTLS_PSA_CRYPTO_C */


#line 63 "suites/main_test.function"


/*----------------------------------------------------------------------------*/
/* Test dispatch code */


/**
 * \brief       Evaluates an expression/macro into its literal integer value.
 *              For optimizing space for embedded targets each expression/macro
 *              is identified by a unique identifier instead of string literals.
 *              Identifiers and evaluation code is generated by script:
 *              generate_test_code.py
 *
 * \param exp_id    Expression identifier.
 * \param out_value Pointer to int to hold the integer.
 *
 * \return       0 if exp_id is found. 1 otherwise.
 */
static int get_expression(int32_t exp_id, intmax_t *out_value)
{
    int ret = KEY_VALUE_MAPPING_FOUND;

    (void) exp_id;
    (void) out_value;

    switch (exp_id) {
    
#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)

        case 0:
            {
                *out_value = PSA_KEY_LIFETIME_PERSISTENT;
            }
            break;
        case 1:
            {
                *out_value = PSA_KEY_TYPE_RSA_KEY_PAIR;
            }
            break;
        case 2:
            {
                *out_value = PSA_KEY_USAGE_EXPORT;
            }
            break;
        case 3:
            {
                *out_value = PSA_ALG_CATEGORY_ASYMMETRIC_ENCRYPTION;
            }
            break;
        case 4:
            {
                *out_value = PSA_ALG_CATEGORY_SIGN;
            }
            break;
        case 5:
            {
                *out_value = PSA_KEY_TYPE_AES;
            }
            break;
        case 6:
            {
                *out_value = PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_ENCRYPT;
            }
            break;
        case 7:
            {
                *out_value = PSA_ALG_GCM;
            }
            break;
        case 8:
            {
                *out_value = PSA_SUCCESS;
            }
            break;
        case 9:
            {
                *out_value = PSA_ERROR_DATA_INVALID;
            }
            break;
        case 10:
            {
                *out_value = PSA_CRYPTO_MAX_STORAGE_SIZE;
            }
            break;
        case 11:
            {
                *out_value = PSA_CRYPTO_MAX_STORAGE_SIZE + 1;
            }
            break;
        case 12:
            {
                *out_value = PSA_ERROR_NOT_SUPPORTED;
            }
            break;
        case 13:
            {
                *out_value = PSA_KEY_TYPE_RAW_DATA;
            }
            break;
        case 14:
            {
                *out_value = PSA_KEY_ID_VENDOR_MIN;
            }
            break;
        case 15:
            {
                *out_value = PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        case 16:
            {
                *out_value = PSA_KEY_ID_VOLATILE_MIN;
            }
            break;
        case 17:
            {
                *out_value = PSA_KEY_ID_VENDOR_MAX;
            }
            break;
        case 18:
            {
                *out_value = PSA_KEY_TYPE_RSA_PUBLIC_KEY;
            }
            break;
        case 19:
            {
                *out_value = PSA_ERROR_INVALID_HANDLE;
            }
            break;
        case 20:
            {
                *out_value = 0xffffffff;
            }
            break;
        case 21:
            {
                *out_value = PSA_KEY_ID_USER_MIN;
            }
            break;
        case 22:
            {
                *out_value = PSA_KEY_ID_VOLATILE_MAX;
            }
            break;
        case 23:
            {
                *out_value = KEY_ID_OUTSIDE_DEFINED_RANGES;
            }
            break;
        case 24:
            {
                *out_value = 0xffff0000;
            }
            break;
        case 25:
            {
                *out_value = PSA_CRYPTO_ITS_RANDOM_SEED_UID;
            }
            break;
        case 26:
            {
                *out_value = 0 - 0x80000000;
            }
            break;
#endif

#line 91 "suites/main_test.function"
        default:
        {
            ret = KEY_VALUE_MAPPING_NOT_FOUND;
        }
        break;
    }
    return ret;
}


/**
 * \brief       Checks if the dependency i.e. the compile flag is set.
 *              For optimizing space for embedded targets each dependency
 *              is identified by a unique identifier instead of string literals.
 *              Identifiers and check code is generated by script:
 *              generate_test_code.py
 *
 * \param dep_id    Dependency identifier.
 *
 * \return       DEPENDENCY_SUPPORTED if set else DEPENDENCY_NOT_SUPPORTED
 */
static int dep_check(int dep_id)
{
    int ret = DEPENDENCY_NOT_SUPPORTED;

    (void) dep_id;

    switch (dep_id) {
    
#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)

        case 0:
            {
#if defined(MBEDTLS_PSA_ITS_FILE_C)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 1:
            {
#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 2:
            {
#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 3:
            {
#if defined(PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 4:
            {
#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 5:
            {
#if defined(PSA_WANT_KEY_TYPE_AES)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
        case 6:
            {
#if defined(MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
                ret = DEPENDENCY_SUPPORTED;
#else
                ret = DEPENDENCY_NOT_SUPPORTED;
#endif
            }
            break;
#endif

#line 121 "suites/main_test.function"
        default:
            break;
    }
    return ret;
}


/**
 * \brief       Function pointer type for test function wrappers.
 *
 * A test function wrapper decodes the parameters and passes them to the
 * underlying test function. Both the wrapper and the underlying function
 * return void. Test wrappers assume that they are passed a suitable
 * parameter array and do not perform any error detection.
 *
 * \param param_array   The array of parameters. Each element is a `void *`
 *                      which the wrapper casts to the correct type and
 *                      dereferences. Each wrapper function hard-codes the
 *                      number and types of the parameters.
 */
typedef void (*TestWrapper_t)(void **param_array);


/**
 * \brief       Table of test function wrappers. Used by dispatch_test().
 *              This table is populated by script:
 *              generate_test_code.py
 *
 */
TestWrapper_t test_funcs[] =
{
    /* Function Id: 0 */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    test_format_storage_data_check_wrapper,
#else
    NULL,
#endif
/* Function Id: 1 */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    test_parse_storage_data_check_wrapper,
#else
    NULL,
#endif
/* Function Id: 2 */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    test_key_id_ranges_wrapper,
#else
    NULL,
#endif
/* Function Id: 3 */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    test_save_large_persistent_key_wrapper,
#else
    NULL,
#endif
/* Function Id: 4 */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    test_persistent_key_destroy_wrapper,
#else
    NULL,
#endif
/* Function Id: 5 */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    test_persistent_key_import_wrapper,
#else
    NULL,
#endif
/* Function Id: 6 */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    test_import_export_persistent_key_wrapper,
#else
    NULL,
#endif
/* Function Id: 7 */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    test_destroy_nonexistent_wrapper,
#else
    NULL,
#endif
/* Function Id: 8 */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    test_load_primed_storage_wrapper,
#else
    NULL,
#endif

#line 154 "suites/main_test.function"
};

/**
 * \brief        Dispatches test functions based on function index.
 *
 * \param func_idx    Test function index.
 * \param params      The array of parameters to pass to the test function.
 *                    It will be decoded by the #TestWrapper_t wrapper function.
 *
 * \return       DISPATCH_TEST_SUCCESS if found
 *               DISPATCH_TEST_FN_NOT_FOUND if not found
 *               DISPATCH_UNSUPPORTED_SUITE if not compile time enabled.
 */
static int dispatch_test(size_t func_idx, void **params)
{
    int ret = DISPATCH_TEST_SUCCESS;
    TestWrapper_t fp = NULL;

    if (func_idx < (int) (sizeof(test_funcs) / sizeof(TestWrapper_t))) {
        fp = test_funcs[func_idx];
        if (fp) {
            #if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
            mbedtls_test_enable_insecure_external_rng();
            #endif

            fp(params);

            #if defined(MBEDTLS_TEST_MUTEX_USAGE)
            mbedtls_test_mutex_usage_check();
            #endif /* MBEDTLS_TEST_MUTEX_USAGE */
        } else {
            ret = DISPATCH_UNSUPPORTED_SUITE;
        }
    } else {
        ret = DISPATCH_TEST_FN_NOT_FOUND;
    }

    return ret;
}


/**
 * \brief       Checks if test function is supported in this build-time
 *              configuration.
 *
 * \param func_idx    Test function index.
 *
 * \return       DISPATCH_TEST_SUCCESS if found
 *               DISPATCH_TEST_FN_NOT_FOUND if not found
 *               DISPATCH_UNSUPPORTED_SUITE if not compile time enabled.
 */
static int check_test(size_t func_idx)
{
    int ret = DISPATCH_TEST_SUCCESS;
    TestWrapper_t fp = NULL;

    if (func_idx < (int) (sizeof(test_funcs)/sizeof(TestWrapper_t))) {
        fp = test_funcs[func_idx];
        if (fp == NULL) {
            ret = DISPATCH_UNSUPPORTED_SUITE;
        }
    } else {
        ret = DISPATCH_TEST_FN_NOT_FOUND;
    }

    return ret;
}


#line 2 "suites/host_test.function"

/**
 * \brief       Verifies that string is in string parameter format i.e. "<str>"
 *              It also strips enclosing '"' from the input string.
 *
 * \param str   String parameter.
 *
 * \return      0 if success else 1
 */
static int verify_string(char **str)
{
    if ((*str)[0] != '"' ||
        (*str)[strlen(*str) - 1] != '"') {
        mbedtls_fprintf(stderr,
                        "Expected string (with \"\") for parameter and got: %s\n", *str);
        return -1;
    }

    (*str)++;
    (*str)[strlen(*str) - 1] = '\0';

    return 0;
}

/**
 * \brief       Verifies that string is an integer. Also gives the converted
 *              integer value.
 *
 * \param str   Input string.
 * \param p_value Pointer to output value.
 *
 * \return      0 if success else 1
 */
static int verify_int(char *str, intmax_t *p_value)
{
    char *end = NULL;
    errno = 0;
    /* Limit the range to long: for large integers, the test framework will
     * use expressions anyway. */
    long value = strtol(str, &end, 0);
    if (errno == EINVAL || *end != '\0') {
        mbedtls_fprintf(stderr,
                        "Expected integer for parameter and got: %s\n", str);
        return KEY_VALUE_MAPPING_NOT_FOUND;
    }
    if (errno == ERANGE) {
        mbedtls_fprintf(stderr, "Integer out of range: %s\n", str);
        return KEY_VALUE_MAPPING_NOT_FOUND;
    }
    *p_value = value;
    return 0;
}


/**
 * \brief       Usage string.
 *
 */
#define USAGE \
    "Usage: %s [OPTIONS] files...\n\n" \
    "   Command line arguments:\n" \
    "     files...          One or more test data files. If no file is\n" \
    "                       specified the following default test case\n" \
    "                       file is used:\n" \
    "                           %s\n\n" \
    "   Options:\n" \
    "     -v | --verbose    Display full information about each test\n" \
    "     -h | --help       Display this information\n\n", \
    argv[0], \
    "TESTCASE_FILENAME"


/** A variable-size text buffer. */
typedef struct {
    /** Null-terminated string, or NULL if not allocated. */
    char *content;
    /** Number of allocated bytes. \c 0 if not allocated. */
    size_t size;
} string_buffer_t;

/**
 * \brief               Read a line from the passed file pointer.
 *                      Empty lines and comments are skipped.
 *
 * \param f             FILE pointer
 * \param buffer        Buffer for the line content.
 *                      It is filled with a null-terminated string.
 *
 * \return              The number of bytes of the resulting line, not
 *                      including the terminating null byte.
 *                      On end of file, (size_t) -1.
 */
static size_t get_line(FILE *f, string_buffer_t *buffer)
{
    char *ret = NULL;
    size_t offset = 0;
    size_t length = 0;
    int have_full_line = 0;

    /* Read until we get a valid line */
    do {
        ret = fgets(buffer->content + offset, buffer->size - offset, f);
        if (ret == NULL) {
            return (size_t) -1;
        }
        length = offset + strlen(buffer->content + offset);

        if (length == buffer->size - 1 && buffer->content[length - 1] != '\n') {
            /* Unfinished line. Enlarge the buffer. */
            /* We don't use realloc() because it may not be available
             * (e.g. MBEDTLS_MEMORY_BUFFER_ALLOC_C doesn't provide it). */
            size_t new_size = buffer->size * 2;
            char *new_buffer = mbedtls_calloc(1, new_size);
            if (new_buffer == NULL) {
                fprintf(stderr, "FATAL: failed to allocate %zu bytes\n", new_size);
                mbedtls_exit(MBEDTLS_EXIT_FAILURE);
            }
            memcpy(new_buffer, buffer->content, length);
            mbedtls_free(buffer->content);
            buffer->content = new_buffer;
            buffer->size = new_size;
            offset = length;
            continue;
        }

        /* Now we have a full line. */
        offset = 0;

        /* Strip new line and carriage return. */
        while (length > 0 && (buffer->content[length - 1] == '\n' ||
                              buffer->content[length - 1] == '\r')) {
            --length;
            buffer->content[length] = 0;
        }

        if (length == 0) {
            /* Skip empty line */
            continue;
        }
        if (buffer->content[0] == '#') {
            /* Skip comment line */
            continue;
        }
        have_full_line = 1;
    } while (!have_full_line);

    return length;
}

/**
 * \brief       Splits string delimited by ':'. Ignores '\:'.
 *
 * \param buf           Input string
 * \param len           Input string length
 * \param params        Out params found
 * \param params_len    Out params array len
 *
 * \return      Count of strings found.
 */
static int parse_arguments(char *buf, size_t len, char **params,
                           size_t params_len)
{
    size_t cnt = 0, i;
    char *cur = buf;
    char *p = buf, *q;

    params[cnt++] = cur;

    while (*p != '\0' && p < (buf + len)) {
        if (*p == '\\') {
            p++;
            p++;
            continue;
        }
        if (*p == ':') {
            if (p + 1 < buf + len) {
                cur = p + 1;
                TEST_HELPER_ASSERT(cnt < params_len);
                params[cnt++] = cur;
            }
            *p = '\0';
        }

        p++;
    }

    /* Replace backslash escapes in strings */
    for (i = 0; i < cnt; i++) {
        p = params[i];
        q = params[i];

        while (*p != '\0') {
            if (*p == '\\') {
                ++p;
                switch (*p) {
                    case 'n':
                        *p = '\n';
                        break;
                    default:
                        // Fall through to copying *p
                        break;
                }
            }
            *(q++) = *(p++);
        }
        *q = '\0';
    }

    return cnt;
}

/**
 * \brief       Converts parameters into test function consumable parameters.
 *              Example: Input:  {"int", "0", "char*", "Hello",
 *                                "hex", "abef", "exp", "1"}
 *                      Output:  {
 *                                0,                // Verified int
 *                                "Hello",          // Verified string
 *                                2, { 0xab, 0xef },// Converted len,hex pair
 *                                9600              // Evaluated expression
 *                               }
 *
 *
 * \param cnt               Parameter array count.
 * \param params            Out array of found parameters.
 * \param int_params_store  Memory for storing processed integer parameters.
 *
 * \return      0 for success else 1
 */
static int convert_params(size_t cnt, char **params,
                          mbedtls_test_argument_t *int_params_store)
{
    char **cur = params;
    char **out = params;
    int ret = DISPATCH_TEST_SUCCESS;

    while (cur < params + cnt) {
        char *type = *cur++;
        char *val = *cur++;

        if (strcmp(type, "char*") == 0) {
            if (verify_string(&val) == 0) {
                *out++ = val;
            } else {
                ret = (DISPATCH_INVALID_TEST_DATA);
                break;
            }
        } else if (strcmp(type, "int") == 0) {
            if (verify_int(val, &int_params_store->sint) == 0) {
                *out++ = (char *) int_params_store++;
            } else {
                ret = (DISPATCH_INVALID_TEST_DATA);
                break;
            }
        } else if (strcmp(type, "hex") == 0) {
            if (verify_string(&val) == 0) {
                size_t len;

                TEST_HELPER_ASSERT(
                    mbedtls_test_unhexify((unsigned char *) val, strlen(val),
                                          val, &len) == 0);

                int_params_store->len = len;
                *out++ = val;
                *out++ = (char *) (int_params_store++);
            } else {
                ret = (DISPATCH_INVALID_TEST_DATA);
                break;
            }
        } else if (strcmp(type, "exp") == 0) {
            int exp_id = strtol(val, NULL, 10);
            if (get_expression(exp_id, &int_params_store->sint) == 0) {
                *out++ = (char *) int_params_store++;
            } else {
                ret = (DISPATCH_INVALID_TEST_DATA);
                break;
            }
        } else {
            ret = (DISPATCH_INVALID_TEST_DATA);
            break;
        }
    }
    return ret;
}

/**
 * \brief       Tests snprintf implementation with test input.
 *
 * \note
 * At high optimization levels (e.g. gcc -O3), this function may be
 * inlined in run_test_snprintf. This can trigger a spurious warning about
 * potential misuse of snprintf from gcc -Wformat-truncation (observed with
 * gcc 7.2). This warning makes tests in run_test_snprintf redundant on gcc
 * only. They are still valid for other compilers. Avoid this warning by
 * forbidding inlining of this function by gcc.
 *
 * \param n         Buffer test length.
 * \param ref_buf   Expected buffer.
 * \param ref_ret   Expected snprintf return value.
 *
 * \return      0 for success else 1
 */
#if defined(__GNUC__)
#  if defined(__dietlibc__)
/* __noinline__ is a macro in dietlibc... */
__attribute__((noinline))
#  else
__attribute__((__noinline__))
#  endif
#endif
static int test_snprintf(size_t n, const char *ref_buf, int ref_ret)
{
    int ret;
    char buf[10] = "xxxxxxxxx";
    const char ref[10] = "xxxxxxxxx";

    if (n >= sizeof(buf)) {
        return -1;
    }
    ret = mbedtls_snprintf(buf, n, "%s", "123");
    if (ret < 0 || (size_t) ret >= n) {
        ret = -1;
    }

    if (strncmp(ref_buf, buf, sizeof(buf)) != 0 ||
        ref_ret != ret ||
        memcmp(buf + n, ref + n, sizeof(buf) - n) != 0) {
        return 1;
    }

    return 0;
}

/**
 * \brief       Tests snprintf implementation.
 *
 * \return      0 for success else 1
 */
static int run_test_snprintf(void)
{
    return test_snprintf(0, "xxxxxxxxx",  -1) != 0 ||
           test_snprintf(1, "",           -1) != 0 ||
           test_snprintf(2, "1",          -1) != 0 ||
           test_snprintf(3, "12",         -1) != 0 ||
           test_snprintf(4, "123",         3) != 0 ||
           test_snprintf(5, "123",         3) != 0;
}

/** \brief Write the description of the test case to the outcome CSV file.
 *
 * \param outcome_file  The file to write to.
 *                      If this is \c NULL, this function does nothing.
 * \param argv0         The test suite name.
 * \param test_case     The test case description.
 */
static void write_outcome_entry(FILE *outcome_file,
                                const char *argv0,
                                const char *test_case)
{
    /* The non-varying fields are initialized on first use. */
    static const char *platform = NULL;
    static const char *configuration = NULL;
    static const char *test_suite = NULL;

    if (outcome_file == NULL) {
        return;
    }

    if (platform == NULL) {
        platform = getenv("MBEDTLS_TEST_PLATFORM");
        if (platform == NULL) {
            platform = "unknown";
        }
    }
    if (configuration == NULL) {
        configuration = getenv("MBEDTLS_TEST_CONFIGURATION");
        if (configuration == NULL) {
            configuration = "unknown";
        }
    }
    if (test_suite == NULL) {
        test_suite = strrchr(argv0, '/');
        if (test_suite != NULL) {
            test_suite += 1; // skip the '/'
        } else {
            test_suite = argv0;
        }
    }

    /* Write the beginning of the outcome line.
     * Ignore errors: writing the outcome file is on a best-effort basis. */
    mbedtls_fprintf(outcome_file, "%s;%s;%s;%s;",
                    platform, configuration, test_suite, test_case);
}

/** \brief Write the result of the test case to the outcome CSV file.
 *
 * \param outcome_file  The file to write to.
 *                      If this is \c NULL, this function does nothing.
 * \param unmet_dep_count            The number of unmet dependencies.
 * \param unmet_dependencies         The array of unmet dependencies.
 * \param missing_unmet_dependencies Non-zero if there was a problem tracking
 *                                   all unmet dependencies, 0 otherwise.
 * \param ret                        The test dispatch status (DISPATCH_xxx).
 */
static void write_outcome_result(FILE *outcome_file,
                                 size_t unmet_dep_count,
                                 int unmet_dependencies[],
                                 int missing_unmet_dependencies,
                                 int ret)
{
    if (outcome_file == NULL) {
        return;
    }

    /* Write the end of the outcome line.
     * Ignore errors: writing the outcome file is on a best-effort basis. */
    switch (ret) {
        case DISPATCH_TEST_SUCCESS:
            if (unmet_dep_count > 0) {
                size_t i;
                mbedtls_fprintf(outcome_file, "SKIP");
                for (i = 0; i < unmet_dep_count; i++) {
                    mbedtls_fprintf(outcome_file, "%c%d",
                                    i == 0 ? ';' : ':',
                                    unmet_dependencies[i]);
                }
                if (missing_unmet_dependencies) {
                    mbedtls_fprintf(outcome_file, ":...");
                }
                break;
            }
            switch (mbedtls_test_get_result()) {
                case MBEDTLS_TEST_RESULT_SUCCESS:
                    mbedtls_fprintf(outcome_file, "PASS;");
                    break;
                case MBEDTLS_TEST_RESULT_SKIPPED:
                    mbedtls_fprintf(outcome_file, "SKIP;Runtime skip");
                    break;
                default:
                    mbedtls_fprintf(outcome_file, "FAIL;%s:%d:%s",
                                    mbedtls_get_test_filename(),
                                    mbedtls_test_get_line_no(),
                                    mbedtls_test_get_test());
                    break;
            }
            break;
        case DISPATCH_TEST_FN_NOT_FOUND:
            mbedtls_fprintf(outcome_file, "FAIL;Test function not found");
            break;
        case DISPATCH_INVALID_TEST_DATA:
            mbedtls_fprintf(outcome_file, "FAIL;Invalid test data");
            break;
        case DISPATCH_UNSUPPORTED_SUITE:
            mbedtls_fprintf(outcome_file, "SKIP;Unsupported suite");
            break;
        default:
            mbedtls_fprintf(outcome_file, "FAIL;Unknown cause");
            break;
    }
    mbedtls_fprintf(outcome_file, "\n");
    fflush(outcome_file);
}

#if defined(__unix__) ||                                \
    (defined(__APPLE__) && defined(__MACH__))
#define MBEDTLS_HAVE_CHDIR
#endif

#if defined(MBEDTLS_HAVE_CHDIR)
/** Try chdir to the directory containing argv0.
 *
 * Failures are silent.
 */
static void try_chdir_if_supported(const char *argv0)
{
    /* We might want to allow backslash as well, for Windows. But then we also
     * need to consider chdir() vs _chdir(), and different conventions
     * regarding paths in argv[0] (naively enabling this code with
     * backslash support on Windows leads to chdir into the wrong directory
     * on the CI). */
    const char *slash = strrchr(argv0, '/');
    if (slash == NULL) {
        return;
    }
    size_t path_size = slash - argv0 + 1;
    char *path = mbedtls_calloc(1, path_size);
    if (path == NULL) {
        return;
    }
    memcpy(path, argv0, path_size - 1);
    path[path_size - 1] = 0;
    int ret = chdir(path);
    if (ret != 0) {
        mbedtls_fprintf(stderr, "%s: note: chdir(\"%s\") failed.\n",
                        __func__, path);
    }
    mbedtls_free(path);
}
#else /* MBEDTLS_HAVE_CHDIR */
/* No chdir() or no support for parsing argv[0] on this platform. */
static void try_chdir_if_supported(const char *argv0)
{
    (void) argv0;
    return;
}
#endif /* MBEDTLS_HAVE_CHDIR */

/**
 * \brief       Desktop implementation of execute_tests().
 *              Parses command line and executes tests from
 *              supplied or default data file.
 *
 * \param argc  Command line argument count.
 * \param argv  Argument array.
 *
 * \return      Program exit status.
 */
static int execute_tests(int argc, const char **argv)
{
    /* Local Configurations and options */
    const char *default_filename = "./test_suite_psa_crypto_persistent_key.datax";
    const char *test_filename = NULL;
    const char **test_files = NULL;
    size_t testfile_count = 0;
    int option_verbose = 0;
    size_t function_id = 0;

    /* Other Local variables */
    int arg_index = 1;
    const char *next_arg;
    size_t testfile_index, i, cnt;
    unsigned total_errors = 0, total_tests = 0, total_skipped = 0;
    FILE *file;
    string_buffer_t line = { NULL, 0 };
    char *params[50];
    /* Store for processed integer params. */
    mbedtls_test_argument_t int_params[50];
    void *pointer;
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
    int stdout_fd = -1;
#endif /* __unix__ || __APPLE__ __MACH__ */
    const char *outcome_file_name = getenv("MBEDTLS_TEST_OUTCOME_FILE");
    FILE *outcome_file = NULL;

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
    unsigned char alloc_buf[1000000];
    mbedtls_memory_buffer_alloc_init(alloc_buf, sizeof(alloc_buf));
#endif

#if defined(MBEDTLS_TEST_MUTEX_USAGE)
    mbedtls_test_mutex_usage_init();
#endif

    /*
     * The C standard doesn't guarantee that all-bits-0 is the representation
     * of a NULL pointer. We do however use that in our code for initializing
     * structures, which should work on every modern platform. Let's be sure.
     */
    memset(&pointer, 0, sizeof(void *));
    if (pointer != NULL) {
        mbedtls_fprintf(stderr, "all-bits-zero is not a NULL pointer\n");
        return 1;
    }

    /*
     * Make sure we have a snprintf that correctly zero-terminates
     */
    if (run_test_snprintf() != 0) {
        mbedtls_fprintf(stderr, "the snprintf implementation is broken\n");
        return 1;
    }

    if (outcome_file_name != NULL && *outcome_file_name != '\0') {
        outcome_file = fopen(outcome_file_name, "a");
        if (outcome_file == NULL) {
            mbedtls_fprintf(stderr, "Unable to open outcome file. Continuing anyway.\n");
        }
    }

    line.size = 256;
    line.content = mbedtls_calloc(1, line.size);
    if (line.content == NULL) {
        fprintf(stderr, "FATAL: failed to allocate %zu bytes\n", line.size);
        mbedtls_exit(MBEDTLS_EXIT_FAILURE);
    }

    while (arg_index < argc) {
        next_arg = argv[arg_index];

        if (strcmp(next_arg, "--verbose") == 0 ||
            strcmp(next_arg, "-v") == 0) {
            option_verbose = 1;
        } else if (strcmp(next_arg, "--help") == 0 ||
                   strcmp(next_arg, "-h") == 0) {
            mbedtls_fprintf(stdout, USAGE);
            mbedtls_exit(EXIT_SUCCESS);
        } else {
            /* Not an option, therefore treat all further arguments as the file
             * list.
             */
            test_files = &argv[arg_index];
            testfile_count = argc - arg_index;
            break;
        }

        arg_index++;
    }

    /* If no files were specified, assume a default */
    if (test_files == NULL || testfile_count == 0) {
        test_files = &default_filename;
        testfile_count = 1;
    }

    /* Initialize the struct that holds information about the last test */
    mbedtls_test_info_reset();

    /* Now begin to execute the tests in the testfiles */
    for (testfile_index = 0;
         testfile_index < testfile_count;
         testfile_index++) {
        size_t unmet_dep_count = 0;
        int unmet_dependencies[20];
        int missing_unmet_dependencies = 0;

        test_filename = test_files[testfile_index];

        file = fopen(test_filename, "r");
        if (file == NULL) {
            mbedtls_fprintf(stderr, "Failed to open test file: %s\n",
                            test_filename);
            if (outcome_file != NULL) {
                fclose(outcome_file);
            }
            return 1;
        }

        while (!feof(file)) {
            if (unmet_dep_count > 0) {
                mbedtls_fprintf(stderr,
                                "FATAL: Dep count larger than zero at start of loop\n");
                mbedtls_exit(MBEDTLS_EXIT_FAILURE);
            }
            unmet_dep_count = 0;
            missing_unmet_dependencies = 0;

            size_t length = get_line(file, &line);
            if (length == (size_t) -1) {
                break;
            }
            mbedtls_fprintf(stdout, "%s%.66s",
                            mbedtls_test_get_result() == MBEDTLS_TEST_RESULT_FAILED ?
                            "\n" : "", line.content);
            mbedtls_fprintf(stdout, " ");
            for (i = length + 1; i < 67; i++) {
                mbedtls_fprintf(stdout, ".");
            }
            mbedtls_fprintf(stdout, " ");
            fflush(stdout);
            write_outcome_entry(outcome_file, argv[0], line.content);

            total_tests++;

            length = get_line(file, &line);
            if (length == (size_t) -1) {
                break;
            }
            cnt = parse_arguments(line.content, length, params,
                                  sizeof(params) / sizeof(params[0]));

            if (strcmp(params[0], "depends_on") == 0) {
                for (i = 1; i < cnt; i++) {
                    int dep_id = strtol(params[i], NULL, 10);
                    if (dep_check(dep_id) != DEPENDENCY_SUPPORTED) {
                        if (unmet_dep_count <
                            ARRAY_LENGTH(unmet_dependencies)) {
                            unmet_dependencies[unmet_dep_count] = dep_id;
                            unmet_dep_count++;
                        } else {
                            missing_unmet_dependencies = 1;
                        }
                    }
                }

                length = get_line(file, &line);
                if (length == (size_t) -1) {
                    break;
                }
                cnt = parse_arguments(line.content, length, params,
                                      sizeof(params) / sizeof(params[0]));
            }

            // If there are no unmet dependencies execute the test
            int ret = DISPATCH_TEST_SUCCESS; /*also covers test case skip*/
            if (unmet_dep_count == 0) {
                mbedtls_test_info_reset();

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
                /* Suppress all output from the library unless we're verbose
                 * mode
                 */
                if (!option_verbose) {
                    stdout_fd = redirect_output(stdout, "/dev/null");
                    if (stdout_fd == -1) {
                        /* Redirection has failed with no stdout so exit */
                        exit(1);
                    }
                }
#endif /* __unix__ || __APPLE__ __MACH__ */

                function_id = strtoul(params[0], NULL, 10);
                ret = check_test(function_id);
                if (ret == DISPATCH_TEST_SUCCESS) {
                    ret = convert_params(cnt - 1, params + 1, int_params);
                    if (DISPATCH_TEST_SUCCESS == ret) {
                        ret = dispatch_test(function_id, (void **) (params + 1));
                    }
                }

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
                if (!option_verbose && restore_output(stdout, stdout_fd)) {
                    /* Redirection has failed with no stdout so exit */
                    exit(1);
                }
#endif /* __unix__ || __APPLE__ __MACH__ */

            }

            write_outcome_result(outcome_file,
                                 unmet_dep_count, unmet_dependencies,
                                 missing_unmet_dependencies,
                                 ret);
            if (unmet_dep_count > 0 || ret == DISPATCH_UNSUPPORTED_SUITE) {
                total_skipped++;
                mbedtls_fprintf(stdout, "----");

                if (1 == option_verbose && ret == DISPATCH_UNSUPPORTED_SUITE) {
                    mbedtls_fprintf(stdout, "\n   Test Suite not enabled");
                }

                if (1 == option_verbose && unmet_dep_count > 0) {
                    mbedtls_fprintf(stdout, "\n   Unmet dependencies: ");
                    for (i = 0; i < unmet_dep_count; i++) {
                        mbedtls_fprintf(stdout, "%d ",
                                        unmet_dependencies[i]);
                    }
                    if (missing_unmet_dependencies) {
                        mbedtls_fprintf(stdout, "...");
                    }
                }
                mbedtls_fprintf(stdout, "\n");
                fflush(stdout);

                unmet_dep_count = 0;
                missing_unmet_dependencies = 0;
            } else if (ret == DISPATCH_TEST_SUCCESS) {
                if (mbedtls_test_get_result() == MBEDTLS_TEST_RESULT_SUCCESS) {
                    mbedtls_fprintf(stdout, "PASS\n");
                } else if (mbedtls_test_get_result() == MBEDTLS_TEST_RESULT_SKIPPED) {
                    mbedtls_fprintf(stdout, "----\n");
                    total_skipped++;
                } else {
                    char line_buffer[MBEDTLS_TEST_LINE_LENGTH];

                    total_errors++;
                    mbedtls_fprintf(stdout, "FAILED\n");
                    mbedtls_fprintf(stdout, "  %s\n  at ",
                                    mbedtls_test_get_test());
                    if (mbedtls_test_get_step() != (unsigned long) (-1)) {
                        mbedtls_fprintf(stdout, "step %lu, ",
                                        mbedtls_test_get_step());
                    }
                    mbedtls_fprintf(stdout, "line %d, %s",
                                    mbedtls_test_get_line_no(),
                                    mbedtls_get_test_filename());

                    mbedtls_test_get_line1(line_buffer);
                    if (line_buffer[0] != 0) {
                        mbedtls_fprintf(stdout, "\n  %s", line_buffer);
                    }
                    mbedtls_test_get_line2(line_buffer);
                    if (line_buffer[0] != 0) {
                        mbedtls_fprintf(stdout, "\n  %s", line_buffer);
                    }
                }
                fflush(stdout);
            } else if (ret == DISPATCH_INVALID_TEST_DATA) {
                mbedtls_fprintf(stderr, "FAILED: FATAL PARSE ERROR\n");
                fclose(file);
                mbedtls_exit(2);
            } else if (ret == DISPATCH_TEST_FN_NOT_FOUND) {
                mbedtls_fprintf(stderr, "FAILED: FATAL TEST FUNCTION NOT FOUND\n");
                fclose(file);
                mbedtls_exit(2);
            } else {
                total_errors++;
            }
        }
        fclose(file);
    }

    if (outcome_file != NULL) {
        fclose(outcome_file);
    }

    mbedtls_fprintf(stdout,
                    "\n----------------------------------------------------------------------------\n\n");
    if (total_errors == 0) {
        mbedtls_fprintf(stdout, "PASSED");
    } else {
        mbedtls_fprintf(stdout, "FAILED");
    }

    mbedtls_fprintf(stdout, " (%u / %u tests (%u skipped))\n",
                    total_tests - total_errors, total_tests, total_skipped);

#if defined(MBEDTLS_TEST_MUTEX_USAGE)
    mbedtls_test_mutex_usage_end();
#endif

    mbedtls_free(line.content);

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
#if defined(MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_status();
#endif
    mbedtls_memory_buffer_alloc_free();
#endif

    return total_errors != 0;
}


#line 226 "suites/main_test.function"

/*----------------------------------------------------------------------------*/
/* Main Test code */


/**
 * \brief       Program main. Invokes platform specific execute_tests().
 *
 * \param argc      Command line arguments count.
 * \param argv      Array of command line arguments.
 *
 * \return       Exit code.
 */
int main(int argc, const char *argv[])
{
#if defined(MBEDTLS_TEST_HOOKS)
    extern void (*mbedtls_test_hook_test_fail)(const char *test, int line, const char *file);
    mbedtls_test_hook_test_fail = &mbedtls_test_fail;
#endif

    /* Try changing to the directory containing the executable, if
     * using the default data file. This allows running the executable
     * from another directory (e.g. the project root) and still access
     * the .datax file as well as data files used by test cases
     * (typically from framework/data_files).
     *
     * Note that we do this before the platform setup (which may access
     * files such as a random seed). We also do this before accessing
     * test-specific files such as the outcome file, which is arguably
     * not desirable and should be fixed later.
     */
    if (argc == 1) {
        try_chdir_if_supported(argv[0]);
    }

    int ret = mbedtls_test_platform_setup();
    if (ret != 0) {
        mbedtls_fprintf(stderr,
                        "FATAL: Failed to initialize platform - error %d\n",
                        ret);
        return -1;
    }

    ret = execute_tests(argc, argv);
    mbedtls_test_platform_teardown();
    return ret;
}
