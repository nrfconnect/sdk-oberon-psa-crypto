/*
 * ASN.1 buffer writing functionality
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "tf_psa_crypto_common.h"

#if defined(MBEDTLS_ASN1_WRITE_C) || defined(MBEDTLS_ASN1_PARSE_C) || \
    defined(PSA_HAVE_ALG_SOME_ECDSA)

#include "mbedtls/asn1write.h"
//#include "bignum_core.h"
#include "mbedtls/private/error_common.h"

#include <string.h>

#include "mbedtls/platform.h"

#if defined(MBEDTLS_ASN1_PARSE_C)
#include "mbedtls/asn1.h"
#endif

int mbedtls_asn1_write_len(unsigned char **p, const unsigned char *start, size_t len)
{
#if SIZE_MAX > 0xFFFFFFFF
    if (len > 0xFFFFFFFF) {
        return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
    }
#endif

    int required = 1;

    if (len >= 0x80) {
        for (size_t l = len; l != 0; l >>= 8) {
            required++;
        }
    }

    if (required > (*p - start)) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    do {
        *--(*p) = MBEDTLS_BYTE_0(len);
        len >>= 8;
    } while (len);

    if (required > 1) {
        *--(*p) = (unsigned char) (0x80 + required - 1);
    }

    return required;
}

int mbedtls_asn1_write_tag(unsigned char **p, const unsigned char *start, unsigned char tag)
{
    if (*p - start < 1) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    *--(*p) = tag;

    return 1;
}
#endif /* MBEDTLS_ASN1_WRITE_C || MBEDTLS_ASN1_PARSE_C || PSA_HAVE_ALG_SOME_ECDSA */

#if defined(MBEDTLS_ASN1_WRITE_C)
static int mbedtls_asn1_write_len_and_tag(unsigned char **p,
                                          const unsigned char *start,
                                          size_t len,
                                          unsigned char tag)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, tag));

    return (int) len;
}

int mbedtls_asn1_write_raw_buffer(unsigned char **p, const unsigned char *start,
                                  const unsigned char *buf, size_t size)
{
    size_t len = 0;

    if (*p < start || (size_t) (*p - start) < size) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    len = size;
    (*p) -= len;
    if (len != 0) {
        memcpy(*p, buf, len);
    }

    return (int) len;
}

int mbedtls_asn1_write_null(unsigned char **p, const unsigned char *start)
{
    // Write NULL
    //
    return mbedtls_asn1_write_len_and_tag(p, start, 0, MBEDTLS_ASN1_NULL);
}

int mbedtls_asn1_write_oid(unsigned char **p, const unsigned char *start,
                           const char *oid, size_t oid_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start,
                                                            (const unsigned char *) oid, oid_len));
    return mbedtls_asn1_write_len_and_tag(p, start, len, MBEDTLS_ASN1_OID);
}

int mbedtls_asn1_write_algorithm_identifier(unsigned char **p, const unsigned char *start,
                                            const char *oid, size_t oid_len,
                                            size_t par_len)
{
    return mbedtls_asn1_write_algorithm_identifier_ext(p, start, oid, oid_len, par_len, 1);
}

int mbedtls_asn1_write_algorithm_identifier_ext(unsigned char **p, const unsigned char *start,
                                                const char *oid, size_t oid_len,
                                                size_t par_len, int has_par)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    if (has_par) {
        if (par_len == 0) {
            MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_null(p, start));
        } else {
            len += par_len;
        }
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(p, start, oid, oid_len));

    return mbedtls_asn1_write_len_and_tag(p, start, len,
                                          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
}

int mbedtls_asn1_write_bool(unsigned char **p, const unsigned char *start, int boolean)
{
    size_t len = 0;

    if (*p - start < 1) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    *--(*p) = (boolean) ? 255 : 0;
    len++;

    return mbedtls_asn1_write_len_and_tag(p, start, len, MBEDTLS_ASN1_BOOLEAN);
}

static int asn1_write_tagged_int(unsigned char **p, const unsigned char *start, int val, int tag)
{
    size_t len = 0;

    do {
        if (*p - start < 1) {
            return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }
        len += 1;
        *--(*p) = val & 0xff;
        val >>= 8;
    } while (val > 0);

    if (**p & 0x80) {
        if (*p - start < 1) {
            return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }
        *--(*p) = 0x00;
        len += 1;
    }

    return mbedtls_asn1_write_len_and_tag(p, start, len, tag);
}

int mbedtls_asn1_write_int(unsigned char **p, const unsigned char *start, int val)
{
    return asn1_write_tagged_int(p, start, val, MBEDTLS_ASN1_INTEGER);
}

#endif /* MBEDTLS_ASN1_WRITE_C */
