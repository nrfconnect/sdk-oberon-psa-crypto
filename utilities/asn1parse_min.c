/*
 *  Generic ASN.1 parsing
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "tf_psa_crypto_common.h"

#if defined(MBEDTLS_ASN1_PARSE_C) || defined(MBEDTLS_ASN1_WRITE_C) || \
    defined(PSA_HAVE_ALG_SOME_ECDSA)

#include "mbedtls/asn1.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/private/error_common.h"

#include <string.h>

#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/private/bignum.h"
#endif

#include "mbedtls/platform.h"

/*
 * ASN.1 DER decoding routines
 */
int mbedtls_asn1_get_len(unsigned char **p,
                         const unsigned char *end,
                         size_t *len)
{
    if ((end - *p) < 1) {
        return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
    }

    if ((**p & 0x80) == 0) {
        *len = *(*p)++;
    } else {
        int n = (**p) & 0x7F;
        if (n == 0 || n > 4) {
            return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
        }
        if ((end - *p) <= n) {
            return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
        }
        *len = 0;
        (*p)++;
        while (n--) {
            *len = (*len << 8) | **p;
            (*p)++;
        }
    }

    if (*len > (size_t) (end - *p)) {
        return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
    }

    return 0;
}

int mbedtls_asn1_get_tag(unsigned char **p,
                         const unsigned char *end,
                         size_t *len, int tag)
{
    if ((end - *p) < 1) {
        return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
    }

    if (**p != tag) {
        return MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
    }

    (*p)++;

    return mbedtls_asn1_get_len(p, end, len);
}
#endif /* MBEDTLS_ASN1_PARSE_C || MBEDTLS_ASN1_WRITE_C || PSA_HAVE_ALG_SOME_ECDSA */
