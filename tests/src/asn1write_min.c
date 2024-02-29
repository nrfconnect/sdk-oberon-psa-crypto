/*
 * ASN.1 buffer writing functionality
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * NOTICE: This file has been modified by Oberon microsystems AG.
 */

#include "common.h"

#if defined(MBEDTLS_ASN1_WRITE_C)

#include "mbedtls/asn1write.h"
#include "mbedtls/error.h"

#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

int mbedtls_asn1_write_len( unsigned char **p, const unsigned char *start, size_t len )
{
    if( len < 0x80 )
    {
        if( *p - start < 1 )
            return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = (unsigned char) len;
        return( 1 );
    }

    if( len <= 0xFF )
    {
        if( *p - start < 2 )
            return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = (unsigned char) len;
        *--(*p) = 0x81;
        return( 2 );
    }

    if( len <= 0xFFFF )
    {
        if( *p - start < 3 )
            return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = MBEDTLS_BYTE_0( len );
        *--(*p) = MBEDTLS_BYTE_1( len );
        *--(*p) = 0x82;
        return( 3 );
    }

    if( len <= 0xFFFFFF )
    {
        if( *p - start < 4 )
            return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = MBEDTLS_BYTE_0( len );
        *--(*p) = MBEDTLS_BYTE_1( len );
        *--(*p) = MBEDTLS_BYTE_2( len );
        *--(*p) = 0x83;
        return( 4 );
    }

#if SIZE_MAX > 0xFFFFFFFF
    if( len <= 0xFFFFFFFF )
#endif
    {
        if( *p - start < 5 )
            return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = MBEDTLS_BYTE_0( len );
        *--(*p) = MBEDTLS_BYTE_1( len );
        *--(*p) = MBEDTLS_BYTE_2( len );
        *--(*p) = MBEDTLS_BYTE_3( len );
        *--(*p) = 0x84;
        return( 5 );
    }

#if SIZE_MAX > 0xFFFFFFFF
    return( MBEDTLS_ERR_ASN1_INVALID_LENGTH );
#endif
}

int mbedtls_asn1_write_tag( unsigned char **p, const unsigned char *start, unsigned char tag )
{
    if( *p - start < 1 )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    *--(*p) = tag;

    return( 1 );
}

static int asn1_write_tagged_int( unsigned char **p, const unsigned char *start, int val, int tag )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    do
    {
        if( *p - start < 1 )
            return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );
        len += 1;
        *--(*p) = val & 0xff;
        val >>= 8;
    }
    while( val > 0 );

    if( **p & 0x80 )
    {
        if( *p - start < 1 )
            return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );
        *--(*p) = 0x00;
        len += 1;
    }

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, tag ) );

    return( (int) len );
}

int mbedtls_asn1_write_int( unsigned char **p, const unsigned char *start, int val )
{
    return( asn1_write_tagged_int( p, start, val, MBEDTLS_ASN1_INTEGER ) );
}

#endif /* MBEDTLS_ASN1_WRITE_C */
