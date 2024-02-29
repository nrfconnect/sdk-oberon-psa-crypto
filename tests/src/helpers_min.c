/*
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

#include <test/helpers.h>
#include <test/macros.h>
#include <string.h>

/*----------------------------------------------------------------------------*/
/* Static global variables */

#if defined(MBEDTLS_PLATFORM_C)
static mbedtls_platform_context platform_ctx;
#endif

mbedtls_test_info_t mbedtls_test_info;

/*----------------------------------------------------------------------------*/
/* Helper Functions */

int mbedtls_test_platform_setup( void )
{
    int ret = 0;
#if defined(MBEDTLS_PLATFORM_C)
    ret = mbedtls_platform_setup( &platform_ctx );
#endif /* MBEDTLS_PLATFORM_C */
    return( ret );
}

void mbedtls_test_platform_teardown( void )
{
#if defined(MBEDTLS_PLATFORM_C)
    mbedtls_platform_teardown( &platform_ctx );
#endif /* MBEDTLS_PLATFORM_C */
}

static int ascii2uc(const char c, unsigned char *uc)
{
    if( ( c >= '0' ) && ( c <= '9' ) )
        *uc = c - '0';
    else if( ( c >= 'a' ) && ( c <= 'f' ) )
        *uc = c - 'a' + 10;
    else if( ( c >= 'A' ) && ( c <= 'F' ) )
        *uc = c - 'A' + 10;
    else
        return( -1 );

    return( 0 );
}

void mbedtls_test_fail( const char *test, int line_no, const char* filename )
{
    if( mbedtls_test_info.result == MBEDTLS_TEST_RESULT_FAILED )
    {
        /* We've already recorded the test as having failed. Don't
         * overwrite any previous information about the failure. */
        return;
    }
    mbedtls_test_info.result = MBEDTLS_TEST_RESULT_FAILED;
    mbedtls_test_info.test = test;
    mbedtls_test_info.line_no = line_no;
    mbedtls_test_info.filename = filename;
}

void mbedtls_test_skip( const char *test, int line_no, const char* filename )
{
    mbedtls_test_info.result = MBEDTLS_TEST_RESULT_SKIPPED;
    mbedtls_test_info.test = test;
    mbedtls_test_info.line_no = line_no;
    mbedtls_test_info.filename = filename;
}

void mbedtls_test_set_step( unsigned long step )
{
    mbedtls_test_info.step = step;
}

void mbedtls_test_info_reset( void )
{
    mbedtls_test_info.result = MBEDTLS_TEST_RESULT_SUCCESS;
    mbedtls_test_info.step = (unsigned long)( -1 );
    mbedtls_test_info.test = 0;
    mbedtls_test_info.line_no = 0;
    mbedtls_test_info.filename = 0;
    memset( mbedtls_test_info.line1, 0, sizeof( mbedtls_test_info.line1 ) );
    memset( mbedtls_test_info.line2, 0, sizeof( mbedtls_test_info.line2 ) );
}

int mbedtls_test_equal( const char *test, int line_no, const char* filename,
                        unsigned long long value1, unsigned long long value2 )
{
    if( value1 == value2 )
        return( 1 );
    if( mbedtls_test_info.result == MBEDTLS_TEST_RESULT_FAILED )
    {
        /* We've already recorded the test as having failed. Don't
         * overwrite any previous information about the failure. */
        return( 0 );
    }
    mbedtls_test_fail( test, line_no, filename );
    (void) mbedtls_snprintf( mbedtls_test_info.line1,
                             sizeof( mbedtls_test_info.line1 ),
                             "lhs = 0x%016llx = %lld",
                             value1, (long long) value1 );
    (void) mbedtls_snprintf( mbedtls_test_info.line2,
                             sizeof( mbedtls_test_info.line2 ),
                             "rhs = 0x%016llx = %lld",
                             value2, (long long) value2 );
    return( 0 );
}

int mbedtls_test_le_u( const char *test, int line_no, const char* filename,
                       unsigned long long value1, unsigned long long value2 )
{
    if( value1 <= value2 )
        return( 1 );
    if( mbedtls_test_info.result == MBEDTLS_TEST_RESULT_FAILED )
    {
        /* We've already recorded the test as having failed. Don't
         * overwrite any previous information about the failure. */
        return( 0 );
    }
    mbedtls_test_fail( test, line_no, filename );
    (void) mbedtls_snprintf( mbedtls_test_info.line1,
                             sizeof( mbedtls_test_info.line1 ),
                             "lhs = 0x%016llx = %llu",
                             value1, value1 );
    (void) mbedtls_snprintf( mbedtls_test_info.line2,
                             sizeof( mbedtls_test_info.line2 ),
                             "rhs = 0x%016llx = %llu",
                             value2, value2 );
    return( 0 );
}

int mbedtls_test_unhexify( unsigned char *obuf,
                           size_t obufmax,
                           const char *ibuf,
                           size_t *len )
{
    unsigned char uc, uc2;

    *len = strlen( ibuf );

    /* Must be even number of bytes. */
    if ( ( *len ) & 1 )
        return( -1 );
    *len /= 2;

    if ( (*len) > obufmax )
        return( -1 );

    while( *ibuf != 0 )
    {
        if ( ascii2uc( *(ibuf++), &uc ) != 0 )
            return( -1 );

        if ( ascii2uc( *(ibuf++), &uc2 ) != 0 )
            return( -1 );

        *(obuf++) = ( uc << 4 ) | uc2;
    }

    return( 0 );
}
