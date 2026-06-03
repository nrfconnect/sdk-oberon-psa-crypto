//
// Copyright Oberon microsystems AG, Switzerland.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
//

#ifndef OBERON_BUILD_INFO_H
#define OBERON_BUILD_INFO_H

/*
 * This set of compile-time defines can be used to determine the version number
 * of Oberon PSA Crypto.
 * The version means
 *    - the version of the Oberon PSA Crypto Core,
 *    - and that the Oberon drivers have been tested for compatibility with this
 *      version of the PSA Core,
 *    - and that the provided dispatch logic, while only a template, has been
 *      tested with that version of the PSA Core.
 */

/**
 * The version number x.y.z is split into three parts.
 * Major, Minor, Patch
 */
#define OBERON_PSA_CRYPTO_VERSION_MAJOR  2
#define OBERON_PSA_CRYPTO_VERSION_MINOR  1
#define OBERON_PSA_CRYPTO_VERSION_PATCH  0

/**
 * The single version number has the following structure:
 *    MMNNPP00
 *    Major version | Minor version | Patch version
 */
#define OBERON_PSA_CRYPTO_VERSION_NUMBER      ((OBERON_PSA_CRYPTO_VERSION_MAJOR << 24) | \
                                               (OBERON_PSA_CRYPTO_VERSION_MINOR << 16) | \
                                               (OBERON_PSA_CRYPTO_VERSION_PATCH <<  8))


#endif /* OBERON_BUILD_INFO_H */
