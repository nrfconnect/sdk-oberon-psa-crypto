/*
 *  Copyright Oberon microsystems AG, Switzerland
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

#include "psa/crypto.h"
#include "test_cycles.h"


static const uint8_t key_data[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

const uint8_t rsa_key_1024[] = {
    0x30, 0x82, 0x02, 0x5e, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xaf, 0x05,
    0x7d, 0x39, 0x6e, 0xe8, 0x4f, 0xb7, 0x5f, 0xdb, 0xb5, 0xc2, 0xb1, 0x3c, 0x7f,
    0xe5, 0xa6, 0x54, 0xaa, 0x8a, 0xa2, 0x47, 0x0b, 0x54, 0x1e, 0xe1, 0xfe, 0xb0,
    0xb1, 0x2d, 0x25, 0xc7, 0x97, 0x11, 0x53, 0x12, 0x49, 0xe1, 0x12, 0x96, 0x28,
    0x04, 0x2d, 0xbb, 0xb6, 0xc1, 0x20, 0xd1, 0x44, 0x35, 0x24, 0xef, 0x4c, 0x0e,
    0x6e, 0x1d, 0x89, 0x56, 0xee, 0xb2, 0x07, 0x7a, 0xf1, 0x23, 0x49, 0xdd, 0xee,
    0xe5, 0x44, 0x83, 0xbc, 0x06, 0xc2, 0xc6, 0x19, 0x48, 0xcd, 0x02, 0xb2, 0x02,
    0xe7, 0x96, 0xae, 0xbd, 0x94, 0xd3, 0xa7, 0xcb, 0xf8, 0x59, 0xc2, 0xc1, 0x81,
    0x9c, 0x32, 0x4c, 0xb8, 0x2b, 0x9c, 0xd3, 0x4e, 0xde, 0x26, 0x3a, 0x2a, 0xbf,
    0xfe, 0x47, 0x33, 0xf0, 0x77, 0x86, 0x9e, 0x86, 0x60, 0xf7, 0xd6, 0x83, 0x4d,
    0xa5, 0x3d, 0x69, 0x0e, 0xf7, 0x98, 0x5f, 0x6b, 0xc3, 0x02, 0x03, 0x01, 0x00,
    0x01, 0x02, 0x81, 0x81, 0x00, 0x87, 0x4b, 0xf0, 0xff, 0xc2, 0xf2, 0xa7, 0x1d,
    0x14, 0x67, 0x1d, 0xdd, 0x01, 0x71, 0xc9, 0x54, 0xd7, 0xfd, 0xbf, 0x50, 0x28,
    0x1e, 0x4f, 0x6d, 0x99, 0xea, 0x0e, 0x1e, 0xbc, 0xf8, 0x2f, 0xaa, 0x58, 0xe7,
    0xb5, 0x95, 0xff, 0xb2, 0x93, 0xd1, 0xab, 0xe1, 0x7f, 0x11, 0x0b, 0x37, 0xc4,
    0x8c, 0xc0, 0xf3, 0x6c, 0x37, 0xe8, 0x4d, 0x87, 0x66, 0x21, 0xd3, 0x27, 0xf6,
    0x4b, 0xbe, 0x08, 0x45, 0x7d, 0x3e, 0xc4, 0x09, 0x8b, 0xa2, 0xfa, 0x0a, 0x31,
    0x9f, 0xba, 0x41, 0x1c, 0x28, 0x41, 0xed, 0x7b, 0xe8, 0x31, 0x96, 0xa8, 0xcd,
    0xf9, 0xda, 0xa5, 0xd0, 0x06, 0x94, 0xbc, 0x33, 0x5f, 0xc4, 0xc3, 0x22, 0x17,
    0xfe, 0x04, 0x88, 0xbc, 0xe9, 0xcb, 0x72, 0x02, 0xe5, 0x94, 0x68, 0xb1, 0xea,
    0xd1, 0x19, 0x00, 0x04, 0x77, 0xdb, 0x2c, 0xa7, 0x97, 0xfa, 0xc1, 0x9e, 0xda,
    0x3f, 0x58, 0xc1, 0x02, 0x41, 0x00, 0xe2, 0xab, 0x76, 0x08, 0x41, 0xbb, 0x9d,
    0x30, 0xa8, 0x1d, 0x22, 0x2d, 0xe1, 0xeb, 0x73, 0x81, 0xd8, 0x22, 0x14, 0x40,
    0x7f, 0x1b, 0x97, 0x5c, 0xbb, 0xfe, 0x4e, 0x1a, 0x94, 0x67, 0xfd, 0x98, 0xad,
    0xbd, 0x78, 0xf6, 0x07, 0x83, 0x6c, 0xa5, 0xbe, 0x19, 0x28, 0xb9, 0xd1, 0x60,
    0xd9, 0x7f, 0xd4, 0x5c, 0x12, 0xd6, 0xb5, 0x2e, 0x2c, 0x98, 0x71, 0xa1, 0x74,
    0xc6, 0x6b, 0x48, 0x81, 0x13, 0x02, 0x41, 0x00, 0xc5, 0xab, 0x27, 0x60, 0x21,
    0x59, 0xae, 0x7d, 0x6f, 0x20, 0xc3, 0xc2, 0xee, 0x85, 0x1e, 0x46, 0xdc, 0x11,
    0x2e, 0x68, 0x9e, 0x28, 0xd5, 0xfc, 0xbb, 0xf9, 0x90, 0xa9, 0x9e, 0xf8, 0xa9,
    0x0b, 0x8b, 0xb4, 0x4f, 0xd3, 0x64, 0x67, 0xe7, 0xfc, 0x17, 0x89, 0xce, 0xb6,
    0x63, 0xab, 0xda, 0x33, 0x86, 0x52, 0xc3, 0xc7, 0x3f, 0x11, 0x17, 0x74, 0x90,
    0x2e, 0x84, 0x05, 0x65, 0x92, 0x70, 0x91, 0x02, 0x41, 0x00, 0xb6, 0xcd, 0xbd,
    0x35, 0x4f, 0x7d, 0xf5, 0x79, 0xa6, 0x3b, 0x48, 0xb3, 0x64, 0x3e, 0x35, 0x3b,
    0x84, 0x89, 0x87, 0x77, 0xb4, 0x8b, 0x15, 0xf9, 0x4e, 0x0b, 0xfc, 0x05, 0x67,
    0xa6, 0xae, 0x59, 0x11, 0xd5, 0x7a, 0xd6, 0x40, 0x9c, 0xf7, 0x64, 0x7b, 0xf9,
    0x62, 0x64, 0xe9, 0xbd, 0x87, 0xeb, 0x95, 0xe2, 0x63, 0xb7, 0x11, 0x0b, 0x9a,
    0x1f, 0x9f, 0x94, 0xac, 0xce, 0xd0, 0xfa, 0xfa, 0x4d, 0x02, 0x40, 0x71, 0x19,
    0x5e, 0xec, 0x37, 0xe8, 0xd2, 0x57, 0xde, 0xcf, 0xc6, 0x72, 0xb0, 0x7a, 0xe6,
    0x39, 0xf1, 0x0c, 0xbb, 0x9b, 0x0c, 0x73, 0x9d, 0x0c, 0x80, 0x99, 0x68, 0xd6,
    0x44, 0xa9, 0x4e, 0x3f, 0xd6, 0xed, 0x92, 0x87, 0x07, 0x7a, 0x14, 0x58, 0x3f,
    0x37, 0x90, 0x58, 0xf7, 0x6a, 0x8a, 0xec, 0xd4, 0x3c, 0x62, 0xdc, 0x8c, 0x0f,
    0x41, 0x76, 0x66, 0x50, 0xd7, 0x25, 0x27, 0x5a, 0xc4, 0xa1, 0x02, 0x41, 0x00,
    0xbb, 0x32, 0xd1, 0x33, 0xed, 0xc2, 0xe0, 0x48, 0xd4, 0x63, 0x38, 0x8b, 0x7b,
    0xe9, 0xcb, 0x4b, 0xe2, 0x9f, 0x4b, 0x62, 0x50, 0xbe, 0x60, 0x3e, 0x70, 0xe3,
    0x64, 0x75, 0x01, 0xc9, 0x7d, 0xdd, 0xe2, 0x0a, 0x4e, 0x71, 0xbe, 0x95, 0xfd,
    0x5e, 0x71, 0x78, 0x4e, 0x25, 0xac, 0xa4, 0xba, 0xf2, 0x5b, 0xe5, 0x73, 0x8a,
    0xae, 0x59, 0xbb, 0xfe, 0x1c, 0x99, 0x77, 0x81, 0x44, 0x7a, 0x2b, 0x24};

const uint8_t rsa_key_2048[] = {
    0x30, 0x82, 0x04, 0xA5, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xC0,
    0x95, 0x08, 0xE1, 0x57, 0x41, 0xF2, 0x71, 0x6D, 0xB7, 0xD2, 0x45, 0x41, 0x27,
    0x01, 0x65, 0xC6, 0x45, 0xAE, 0xF2, 0xBC, 0x24, 0x30, 0xB8, 0x95, 0xCE, 0x2F,
    0x4E, 0xD6, 0xF6, 0x1C, 0x88, 0xBC, 0x7C, 0x9F, 0xFB, 0xA8, 0x67, 0x7F, 0xFE,
    0x5C, 0x9C, 0x51, 0x75, 0xF7, 0x8A, 0xCA, 0x07, 0xE7, 0x35, 0x2F, 0x8F, 0xE1,
    0xBD, 0x7B, 0xC0, 0x2F, 0x7C, 0xAB, 0x64, 0xA8, 0x17, 0xFC, 0xCA, 0x5D, 0x7B,
    0xBA, 0xE0, 0x21, 0xE5, 0x72, 0x2E, 0x6F, 0x2E, 0x86, 0xD8, 0x95, 0x73, 0xDA,
    0xAC, 0x1B, 0x53, 0xB9, 0x5F, 0x3F, 0xD7, 0x19, 0x0D, 0x25, 0x4F, 0xE1, 0x63,
    0x63, 0x51, 0x8B, 0x0B, 0x64, 0x3F, 0xAD, 0x43, 0xB8, 0xA5, 0x1C, 0x5C, 0x34,
    0xB3, 0xAE, 0x00, 0xA0, 0x63, 0xC5, 0xF6, 0x7F, 0x0B, 0x59, 0x68, 0x78, 0x73,
    0xA6, 0x8C, 0x18, 0xA9, 0x02, 0x6D, 0xAF, 0xC3, 0x19, 0x01, 0x2E, 0xB8, 0x10,
    0xE3, 0xC6, 0xCC, 0x40, 0xB4, 0x69, 0xA3, 0x46, 0x33, 0x69, 0x87, 0x6E, 0xC4,
    0xBB, 0x17, 0xA6, 0xF3, 0xE8, 0xDD, 0xAD, 0x73, 0xBC, 0x7B, 0x2F, 0x21, 0xB5,
    0xFD, 0x66, 0x51, 0x0C, 0xBD, 0x54, 0xB3, 0xE1, 0x6D, 0x5F, 0x1C, 0xBC, 0x23,
    0x73, 0xD1, 0x09, 0x03, 0x89, 0x14, 0xD2, 0x10, 0xB9, 0x64, 0xC3, 0x2A, 0xD0,
    0xA1, 0x96, 0x4A, 0xBC, 0xE1, 0xD4, 0x1A, 0x5B, 0xC7, 0xA0, 0xC0, 0xC1, 0x63,
    0x78, 0x0F, 0x44, 0x37, 0x30, 0x32, 0x96, 0x80, 0x32, 0x23, 0x95, 0xA1, 0x77,
    0xBA, 0x13, 0xD2, 0x97, 0x73, 0xE2, 0x5D, 0x25, 0xC9, 0x6A, 0x0D, 0xC3, 0x39,
    0x60, 0xA4, 0xB4, 0xB0, 0x69, 0x42, 0x42, 0x09, 0xE9, 0xD8, 0x08, 0xBC, 0x33,
    0x20, 0xB3, 0x58, 0x22, 0xA7, 0xAA, 0xEB, 0xC4, 0xE1, 0xE6, 0x61, 0x83, 0xC5,
    0xD2, 0x96, 0xDF, 0xD9, 0xD0, 0x4F, 0xAD, 0xD7, 0x02, 0x03, 0x01, 0x00, 0x01,
    0x02, 0x82, 0x01, 0x01, 0x00, 0x9A, 0xD0, 0x34, 0x0F, 0x52, 0x62, 0x05, 0x50,
    0x01, 0xEF, 0x9F, 0xED, 0x64, 0x6E, 0xC2, 0xC4, 0xDA, 0x1A, 0xF2, 0x84, 0xD7,
    0x92, 0x10, 0x48, 0x92, 0xC4, 0xE9, 0x6A, 0xEB, 0x8B, 0x75, 0x6C, 0xC6, 0x79,
    0x38, 0xF2, 0xC9, 0x72, 0x4A, 0x86, 0x64, 0x54, 0x95, 0x77, 0xCB, 0xC3, 0x9A,
    0x9D, 0xB7, 0xD4, 0x1D, 0xA4, 0x00, 0xC8, 0x9E, 0x4E, 0xE4, 0xDD, 0xC7, 0xBA,
    0x67, 0x16, 0xC1, 0x74, 0xBC, 0xA9, 0xD6, 0x94, 0x8F, 0x2B, 0x30, 0x1A, 0xFB,
    0xED, 0xDF, 0x21, 0x05, 0x23, 0xD9, 0x4A, 0x39, 0xBD, 0x98, 0x6B, 0x65, 0x9A,
    0xB8, 0xDC, 0xC4, 0x7D, 0xEE, 0xA6, 0x43, 0x15, 0x2E, 0x3D, 0xBE, 0x1D, 0x22,
    0x60, 0x2A, 0x73, 0x30, 0xD5, 0x3E, 0xD8, 0xA2, 0xAC, 0x86, 0x43, 0x2E, 0xC4,
    0xF5, 0x64, 0x5E, 0x3F, 0x89, 0x75, 0x0F, 0x11, 0xD8, 0x51, 0x25, 0x4E, 0x9F,
    0xD8, 0xAA, 0xA3, 0xCE, 0x60, 0xB3, 0xE2, 0x8A, 0xD9, 0x7E, 0x1B, 0xF0, 0x64,
    0xCA, 0x9A, 0x5B, 0x05, 0x0B, 0x5B, 0xAA, 0xCB, 0xE5, 0xE3, 0x3F, 0x6E, 0x32,
    0x22, 0x05, 0xF3, 0xD0, 0xFA, 0xEF, 0x74, 0x52, 0x81, 0xE2, 0x5F, 0x74, 0xD3,
    0xBD, 0xFF, 0x31, 0x83, 0x45, 0x75, 0xFA, 0x63, 0x7A, 0x97, 0x2E, 0xD6, 0xB6,
    0x19, 0xC6, 0x92, 0x26, 0xE4, 0x28, 0x06, 0x50, 0x50, 0x0E, 0x78, 0x2E, 0xA9,
    0x78, 0x0D, 0x14, 0x97, 0xB4, 0x12, 0xD8, 0x31, 0x40, 0xAB, 0xA1, 0x01, 0x41,
    0xC2, 0x30, 0xF8, 0x07, 0x5F, 0x16, 0xE4, 0x61, 0x77, 0xD2, 0x60, 0xF2, 0x9F,
    0x8D, 0xE8, 0xF4, 0xBA, 0xEB, 0x63, 0xDE, 0x2A, 0x97, 0x81, 0xEF, 0x4C, 0x6C,
    0xE6, 0x55, 0x34, 0x51, 0x2B, 0x28, 0x34, 0xF4, 0x53, 0x1C, 0xC4, 0x58, 0x0A,
    0x3F, 0xBB, 0xAF, 0xB5, 0xF7, 0x4A, 0x85, 0x43, 0x2D, 0x3C, 0xF1, 0x58, 0x58,
    0x81, 0x02, 0x81, 0x81, 0x00, 0xF2, 0x2C, 0x54, 0x76, 0x39, 0x23, 0x63, 0xC9,
    0x10, 0x32, 0xB7, 0x93, 0xAD, 0xAF, 0xBE, 0x19, 0x75, 0x96, 0x81, 0x64, 0xE6,
    0xB5, 0xB8, 0x89, 0x42, 0x41, 0xD1, 0x6D, 0xD0, 0x1C, 0x1B, 0xF8, 0x1B, 0xAC,
    0x69, 0xCB, 0x36, 0x3C, 0x64, 0x7D, 0xDC, 0xF4, 0x19, 0xB8, 0xC3, 0x60, 0xB1,
    0x57, 0x48, 0x5F, 0x52, 0x4F, 0x59, 0x3A, 0x55, 0x7F, 0x32, 0xC0, 0x19, 0x43,
    0x50, 0x3F, 0xAE, 0xCE, 0x6F, 0x17, 0xF3, 0x0E, 0x9F, 0x40, 0xCA, 0x4E, 0xAD,
    0x15, 0x3B, 0xC9, 0x79, 0xE9, 0xC0, 0x59, 0x38, 0x73, 0x70, 0x9C, 0x0A, 0x7C,
    0xC9, 0x3A, 0x48, 0x32, 0xA7, 0xD8, 0x49, 0x75, 0x0A, 0x85, 0xC2, 0xC2, 0xFD,
    0x15, 0x73, 0xDA, 0x99, 0x09, 0x2A, 0x69, 0x9A, 0x9F, 0x0A, 0x71, 0xBF, 0xB0,
    0x04, 0xA6, 0x8C, 0x7A, 0x5A, 0x6F, 0x48, 0x5A, 0x54, 0x3B, 0xC6, 0xB1, 0x53,
    0x17, 0xDF, 0xE7, 0x02, 0x81, 0x81, 0x00, 0xCB, 0x93, 0xDE, 0x77, 0x15, 0x5D,
    0xB7, 0x5C, 0x5C, 0x7C, 0xD8, 0x90, 0xA9, 0x98, 0x2D, 0xD6, 0x69, 0x0E, 0x63,
    0xB3, 0xA3, 0xDC, 0xA6, 0xCC, 0x8B, 0x6A, 0xA4, 0xA2, 0x12, 0x8C, 0x8E, 0x7B,
    0x48, 0x2C, 0xB2, 0x4B, 0x37, 0xDC, 0x06, 0x18, 0x7D, 0xEA, 0xFE, 0x76, 0xA1,
    0xD4, 0xA1, 0xE9, 0x3F, 0x0D, 0xCD, 0x1B, 0x5F, 0xAF, 0x5F, 0x9E, 0x96, 0x5B,
    0x5B, 0x0F, 0xA1, 0x7C, 0xAF, 0xB3, 0x9B, 0x90, 0xDB, 0x57, 0x73, 0x3A, 0xED,
    0xB0, 0x23, 0x44, 0xAE, 0x41, 0x4F, 0x1F, 0x07, 0x42, 0x13, 0x23, 0x4C, 0xCB,
    0xFA, 0xF4, 0x14, 0xA4, 0xD5, 0xF7, 0x9E, 0x36, 0x7C, 0x5B, 0x9F, 0xA8, 0x3C,
    0xC1, 0x85, 0x5F, 0x74, 0xD2, 0x39, 0x2D, 0xFF, 0xD0, 0x84, 0xDF, 0xFB, 0xB3,
    0x20, 0x7A, 0x2E, 0x9B, 0x17, 0xAE, 0xE6, 0xBA, 0x0B, 0xAE, 0x5F, 0x53, 0xA4,
    0x52, 0xED, 0x1B, 0xC4, 0x91, 0x02, 0x81, 0x81, 0x00, 0xEC, 0x98, 0xDA, 0xBB,
    0xD5, 0xFE, 0xF9, 0x52, 0x4A, 0x7D, 0x02, 0x55, 0x49, 0x6F, 0x55, 0x6E, 0x52,
    0x2F, 0x84, 0xA3, 0x2B, 0xB3, 0x86, 0x62, 0xB3, 0x54, 0xD2, 0x63, 0x52, 0xDA,
    0xE3, 0x88, 0x76, 0xA0, 0xEF, 0x8B, 0x15, 0xA5, 0xD3, 0x18, 0x14, 0x72, 0x77,
    0x5E, 0xC7, 0xA3, 0x04, 0x1F, 0x9E, 0x19, 0x62, 0xB5, 0x1B, 0x1B, 0x9E, 0xC3,
    0xF2, 0xB5, 0x32, 0xF9, 0x4C, 0xC1, 0xAA, 0xEB, 0x0C, 0x26, 0x7D, 0xD4, 0x5F,
    0x4A, 0x51, 0x5C, 0xA4, 0x45, 0x06, 0x70, 0x44, 0xA7, 0x56, 0xC0, 0xD4, 0x22,
    0x14, 0x76, 0x9E, 0xD8, 0x63, 0x50, 0x89, 0x90, 0xD3, 0xE2, 0xBF, 0x81, 0x95,
    0x92, 0x31, 0x41, 0x87, 0x39, 0x1A, 0x43, 0x0B, 0x18, 0xA5, 0x53, 0x1F, 0x39,
    0x1A, 0x5F, 0x1F, 0x43, 0xBC, 0x87, 0x6A, 0xDF, 0x6E, 0xD3, 0x22, 0x00, 0xFE,
    0x22, 0x98, 0x70, 0x4E, 0x1A, 0x19, 0x29, 0x02, 0x81, 0x81, 0x00, 0x8A, 0x41,
    0x56, 0x28, 0x51, 0x9E, 0x5F, 0xD4, 0x9E, 0x0B, 0x3B, 0x98, 0xA3, 0x54, 0xF2,
    0x6C, 0x56, 0xD4, 0xAA, 0xE9, 0x69, 0x33, 0x85, 0x24, 0x0C, 0xDA, 0xD4, 0x0C,
    0x2D, 0xC4, 0xBF, 0x4F, 0x02, 0x69, 0x38, 0x7C, 0xD4, 0xE6, 0xDC, 0x4C, 0xED,
    0xD7, 0x16, 0x11, 0xC3, 0x3E, 0x00, 0xE7, 0xC3, 0x26, 0xC0, 0x51, 0x02, 0xDE,
    0xBB, 0x75, 0x9C, 0x6F, 0x56, 0x9C, 0x7A, 0xF3, 0x8E, 0xEF, 0xCF, 0x8A, 0xC5,
    0x2B, 0xD2, 0xDA, 0x06, 0x6A, 0x44, 0xC9, 0x73, 0xFE, 0x6E, 0x99, 0x87, 0xF8,
    0x5B, 0xBE, 0xF1, 0x7C, 0xE6, 0x65, 0xB5, 0x4F, 0x6C, 0xF0, 0xC9, 0xC5, 0xFF,
    0x16, 0xCA, 0x8B, 0x1B, 0x17, 0xE2, 0x58, 0x3D, 0xA2, 0x37, 0xAB, 0x01, 0xBC,
    0xBF, 0x40, 0xCE, 0x53, 0x8C, 0x8E, 0xED, 0xEF, 0xEE, 0x59, 0x9D, 0xE0, 0x63,
    0xE6, 0x7C, 0x5E, 0xF5, 0x8E, 0x4B, 0xF1, 0x3B, 0xC1, 0x02, 0x81, 0x80, 0x4D,
    0x45, 0xF9, 0x40, 0x8C, 0xC5, 0x5B, 0xF4, 0x2A, 0x1A, 0x8A, 0xB4, 0xF2, 0x1C,
    0xAC, 0x6B, 0xE9, 0x0C, 0x56, 0x36, 0xB7, 0x4E, 0x72, 0x96, 0xD5, 0xE5, 0x8A,
    0xD2, 0xE2, 0xFF, 0xF1, 0xF1, 0x18, 0x13, 0x3D, 0x86, 0x09, 0xB8, 0xD8, 0x76,
    0xA7, 0xC9, 0x1C, 0x71, 0x52, 0x94, 0x30, 0x43, 0xE0, 0xF1, 0x78, 0x74, 0xFD,
    0x61, 0x1B, 0x4C, 0x09, 0xCC, 0xE6, 0x68, 0x2A, 0x71, 0xAD, 0x1C, 0xDF, 0x43,
    0xBC, 0x56, 0xDB, 0xA5, 0xA4, 0xBE, 0x35, 0x70, 0xA4, 0x5E, 0xCF, 0x4F, 0xFC,
    0x00, 0x55, 0x99, 0x3A, 0x3D, 0x23, 0xCF, 0x67, 0x5A, 0xF5, 0x22, 0xF8, 0xB5,
    0x29, 0xD0, 0x44, 0x11, 0xEB, 0x35, 0x2E, 0x46, 0xBE, 0xFD, 0x8E, 0x18, 0xB2,
    0x5F, 0xA8, 0xBF, 0x19, 0x32, 0xA1, 0xF5, 0xDC, 0x03, 0xE6, 0x7C, 0x9A, 0x1F,
    0x0C, 0x7C, 0xA9, 0xB0, 0x0E, 0x21, 0x37, 0x3B, 0xF1, 0xB0};


int main(void)
{
    psa_status_t status;
    uint64_t t0, t1;
    uint8_t data[1024], pk[300], sig[256], tag[16];
    psa_key_id_t key = 0;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_cipher_operation_t cipher_op = PSA_CIPHER_OPERATION_INIT;
    psa_aead_operation_t aead_op = PSA_AEAD_OPERATION_INIT;
    psa_key_derivation_operation_t kdf_op = PSA_KEY_DERIVATION_OPERATION_INIT;
    size_t length, pk_len;

    status = psa_crypto_init();
    if (status) goto error;

    t0 = cpucycles();
    status = psa_hash_compute(PSA_ALG_SHA_256, data, 1024, data, sizeof data, &length);
    if (status) goto error;
    t1 = cpucycles();
    printf("SHA-256 (1024 bytes):                %lld cycles\r\n", t1 - t0);

    t0 = cpucycles();
    status = psa_hash_compute(PSA_ALG_SHA_512, data, 1024, data, sizeof data, &length);
    if (status) goto error;
    t1 = cpucycles();
    printf("SHA-512 (1024 bytes):                %lld cycles\r\n", t1 - t0);

    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attr, 256);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    status = psa_import_key(&attr, key_data, 32, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_mac_compute(key, PSA_ALG_HMAC(PSA_ALG_SHA_256), data, sizeof data, data, sizeof data, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("HMAC-SHA-256 (1024 bytes):           %lld cycles\r\n", t1 - t0);

    psa_set_key_bits(&attr, 256);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_512));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    status = psa_import_key(&attr, key_data, 32, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_mac_compute(key, PSA_ALG_HMAC(PSA_ALG_SHA_512), data, sizeof data, data, sizeof data, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("HMAC-SHA-512 (1024 bytes):           %lld cycles\r\n", t1 - t0);

    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 256);
    psa_set_key_algorithm(&attr, PSA_ALG_CMAC);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    status = psa_import_key(&attr, key_data, 32, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_mac_compute(key, PSA_ALG_CMAC, data, sizeof data, data, sizeof data, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("CMAC-AES-256 (1024 bytes):           %lld cycles\r\n", t1 - t0);

    t0 = cpucycles();
    status = psa_key_derivation_setup(&kdf_op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (status) goto error;
    status = psa_key_derivation_input_bytes(&kdf_op, PSA_KEY_DERIVATION_INPUT_SALT, (uint8_t*)"Salt", 4);
    if (status) goto error;
    status = psa_key_derivation_input_bytes(&kdf_op, PSA_KEY_DERIVATION_INPUT_INFO, (uint8_t*)"Info", 4);
    if (status) goto error;
    status = psa_key_derivation_input_bytes(&kdf_op, PSA_KEY_DERIVATION_INPUT_SECRET, key_data, 32);
    if (status) goto error;
    status = psa_key_derivation_output_bytes(&kdf_op, data, 32);
    if (status) goto error;
    status = psa_key_derivation_abort(&kdf_op);
    if (status) goto error;
    t1 = cpucycles();
    printf("HKDF-SHA-256:                        %lld cycles\r\n", t1 - t0);

    t0 = cpucycles();
    status = psa_key_derivation_setup(&kdf_op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    if (status) goto error;
    status = psa_key_derivation_input_integer(&kdf_op, PSA_KEY_DERIVATION_INPUT_COST, 100);
    if (status) goto error;
    status = psa_key_derivation_input_bytes(&kdf_op, PSA_KEY_DERIVATION_INPUT_SALT, (uint8_t*)"Salt", 4);
    if (status) goto error;
    status = psa_key_derivation_input_bytes(&kdf_op, PSA_KEY_DERIVATION_INPUT_PASSWORD, key_data, 16);
    if (status) goto error;
    status = psa_key_derivation_output_bytes(&kdf_op, data, 32);
    if (status) goto error;
    status = psa_key_derivation_abort(&kdf_op);
    if (status) goto error;
    t1 = cpucycles();
    printf("PBKDF2-SHA-256 (100 iterations):     %lld cycles\r\n", t1 - t0);

    t0 = cpucycles();
    status = psa_key_derivation_setup(&kdf_op, PSA_ALG_PBKDF2_AES_CMAC_PRF_128);
    if (status) goto error;
    status = psa_key_derivation_input_integer(&kdf_op, PSA_KEY_DERIVATION_INPUT_COST, 100);
    if (status) goto error;
    status = psa_key_derivation_input_bytes(&kdf_op, PSA_KEY_DERIVATION_INPUT_SALT, (uint8_t*)"Salt", 4);
    if (status) goto error;
    status = psa_key_derivation_input_bytes(&kdf_op, PSA_KEY_DERIVATION_INPUT_PASSWORD, key_data, 16);
    if (status) goto error;
    status = psa_key_derivation_output_bytes(&kdf_op, data, 32);
    if (status) goto error;
    status = psa_key_derivation_abort(&kdf_op);
    if (status) goto error;
    t1 = cpucycles();
    printf("PBKDF2-CMAC-PRF128 (100 iterations): %lld cycles\r\n", t1 - t0);

    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 256);
    psa_set_key_algorithm(&attr, PSA_ALG_ECB_NO_PADDING);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    status = psa_import_key(&attr, key_data, 32, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_cipher_encrypt_setup(&cipher_op, key, PSA_ALG_ECB_NO_PADDING);
    if (status) goto error;
    status = psa_cipher_update(&cipher_op, data, sizeof data, data, sizeof data, &length);
    if (status) goto error;
    status = psa_cipher_finish(&cipher_op, NULL, 0, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("AES-ECB enc (1024 bytes):            %lld cycles\r\n", t1 - t0);

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    status = psa_import_key(&attr, key_data, 32, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_cipher_decrypt_setup(&cipher_op, key, PSA_ALG_ECB_NO_PADDING);
    if (status) goto error;
    status = psa_cipher_update(&cipher_op, data, sizeof data, data, sizeof data, &length);
    if (status) goto error;
    status = psa_cipher_finish(&cipher_op, NULL, 0, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("AES-ECB dec (1024 bytes):            %lld cycles\r\n", t1 - t0);

    psa_set_key_algorithm(&attr, PSA_ALG_CBC_PKCS7);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    status = psa_import_key(&attr, key_data, 32, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_cipher_encrypt_setup(&cipher_op, key, PSA_ALG_CBC_PKCS7);
    if (status) goto error;
    status = psa_cipher_set_iv(&cipher_op, key_data, 16);
    if (status) goto error;
    status = psa_cipher_update(&cipher_op, data, 1020, data, sizeof data, &length);
    if (status) goto error;
    status = psa_cipher_finish(&cipher_op, data + length, sizeof data - length, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("AES-CBC-PKCS7 enc (1024 bytes):      %lld cycles\r\n", t1 - t0);

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    status = psa_import_key(&attr, key_data, 32, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_cipher_decrypt_setup(&cipher_op, key, PSA_ALG_CBC_PKCS7);
    if (status) goto error;
    status = psa_cipher_set_iv(&cipher_op, key_data, 16);
    if (status) goto error;
    status = psa_cipher_update(&cipher_op, data, sizeof data, data, sizeof data, &length);
    if (status) goto error;
    status = psa_cipher_finish(&cipher_op, data, sizeof data, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("AES-CBC-PKCS7 dec (1024 bytes):      %lld cycles\r\n", t1 - t0);

    psa_set_key_algorithm(&attr, PSA_ALG_CTR);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    status = psa_import_key(&attr, key_data, 32, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_cipher_encrypt_setup(&cipher_op, key, PSA_ALG_CTR);
    if (status) goto error;
    status = psa_cipher_set_iv(&cipher_op, key_data, 16);
    if (status) goto error;
    status = psa_cipher_update(&cipher_op, data, sizeof data, data, sizeof data, &length);
    if (status) goto error;
    status = psa_cipher_finish(&cipher_op, NULL, 0, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("AES-CTR enc (1024 bytes):            %lld cycles\r\n", t1 - t0);

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    status = psa_import_key(&attr, key_data, 32, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_cipher_decrypt_setup(&cipher_op, key, PSA_ALG_CTR);
    if (status) goto error;
    status = psa_cipher_set_iv(&cipher_op, key_data, 16);
    if (status) goto error;
    status = psa_cipher_update(&cipher_op, data, sizeof data, data, sizeof data, &length);
    if (status) goto error;
    status = psa_cipher_finish(&cipher_op, NULL, 0, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("AES-CTR dec (1024 bytes):            %lld cycles\r\n", t1 - t0);

    psa_set_key_algorithm(&attr, PSA_ALG_CCM);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    status = psa_import_key(&attr, key_data, 32, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_aead_encrypt_setup(&aead_op, key, PSA_ALG_CCM);
    if (status) goto error;
    status = psa_aead_set_lengths(&aead_op, 0, sizeof data);
    if (status) goto error;
    status = psa_aead_set_nonce(&aead_op, key_data, 13);
    if (status) goto error;
    status = psa_aead_update(&aead_op, data, sizeof data, data, sizeof data, &length);
    if (status) goto error;
    status = psa_aead_finish(&aead_op, NULL, 0, &length, tag, sizeof tag, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("AES-CCM enc (1024 bytes):            %lld cycles\r\n", t1 - t0);

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    status = psa_import_key(&attr, key_data, 32, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_aead_decrypt_setup(&aead_op, key, PSA_ALG_CCM);
    if (status) goto error;
    status = psa_aead_set_lengths(&aead_op, 0, sizeof data);
    if (status) goto error;
    status = psa_aead_set_nonce(&aead_op, key_data, 13);
    if (status) goto error;
    status = psa_aead_update(&aead_op, data, sizeof data, data, sizeof data, &length);
    if (status) goto error;
    status = psa_aead_verify(&aead_op, NULL, 0, &length, tag, sizeof tag);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("AES-CCM dec (1024 bytes):            %lld cycles\r\n", t1 - t0);

    psa_set_key_algorithm(&attr, PSA_ALG_GCM);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    status = psa_import_key(&attr, key_data, 32, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_aead_encrypt_setup(&aead_op, key, PSA_ALG_GCM);
    if (status) goto error;
    status = psa_aead_set_nonce(&aead_op, key_data, 13);
    if (status) goto error;
    status = psa_aead_update(&aead_op, data, sizeof data, data, sizeof data, &length);
    if (status) goto error;
    status = psa_aead_finish(&aead_op, NULL, 0, &length, tag, sizeof tag, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("AES-GCM enc (1024 bytes):            %lld cycles\r\n", t1 - t0);

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    status = psa_import_key(&attr, key_data, 32, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_aead_decrypt_setup(&aead_op, key, PSA_ALG_GCM);
    if (status) goto error;
    status = psa_aead_set_nonce(&aead_op, key_data, 13);
    if (status) goto error;
    status = psa_aead_update(&aead_op, data, sizeof data, data, sizeof data, &length);
    if (status) goto error;
    status = psa_aead_verify(&aead_op, NULL, 0, &length, tag, sizeof tag);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("AES-GCM dec (1024 bytes):            %lld cycles\r\n", t1 - t0);

    psa_set_key_type(&attr, PSA_KEY_TYPE_CHACHA20);
    psa_set_key_bits(&attr, 256);
    psa_set_key_algorithm(&attr, PSA_ALG_STREAM_CIPHER);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    status = psa_import_key(&attr, key_data, 32, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_cipher_encrypt_setup(&cipher_op, key, PSA_ALG_STREAM_CIPHER);
    if (status) goto error;
    status = psa_cipher_set_iv(&cipher_op, key_data, 12);
    if (status) goto error;
    status = psa_cipher_update(&cipher_op, data, sizeof data, data, sizeof data, &length);
    if (status) goto error;
    status = psa_cipher_finish(&cipher_op, NULL, 0, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("CHACHA20 enc (1024 bytes):           %lld cycles\r\n", t1 - t0);

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    status = psa_import_key(&attr, key_data, 32, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_cipher_decrypt_setup(&cipher_op, key, PSA_ALG_STREAM_CIPHER);
    if (status) goto error;
    status = psa_cipher_set_iv(&cipher_op, key_data, 12);
    if (status) goto error;
    status = psa_cipher_update(&cipher_op, data, sizeof data, data, sizeof data, &length);
    if (status) goto error;
    status = psa_cipher_finish(&cipher_op, NULL, 0, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("CHACHA20 dec (1024 bytes):           %lld cycles\r\n", t1 - t0);

    psa_set_key_algorithm(&attr, PSA_ALG_CHACHA20_POLY1305);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    status = psa_import_key(&attr, key_data, 32, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_aead_encrypt_setup(&aead_op, key, PSA_ALG_CHACHA20_POLY1305);
    if (status) goto error;
    status = psa_aead_set_nonce(&aead_op, key_data, 12);
    if (status) goto error;
    status = psa_aead_update(&aead_op, data, sizeof data, data, sizeof data, &length);
    if (status) goto error;
    status = psa_aead_finish(&aead_op, NULL, 0, &length, tag, sizeof tag, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("Chacha20-Poly1305 enc (1024 bytes):  %lld cycles\r\n", t1 - t0);

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    status = psa_import_key(&attr, key_data, 32, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_aead_decrypt_setup(&aead_op, key, PSA_ALG_CHACHA20_POLY1305);
    if (status) goto error;
    status = psa_aead_set_nonce(&aead_op, key_data, 12);
    if (status) goto error;
    status = psa_aead_update(&aead_op, data, sizeof data, data, sizeof data, &length);
    if (status) goto error;
    status = psa_aead_verify(&aead_op, NULL, 0, &length, tag, sizeof tag);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("Chacha20-Poly1305 dec (1024 bytes):  %lld cycles\r\n", t1 - t0);

    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    status = psa_import_key(&attr, key_data, 32, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_export_public_key(key, pk, sizeof pk, &length);
    if (status) goto error;
    t1 = cpucycles();
    printf("P256 public key:                     %lld cycles\r\n", t1 - t0);
    t0 = cpucycles();
    status = psa_sign_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), data, 32, sig, sizeof sig, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("P256 sign hash (32 bytes):           %lld cycles\r\n", t1 - t0);

    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
    status = psa_import_key(&attr, pk, 65, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_verify_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), data, 32, sig, length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("P256 verify hash (32 bytes):         %lld cycles\r\n", t1 - t0);

    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    status = psa_import_key(&attr, key_data, 32, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_raw_key_agreement(PSA_ALG_ECDH, key, pk, 65, data, sizeof data, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("ECDH P256:                           %lld cycles\r\n", t1 - t0);

    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attr, 255);
    psa_set_key_algorithm(&attr, PSA_ALG_PURE_EDDSA);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    status = psa_import_key(&attr, key_data, 32, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_export_public_key(key, pk, sizeof pk, &length);
    if (status) goto error;
    t1 = cpucycles();
    printf("Ed25519 public key:                  %lld cycles\r\n", t1 - t0);
    t0 = cpucycles();
    status = psa_sign_message(key, PSA_ALG_PURE_EDDSA, data, 32, sig, sizeof sig, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("Ed25519 sign (32 bytes):             %lld cycles\r\n", t1 - t0);

    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attr, 255);
    psa_set_key_algorithm(&attr, PSA_ALG_PURE_EDDSA);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_MESSAGE);
    status = psa_import_key(&attr, pk, 32, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_verify_message(key, PSA_ALG_PURE_EDDSA, data, 32, sig, length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("Ed25519 verify (32 bytes):           %lld cycles\r\n", t1 - t0);

    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&attr, 255);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    status = psa_import_key(&attr, key_data, 32, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_export_public_key(key, pk, sizeof pk, &length);
    if (status) goto error;
    t1 = cpucycles();
    printf("X25519 public key:                   %lld cycles\r\n", t1 - t0);
    t0 = cpucycles();
    status = psa_raw_key_agreement(PSA_ALG_ECDH, key, pk, 32, data, sizeof data, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("ECDH X25519:                         %lld cycles\r\n", t1 - t0);

    psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attr, 1024);
    psa_set_key_algorithm(&attr, PSA_ALG_RSA_PSS(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    status = psa_import_key(&attr, rsa_key_1024, sizeof rsa_key_1024, &key);
    if (status) goto error;
    status = psa_export_public_key(key, pk, sizeof pk, &pk_len);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_sign_hash(key, PSA_ALG_RSA_PSS(PSA_ALG_SHA_256), data, 32, sig, sizeof sig, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("RSA-PSS-1024 sign hash:              %lld cycles\r\n", t1 - t0);

    psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_bits(&attr, 1024);
    psa_set_key_algorithm(&attr, PSA_ALG_RSA_PSS(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
    status = psa_import_key(&attr, pk, pk_len, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_verify_hash(key, PSA_ALG_RSA_PSS(PSA_ALG_SHA_256), data, 32, sig, length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("RSA-PSS-1024 verify hash:            %lld cycles\r\n", t1 - t0);

    psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_bits(&attr, 1024);
    psa_set_key_algorithm(&attr, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    status = psa_import_key(&attr, pk, pk_len, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_asymmetric_encrypt(key, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256), data, 40, NULL, 0, data, sizeof data, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("RSA-OAEP-1024 encrypt:               %lld cycles\r\n", t1 - t0);

    psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attr, 1024);
    psa_set_key_algorithm(&attr, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    status = psa_import_key(&attr, rsa_key_1024, sizeof rsa_key_1024, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_asymmetric_decrypt(key, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256), data, length, NULL, 0, data, sizeof data, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("RSA-OAEP-1024 decrypt:               %lld cycles\r\n", t1 - t0);

    psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attr, 2048);
    psa_set_key_algorithm(&attr, PSA_ALG_RSA_PSS(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    status = psa_import_key(&attr, rsa_key_2048, sizeof rsa_key_2048, &key);
    if (status) goto error;
    status = psa_export_public_key(key, pk, sizeof pk, &pk_len);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_sign_hash(key, PSA_ALG_RSA_PSS(PSA_ALG_SHA_256), data, 32, sig, sizeof sig, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("RSA-PSS-2048 sign hash:              %lld cycles\r\n", t1 - t0);

    psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_bits(&attr, 2048);
    psa_set_key_algorithm(&attr, PSA_ALG_RSA_PSS(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
    status = psa_import_key(&attr, pk, pk_len, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_verify_hash(key, PSA_ALG_RSA_PSS(PSA_ALG_SHA_256), data, 32, sig, length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("RSA-PSS-2048 verify hash:            %lld cycles\r\n", t1 - t0);

    psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_bits(&attr, 2048);
    psa_set_key_algorithm(&attr, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    status = psa_import_key(&attr, pk, pk_len, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_asymmetric_encrypt(key, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256), data, 100, NULL, 0, data, sizeof data, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("RSA-OAEP-2048 encrypt:               %lld cycles\r\n", t1 - t0);

    psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attr, 2048);
    psa_set_key_algorithm(&attr, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    status = psa_import_key(&attr, rsa_key_2048, sizeof rsa_key_2048, &key);
    if (status) goto error;
    t0 = cpucycles();
    status = psa_asymmetric_decrypt(key, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256), data, length, NULL, 0, data, sizeof data, &length);
    if (status) goto error;
    t1 = cpucycles();
    psa_destroy_key(key);
    printf("RSA-OAEP-2048 decrypt:               %lld cycles\r\n", t1 - t0);

    printf("done\r\n");
    return 0;
error:
    printf("error %d received\r\n", status);
    return 1;
}