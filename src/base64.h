/*
 * base64.h
 *
 * Copyright (c) 2021, Laurence Lundblade.
 * Most Code originally from
 * // https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
 *  which has no copyright
 *
 * Created by Laurence Lundblade on 2/15/21.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef base64_h
#define base64_h

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>

char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length);

unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length);

#endif /* base64_h */
