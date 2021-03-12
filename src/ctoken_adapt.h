/*
 * ctoken_adapt.h
 *
 * Copyright (c) 2021, Laurence Lundblade.
 *
 * Created by Laurence Lundblade on 2/14/21.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef ctoken_adapt_h
#define ctoken_adapt_h

#include "xclaim.h"
#include "ctoken/ctoken_encode.h"
#include "ctoken/ctoken_decode.h"
#include "t_cose/t_cose_common.h"


void xclaim_ctoken_encode_init(xclaim_encoder *out, struct ctoken_encode_ctx *ctx);


int xclaim_ctoken_decode_init(xclaim_decoder           *xclaim_decoder,
                              struct ctoken_decode_ctx *ctx,
                              struct q_useful_buf_c     input_bytes,
                              struct t_cose_key         verification_key);

#endif /* ctoken_adapt_h */
