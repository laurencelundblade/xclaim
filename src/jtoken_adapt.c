/*
 * jtoken_adapt.c
 *
 * Copyright (c) 2021, Laurence Lundblade.
 *
 * Created by Laurence Lundblade on 2/15/21.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "jtoken_adapt.h"
#include "ctoken/ctoken_cwt_labels.h"
#include "ctoken/ctoken_eat_labels.h"
#include "jtoken_encode.h"


static int
xclaim_encode_generic(struct jtoken_encode_ctx *ectx, const QCBORItem *claim_item)
{
    bool bool_value;
    char json_name[20];

    snprintf(json_name, sizeof(json_name), "%lld", claim_item->label.int64);

    switch(claim_item->uDataType) {
        case QCBOR_TYPE_INT64:
            jtoken_encode_int64(ectx, json_name, claim_item->val.int64);
            break;

        case QCBOR_TYPE_UINT64:
            jtoken_encode_uint64(ectx, json_name, claim_item->val.uint64);
            break;

        case QCBOR_TYPE_DOUBLE:
            jtoken_encode_double(ectx, json_name, claim_item->val.dfnum);
            break;

        case QCBOR_TYPE_TEXT_STRING:
            jtoken_encode_text_string(ectx, json_name, claim_item->val.string);
            break;

        case QCBOR_TYPE_BYTE_STRING:
            jtoken_encode_byte_string(ectx, json_name, claim_item->val.string);
            break;

        case QCBOR_TYPE_TRUE:
        case QCBOR_TYPE_FALSE:
            bool_value = claim_item->uDataType == QCBOR_TYPE_TRUE;
            jtoken_encode_bool(ectx, json_name, bool_value);
            break;

        case QCBOR_TYPE_NULL:
            jtoken_encode_null(ectx, json_name);
            break;

        default:
            // TODO: some type that is not understood. Fix error code
            return 1;
            break;
    }

    return 0; // TODO: error handling
}


static enum xclaim_error_t
jtoken_output_claim(void *ctx, const struct xclaim *claim)
{
    struct jtoken_encode_ctx *me = ctx;

    switch(claim->qcbor_item.label.int64) {

        case CTOKEN_CWT_LABEL_ISSUER:
            jtoken_encode_issuer(me, claim->qcbor_item.val.string);
            break;

        case CTOKEN_CWT_LABEL_SUBJECT:
            jtoken_encode_subject(me, claim->qcbor_item.val.string);
            break;

        case CTOKEN_CWT_LABEL_AUDIENCE:
            jtoken_encode_audience(me, claim->qcbor_item.val.string);
            break;

        case CTOKEN_CWT_LABEL_EXPIRATION:
            jtoken_encode_expiration(me, claim->qcbor_item.val.int64);
            break;

        case CTOKEN_CWT_LABEL_NOT_BEFORE:
            jtoken_encode_not_before(me, claim->qcbor_item.val.int64);
            break;

        case CTOKEN_CWT_LABEL_IAT:
            jtoken_encode_iat(me, claim->qcbor_item.val.int64);
            break;

        case CTOKEN_CWT_LABEL_CTI:
            jtoken_encode_jti(me, claim->qcbor_item.val.string);
            break;

        case CTOKEN_EAT_LABEL_UEID:
            jtoken_encode_ueid(me, claim->qcbor_item.val.string);
            break;

        case CTOKEN_EAT_LABEL_NONCE:
            jtoken_encode_nonce(me, claim->qcbor_item.val.string);
            break;

        case CTOKEN_EAT_LABEL_SECURITY_LEVEL:
            jtoken_encode_security_level(me, (enum jtoken_security_level_t)claim->qcbor_item.val.int64);
            break;

        default:
            xclaim_encode_generic(me, &(claim->qcbor_item));
            break;
    }

    return 0;
}


static enum xclaim_error_t
jtoken_encode_start_submod_section_x(void *ctx)
{
    struct jtoken_encode_ctx *me = (struct jtoken_encode_ctx *)ctx;
    jtoken_encode_start_submod_section(me);
    return XCLAIM_SUCCESS;
}

static enum xclaim_error_t
jtoken_encode_end_submod_section_x(void *ctx)
{
    struct jtoken_encode_ctx *me = (struct jtoken_encode_ctx *)ctx;
    jtoken_encode_end_submod_section(me);
    return XCLAIM_SUCCESS;
}

static enum xclaim_error_t
jtoken_encode_open_submod_x(void *ctx, struct q_useful_buf_c submod_name )
{
    struct jtoken_encode_ctx *me = (struct jtoken_encode_ctx *)ctx;

    jtoken_encode_open_submod(me,  submod_name);
    return XCLAIM_SUCCESS;
}

static enum xclaim_error_t
jtoken_encode_close_submod_section_x(void *ctx)
{
    struct jtoken_encode_ctx *me = (struct jtoken_encode_ctx *)ctx;
    jtoken_encode_close_submod_section(me);
    return XCLAIM_SUCCESS;
}


enum xclaim_error_t jtoken_encode_output_nested_x(void                       *ctx,
                                                  const struct q_useful_buf_c submod_name,
                                                  struct q_useful_buf_c       nested_token)
{
    struct jtoken_encode_ctx *me = (struct jtoken_encode_ctx *)ctx;
    jtoken_encode_output_nested(me, submod_name, nested_token);
    return XCLAIM_SUCCESS;
}

int xclaim_jtoken_encode_init(xclaim_encoder *out, struct jtoken_encode_ctx *ctx)
{
    out->ctx = ctx;

    out->output_claim          = jtoken_output_claim;
    out->start_submods_section = jtoken_encode_start_submod_section_x;
    out->end_submods_section   = jtoken_encode_end_submod_section_x;
    out->open_submod           = jtoken_encode_open_submod_x;
    out->close_submod          = jtoken_encode_close_submod_section_x;
    out->output_nested         = jtoken_encode_output_nested_x;

    return 0;
}
