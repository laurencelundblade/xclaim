/*
 * ctoken_adapt.c
 *
 * Copyright (c) 2021, Laurence Lundblade.
 *
 * Created by Laurence Lundblade on 2/14/21.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "ctoken_adapt.h"

#include "ctoken/ctoken_encode.h"
#include "ctoken/ctoken_decode.h"

#include <stdio.h> /* For error prints */



int xclaim_encode_generic(struct ctoken_encode_ctx *ectx, const QCBORItem *claim_item)
{
    bool bool_value;

    switch(claim_item->uDataType) {
        case QCBOR_TYPE_INT64:
            ctoken_encode_add_integer(ectx, claim_item->label.int64, claim_item->val.int64);
            break;

        case QCBOR_TYPE_UINT64:
            ctoken_encode_add_unsigned(ectx, claim_item->label.int64, claim_item->val.uint64);
            break;

        case QCBOR_TYPE_DOUBLE:
            ctoken_encode_add_double(ectx, claim_item->label.int64, claim_item->val.dfnum);
            break;

        case QCBOR_TYPE_TEXT_STRING:
            ctoken_encode_add_tstr(ectx, claim_item->label.int64, claim_item->val.string);
            break;

        case QCBOR_TYPE_BYTE_STRING:
            ctoken_encode_add_bstr(ectx, claim_item->label.int64, claim_item->val.string);
            break;

        case QCBOR_TYPE_TRUE:
        case QCBOR_TYPE_FALSE:
            bool_value = claim_item->uDataType == QCBOR_TYPE_TRUE;
            ctoken_encode_add_bool(ectx, claim_item->label.int64, bool_value);
            break;

        case QCBOR_TYPE_NULL:
            ctoken_encode_add_null(ectx, claim_item->label.int64);
            break;

        default:
            // TODO: some type that is not understood. Fix error code
            return 1;
            break;
    }

    return 0; // TODO: error handling
}


static enum xclaim_error_t
encode_xclaim(void *ctx, const struct xclaim *claim)
{
    struct ctoken_encode_ctx *e_ctx = (struct ctoken_encode_ctx *)ctx;
    switch(claim->qcbor_item.label.int64) {

        case CTOKEN_CWT_LABEL_ISSUER:
            ctoken_encode_issuer(e_ctx, claim->qcbor_item.val.string);
            break;

        case CTOKEN_EAT_LABEL_LOCATION:
            ctoken_encode_location(e_ctx, &(claim->u.location_claim));
            break;

        case CTOKEN_CWT_LABEL_SUBJECT:
            ctoken_encode_subject(e_ctx, claim->qcbor_item.val.string);
            break;

        case CTOKEN_CWT_LABEL_AUDIENCE:
            ctoken_encode_audience(e_ctx, claim->qcbor_item.val.string);
            break;

        case CTOKEN_CWT_LABEL_EXPIRATION:
            ctoken_encode_expiration(e_ctx, claim->qcbor_item.val.int64);
            break;

        case CTOKEN_CWT_LABEL_NOT_BEFORE:
            ctoken_encode_not_before(e_ctx, claim->qcbor_item.val.int64);
            break;

        case CTOKEN_CWT_LABEL_IAT:
            ctoken_encode_iat(e_ctx, claim->qcbor_item.val.int64);
            break;

        case CTOKEN_CWT_LABEL_CTI:
            ctoken_encode_cti(e_ctx, claim->qcbor_item.val.string);
            break;

        case CTOKEN_EAT_LABEL_UEID:
            ctoken_encode_ueid(e_ctx, claim->qcbor_item.val.string);
            break;

        case CTOKEN_EAT_LABEL_NONCE:
            ctoken_encode_nonce(e_ctx, claim->qcbor_item.val.string);
            break;

        case CTOKEN_EAT_LABEL_SECURITY_LEVEL:
            ctoken_encode_security_level(e_ctx, (enum ctoken_security_level_t)claim->qcbor_item.val.int64);
            break;

        default:
            xclaim_encode_generic(e_ctx, &(claim->qcbor_item));
            break;
    }

    return 0;
}


static enum xclaim_error_t
ctoken_encode_open_submod_x(void *ctx, struct q_useful_buf_c submod_name)
{
    // TODO: make xclaim encode return NULL?
    struct ctoken_encode_ctx *e_ctx = (struct ctoken_encode_ctx *)ctx;
    ctoken_encode_open_submod(e_ctx, submod_name);
    return XCLAIM_SUCCESS;
}


static enum xclaim_error_t
ctoken_encode_close_submod_x(void *ctx)
{
    struct ctoken_encode_ctx *e_ctx = (struct ctoken_encode_ctx *)ctx;
    ctoken_encode_close_submod(e_ctx);
    return XCLAIM_SUCCESS;
}


static enum xclaim_error_t
ctoken_encode_start_submod_section_x(void *ctx)
{
    struct ctoken_encode_ctx *e_ctx = (struct ctoken_encode_ctx *)ctx;
    ctoken_encode_start_submod_section(e_ctx);
    return XCLAIM_SUCCESS;
}


static enum xclaim_error_t
ctoken_encode_end_submod_section_x(void *ctx)
{
    struct ctoken_encode_ctx *e_ctx = (struct ctoken_encode_ctx *)ctx;
    ctoken_encode_end_submod_section(e_ctx);
    return XCLAIM_SUCCESS;
}

void xclaim_ctoken_encode_init(xclaim_encoder *out, struct ctoken_encode_ctx *ctx)
{
    out->ctx = ctx;

    out->output_claim          = encode_xclaim;
    out->open_submod           = ctoken_encode_open_submod_x;
    out->close_submod          = ctoken_encode_close_submod_x;
    out->start_submods_section = ctoken_encode_start_submod_section_x;
    out->end_submods_section   = ctoken_encode_end_submod_section_x;
}




static enum xclaim_error_t
decode_next_xclaim(void *decode_ctx, struct xclaim *xclaim)
{
    enum ctoken_err_t         err;
    enum xclaim_error_t       return_value;
    struct ctoken_decode_ctx *dctx = (struct ctoken_decode_ctx *)decode_ctx;

    err = ctoken_decode_next_claim(dctx, &(xclaim->qcbor_item));
    if(err == CTOKEN_ERR_NO_MORE_CLAIMS) {
        /* End of claims or error getting them. */
        return_value =  XCLAIM_NO_MORE;
        goto Done;
    } else if(err != 0) {
        return_value = (enum xclaim_error_t)XCLAIM_CTOKEN_ERROR_BASE + err;
        goto Done;
    }
    return_value = XCLAIM_SUCCESS;

    if(xclaim->qcbor_item.label.int64 == CTOKEN_EAT_LABEL_LOCATION) {
       ctoken_decode_location(dctx, &(xclaim->u.location_claim));
    } else {
        /* Nothing to do. The qcbor_item has everything that is needed. */
    }

Done:
    return return_value;
}



static enum xclaim_error_t
enter_submod(void *decode_ctx, uint32_t submod_index, struct q_useful_buf_c *submod_name)
{
    struct ctoken_decode_ctx *dctx = (struct ctoken_decode_ctx *)decode_ctx;

    enum ctoken_err_t error;

    error = ctoken_decode_enter_nth_submod(dctx, submod_index, submod_name);

    if(error == CTOKEN_ERR_SUBMOD_NOT_FOUND) {
        return XCLAIM_NO_MORE;
    } else if(error == CTOKEN_ERR_SUCCESS) {
        return XCLAIM_SUCCESS;
    } else if(error == CTOKEN_ERR_SUBMOD_IS_A_TOKEN) {
        return XCLAIM_SUBMOD_IS_TOKEN;
    } else {
        return XCLAIM_CTOKEN_ERROR_BASE + error;
    }
}


static enum xclaim_error_t
exit_submod(void *decode_ctx)
{
    struct ctoken_decode_ctx *dctx = (struct ctoken_decode_ctx *)decode_ctx;

    enum ctoken_err_t error;

    error = ctoken_decode_exit_submod(dctx);

    if(error == CTOKEN_ERR_SUCCESS) {
        return XCLAIM_SUCCESS;
    } else {
        return XCLAIM_CTOKEN_ERROR_BASE + error;
    }
}


static enum xclaim_error_t
get_nth_nested_token(void                   *decode_ctx,
                     uint32_t                submod_index,
                     enum ctoken_type_t     *type,
                     struct q_useful_buf_c  *submod_name,
                     struct q_useful_buf_c  *token)
{
    struct ctoken_decode_ctx *dctx = (struct ctoken_decode_ctx *)decode_ctx;

    enum ctoken_err_t error;

    error = ctoken_decode_get_nth_nested_token(dctx, submod_index, type, submod_name, token);

    if(error == CTOKEN_ERR_SUCCESS) {
        return XCLAIM_SUCCESS;
    } else {
        return XCLAIM_CTOKEN_ERROR_BASE + error;
    }
}


static void
xclaim_ctoken_decode_setup(xclaim_decoder *ic, struct ctoken_decode_ctx *ctx)
{
    ic->ctx = ctx;

    /* Fill in the vtable */
    ic->next_claim   = decode_next_xclaim;
    ic->enter_submod = enter_submod;
    ic->exit_submod  = exit_submod;
    ic->get_nested   = get_nth_nested_token;
    /* Can use ctoken method directly, but need a cast to void * */
    ic->rewind       = (void (*)(void *))ctoken_decode_rewind;
}


int xclaim_ctoken_decode_init(xclaim_decoder           *xclaim_decoder,
                              struct ctoken_decode_ctx *ctx,
                              struct q_useful_buf_c     input_bytes,
                              struct t_cose_key         verification_key)
{
    enum ctoken_err_t error;

    ctoken_decode_init(ctx, 0, 0, CTOKEN_PROTECTION_NONE);

    if(verification_key.k.key_ptr != NULL) {
        ctoken_decode_set_verification_key(ctx, verification_key);
    }

    error = ctoken_decode_validate_token(ctx, input_bytes);
    if(error) {
        fprintf(stderr, "token validation failed. Ctoken error %d\n", error);
        return -9;
    }

    xclaim_ctoken_decode_setup(xclaim_decoder, ctx);

    return 0;
}

