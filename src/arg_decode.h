/*
 * arg_decode.h
 *
 * Copyright (c) 2021, Laurence Lundblade.
 *
 * Created by Laurence Lundblade on 1/29/21.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
*/

#ifndef arg_parse_h
#define arg_parse_h

#include "xclaim.h"

#include <stdbool.h>



/*

 */

struct ctoken_arguments {
    bool help;

    const char *input_file;
    const char *output_file;

    const char **claims;

    enum {IN_FORMAT_CBOR, IN_FORMAT_JSON} input_format;
    enum {OUT_FORMAT_CBOR, OUT_FORMAT_JSON} output_format;

    enum {IN_PROT_DETECT, IN_PROT_NONE, IN_PROT_SIGN, IN_PROT_MAC,
          IN_PROT_SIGN_ENCRYPT, IN_PROT_MAC_ENCRYPT} input_protection;

    enum {OUT_PROT_SIGN, OUT_PROT_NONE, OUT_PROT_MAC, OUT_PROT_SIGN_ENCRYPT,
          OUT_PROT_MAC_ENCRYPT} output_protection;

    enum {OUT_TAG_CWT, OUT_TAG_COSE, OUT_TAG_NONE} output_tagging;

    const char *out_sign_key_file;
    bool        out_sign_short_circuit;
    const char *out_certs_file;
    int32_t     out_sign_algorithm;
    struct q_useful_buf_c out_sign_kid;

    const char *in_verify_key_file;

    bool no_verify;
};


/**
 * @brief Main / initial parse of argv and put results into arguments stucture.
 *
 * @return 0 on success; 1 on failure
 *
 * free_arguments() must be called to deallocate memory that was allocated by this.
 */
int parse_arguments(int                      argc,
                    char                   **argv,
                    struct ctoken_arguments *arguments);


void free_arguments(struct ctoken_arguments *arguments);




/* Context for xclaim-style decoder that provides the claims
 from the command line arguments.
 */
struct claim_argument_decoder {

    const char **claim_args;

    const char **iterator;
};


/* Returns an initialized xclaim_decoder that
 will return all the claim arguments passed in
 as claims_args.
*/
void xclaim_argument_decode_init(xclaim_decoder *ic,
                                struct claim_argument_decoder *ctx,
                                const char **claims_args);



void print_arguments_help(void);


#endif /* arg_parse_h */
