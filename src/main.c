//
//  decode_token.c
//  CToken
//
//  Created by Laurence Lundblade on 1/11/21.
//  Copyright © 2021 Laurence Lundblade. All rights reserved.
//

#include "t_cose/q_useful_buf.h"
#include <stdlib.h>
#include <fcntl.h>
#include "ctoken/ctoken_decode.h"
#include <sys/errno.h>
#include "ctoken/ctoken_encode.h"

#include "arg_decode.h"

#include "jtoken_adapt.h"
#include "ctoken_adapt.h"

#include <stdint.h>

#include "useful_file_io.h"
#include "openssl_keys.h"

#include "xclaim.h"




/* This drives the encoding of the input in CBOR using ctoken. */
int encode_as_cbor(xclaim_decoder *xclaim_decoder,
                   FILE           *output_file,
                   const struct ctoken_arguments *arguments)
{
    xclaim_encoder            xclaim_encoder;
    struct ctoken_encode_ctx  ctoken_encoder;
    struct q_useful_buf       out_buf;
    struct q_useful_buf_c     completed_token;
    enum ctoken_protection_t  protection_type;
    enum xclaim_error_t       xclaim_err;
    int32_t                   cose_signing_alg;
    uint32_t                  t_cose_opt_flags;
    uint32_t                  ctoken_opt_flags;
    enum ctoken_err_t         ctoken_err;
    struct t_cose_key         out_sign_key;


    // TODO: this should not be necessary
    memset(&ctoken_encoder, 0, sizeof(struct ctoken_encode_ctx));

    cose_signing_alg = -7;
    t_cose_opt_flags = 0;
    ctoken_opt_flags = 0;

    switch(arguments->output_protection) {
        case OUT_PROT_NONE:
            protection_type = CTOKEN_PROTECTION_NONE;
            // TODO: could complain if key file and such are set
            break;

        case OUT_PROT_SIGN:
            protection_type = CTOKEN_PROTECTION_COSE_SIGN1;
            cose_signing_alg = arguments->out_sign_algorithm;
            if(cose_signing_alg == 0) {
                cose_signing_alg = -7; // TODO: constant for this
            }
            if(arguments->out_sign_short_circuit) {
                // TODO: warn if key and such are set
                t_cose_opt_flags |= T_COSE_OPT_SHORT_CIRCUIT_SIG;

            }
            // TODO: will have to handle sign and protect combo
            // TODO: need to set up further...
            break;

        default:
            return 99; // TODO: error code
    }


    memset(&out_sign_key, 0, sizeof(struct t_cose_key));

    if(arguments->out_sign_key_file != NULL) {
        int err = read_private_ec_key_from_file(arguments->out_sign_key_file, &out_sign_key);
        if(err) {
            return 77;
        }
    }


    /* Set up the ctoken encoder with all the necessary options.
       This is a lot. There is a lot of work to do. */
    // TODO: further set up needed.
    ctoken_encode_init(&ctoken_encoder,
                       t_cose_opt_flags,
                       ctoken_opt_flags,
                       protection_type,
                       cose_signing_alg);

    if(arguments->out_sign_key_file != NULL) {
        ctoken_encode_set_key(&ctoken_encoder,
                              out_sign_key,
                              NULLUsefulBufC); // TODO: fix the kid
                              //arguments->out_sign_kid);
    }

    /* Set up the xclaim decoder to work with ctoken. */
    xclaim_ctoken_encode_init(&xclaim_encoder, &ctoken_encoder);


    // Loop only executes twice, once to compute size then to actually created token
    out_buf = (struct q_useful_buf){NULL, SIZE_MAX};

    while(1) {
        ctoken_encode_start(&ctoken_encoder, out_buf);

        xclaim_err = xclaim_processor(xclaim_decoder, &xclaim_encoder);
        if(xclaim_err != XCLAIM_SUCCESS) {
            goto Done;
        }

        ctoken_err = ctoken_encode_finish(&ctoken_encoder, &completed_token);
        if(ctoken_err != CTOKEN_ERR_SUCCESS) {
            goto Done;
        }

        if(out_buf.ptr != NULL) {
            // Normal exit from loop
            break;
        }

        out_buf.ptr = malloc(completed_token.len);
        out_buf.len = completed_token.len;
    }

    write_bytes(output_file, completed_token);

Done:
    if(out_buf.ptr != NULL) {
        free(out_buf.ptr);
    }

    return 0; // TODO: error code
}




int encode_as_json(xclaim_decoder *in, FILE *output_file)
{
    xclaim_encoder output;
    struct jtoken_encode_ctx jo;

    jo.out_file = output_file;

    xclaim_jtoken_encode_init(&output, &jo);

    jtoken_encode_start(&jo);

    xclaim_processor(in, &output);

    jtoken_encode_finish(&jo);

    // TODO: error handling

    return 0;
}




int ctoken(const struct ctoken_arguments *arguments)
{
    struct q_useful_buf_c    input_bytes = NULL_Q_USEFUL_BUF_C;
    FILE                    *output_file;
    struct ctoken_decode_ctx cctx;
    struct claim_argument_decoder parg;

    xclaim_decoder decoder;

    /* Set up the xlaim_decoder object first. The type of this object
       depends on the input type (e.g. CBOR or command line arguments
       (eventually JWT too)). The decoder object will be called by
     the outputter to iterate over all the claims. */
    if(arguments->input_file) {

        /* Input is a file, not claim arguments */
        if(arguments->claims) {
            fprintf(stderr, "Can't give -in option and -claim option at the same time (yet)\n");
            return -9;
        }

        int file_descriptor;
        if(!strcmp(arguments->input_file, "-")) {
            file_descriptor = 0;
        } else {
            file_descriptor = open(arguments->input_file, O_RDONLY);
            if(file_descriptor < 0) {
                fprintf(stderr, "can't open input file \"%s\" (%d)\n", arguments->input_file, errno);
                return -1;
            }
        }
        input_bytes = read_file(file_descriptor);
        if(UsefulBuf_IsNULLC(input_bytes)) {
            fprintf(stderr, "error reading input file \"%s\"\n", arguments->input_file);
            return -2;
        }

        // TODO: need to handle JSON too. This assumes file is CBOR
        // TODO: key material and options for decoding CBOR

        struct t_cose_key v_key;
        v_key.crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
        v_key.k.key_ptr = NULL;
        if(arguments->in_verify_key_file) {
            int x = read_pub_ec_key_from_file(arguments->in_verify_key_file, &v_key);
            if(x) {
                return 999;
            }

        }
        if(xclaim_ctoken_decode_init(&decoder, &cctx, input_bytes, v_key)) {
            return 1;
        }

    } else {
        if(arguments->claims) {
            /* input is some claim arguments. */
            xclaim_argument_decode_init(&decoder, &parg, arguments->claims);

        } else {
            fprintf(stderr, "No input given (neither -in or -claim given)\n");
            return -88;
        }
    }


    /* Set up output file to which whatever is done will be written. */
    if(arguments->output_file) {
        output_file = fopen(arguments->output_file, "w");
        if(output_file == NULL) {
            fprintf(stderr, "error opening output file \"%s\"\n", arguments->output_file);
            return -4;
        }
    } else {
        output_file = stdout;
    }


    /* Call the outputter to do the actual work */
    if(arguments->output_format == OUT_FORMAT_CBOR) {
        encode_as_cbor(&decoder, output_file, arguments);

    } else {
        encode_as_json(&decoder, output_file);

    }

    fclose(output_file);

    return 0;
}




int main(int argc, char * argv[])
{
    int return_value = 0;

    struct ctoken_arguments arguments;

    return_value = parse_arguments(argc, argv, &arguments);
    if(return_value != 0) {
        return return_value;
    }

    return_value = ctoken(&arguments);

    free_arguments(&arguments);

    return return_value;
}



/*
 args to json X
 args to cbor
 cbor to json X
 cbor to cbor




 */
