/*
 * main.c for xclaim
 *
 * Copyright (c) 2021, Laurence Lundblade.
 *
 * Created by Laurence Lundblade on 2/14/21.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
*/

#include "t_cose/q_useful_buf.h"
#include <stdlib.h>
#include <fcntl.h>
#include "ctoken/ctoken_decode.h"
#include <sys/errno.h>
#include "ctoken/ctoken_encode.h"
#include <string.h>

#include "arg_decode.h"

#include "jtoken_adapt.h"
#include "ctoken_adapt.h"

#include <stdint.h>

#include "useful_file_io.h"
#include "openssl_keys.h"

#include "xclaim.h"




/* This drives the encoding of the output in CBOR using ctoken. */
int encode_as_cbor(xclaim_decoder                *xclaim_decoder,
                   FILE                          *output_file,
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

    cose_signing_alg = T_COSE_ALGORITHM_ES256;
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
                cose_signing_alg = T_COSE_ALGORITHM_ES256;
            }
            if(arguments->out_sign_short_circuit) {
                // TODO: warn if key and such are set
                t_cose_opt_flags |= T_COSE_OPT_SHORT_CIRCUIT_SIG;

            }
            // TODO: will have to handle sign and protect combo
            // TODO: need to set up further...
            break;

        default:
            return 1;
    }


    memset(&out_sign_key, 0, sizeof(struct t_cose_key));

    if(arguments->out_sign_key_file != NULL) {
        int err = read_private_ec_key_from_file(arguments->out_sign_key_file, &out_sign_key);
        if(err) {
            return 1;
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
                              arguments->out_sign_kid);

    }

    /* Set up the xclaim decoder to work with ctoken. */
    xclaim_ctoken_encode_init(&xclaim_encoder, &ctoken_encoder);


    /* Loop only executes twice, once to compute size then to actually
     * created token */
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
            /* Normal exit from loop */
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

    return 0;
}



/* This drives the encoding of the output in JSONB using jtoken.
 * Unlike ctoken, jtoken is a limited and primitive encoder. It
 * doesn't support signing or decoding
 */
int encode_as_json(xclaim_decoder *in, FILE *output_file)
{
    xclaim_encoder           output;
    struct jtoken_encode_ctx jo;
    enum xclaim_error_t      xclaim_error;

    jo.out_file = output_file;

    xclaim_jtoken_encode_init(&output, &jo);

    jtoken_encode_start(&jo);

    xclaim_error = xclaim_processor(in, &output);
    if(xclaim_error != XCLAIM_SUCCESS) {
        fprintf(stderr, "Error processing claims %d\n", xclaim_error);
        goto Done;
    }

    jtoken_encode_finish(&jo);

    // TODO: error handling
Done:
    return xclaim_error;
}



/* Does the main work of xclaim aside from argument parsing. */
int xclaim_main(const struct ctoken_arguments *arguments)
{
    struct q_useful_buf_c         input_bytes;
    FILE                         *output_file;
    struct ctoken_decode_ctx      cctx;
    struct claim_argument_decoder parg;
    struct t_cose_key             verification_key;
    xclaim_decoder                decoder;
    int                           return_value;

    verification_key.crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    verification_key.k.key_ptr = NULL;

    output_file = NULL;

    input_bytes = NULL_Q_USEFUL_BUF_C;

    return_value = 0;


    /* Set up the xlaim_decoder object first. The type of this object
     * depends on the input type (e.g. CBOR or command line arguments
     * (eventually JWT too)). The decoder object will be called by
     *   (eventually JWT too)). The decoder object will be called by
     * the outputter to iterate over all the claims. */
    if(arguments->input_file) {

        /* Input is a file, not claim arguments */
        if(arguments->claims) {
            fprintf(stderr, "Can't give -in option and -claim option at the same time (yet)\n");
            fprintf(stderr, "\xclaim -help\" for xclaim options\n");
            return_value = 1;
            goto Done;
        }

        int file_descriptor;
        if(!strcmp(arguments->input_file, "-")) {
            file_descriptor = 0;
        } else {
            file_descriptor = open(arguments->input_file, O_RDONLY);
            if(file_descriptor < 0) {
                fprintf(stderr,
                        "can't open input file \"%s\" (%s)\n",
                        arguments->input_file,
                        strerror(errno));
                return_value = 1;
                goto Done;
            }
        }
        input_bytes = read_file(file_descriptor);
        if(UsefulBuf_IsNULLC(input_bytes)) {
            fprintf(stderr,
                    "error reading input file \"%s\" (%s)\n",
                    arguments->input_file,
                    strerror(errno));
            return_value = 1;
            goto Done;
        }
        if(UsefulBuf_IsEmptyC(input_bytes)){
            fprintf(stderr,
                    "input  \"%s\" is empty\n",
                    arguments->input_file);
            return_value = 1;
            goto Done;
        }

        // TODO: need to handle JSON input too. This assumes file is CBOR for now
        if(arguments->in_verify_key_file) {
            int x = read_pub_ec_key_from_file(arguments->in_verify_key_file, &verification_key);
            if(x) {
                return_value = 1;
                goto Done;
            }

        }
        if(xclaim_ctoken_decode_init(&decoder, &cctx, input_bytes, verification_key)) {
            return_value = 1;
            goto Done;
        }

    } else {
        if(arguments->claims) {
            /* input is some claim arguments. */
            xclaim_argument_decode_init(&decoder, &parg, arguments->claims);

        } else {
            fprintf(stderr, "No input given (neither -in or -claim given)\n");
            fprintf(stderr, "\"xclaim -help\" for xclaim options\n");
            return_value = 1;
            goto Done;        }
    }


    /* Set up output file to for CBOR, JSON... */
    if(arguments->output_file) {
        output_file = fopen(arguments->output_file, "w");
        if(output_file == NULL) {
            fprintf(stderr, "error opening output file \"%s\" (%s)\n",
                    arguments->output_file,
                    strerror(errno));
            goto Done;
        }
    } else {
        output_file = stdout;
    }


    /* Call the outputter to do the actual work */
    if(arguments->output_format == OUT_FORMAT_CBOR) {
        return_value = encode_as_cbor(&decoder, output_file, arguments);

    } else {
        return_value = encode_as_json(&decoder, output_file);

    }

Done:
    if(output_file != NULL) {
        fclose(output_file);
    }

    free_ec_key(verification_key);

    return return_value;
}




int main(int argc, char * argv[])
{
    int return_value = 0;

    struct ctoken_arguments arguments;

    return_value = parse_arguments(argc, argv, &arguments);
    if(return_value != 0) {
        return return_value;
    }

    if(arguments.help) {
        print_arguments_help();

    } else {
        /* This is where the all the real work happens */
        return_value = xclaim_main(&arguments);
    }

    free_arguments(&arguments);

    return return_value;
}

