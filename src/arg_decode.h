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
 -claim ll:vv

 -in <file>
 -out <file>

 -in_form CBOR, JSON
 -out_form CBOR, JSON, text, CBOR diag

 -in_prot none, sign, mac, sign_encrypt, mac_encrypt, auto
 -out_prot none, sign, mac, sign_encrypt, mac_encrypt

 -no_verify  The input file will be decoded, but any signature or mac will not be verified. No need to supply key material

 -out_sign_alg <alg>  Alg is one of the COSE signing algorithms
 -out_sign_key  <file>  private key to sign with
 -out_sign_kid  <kid>   Key ID associated with -out_sign_key
 -out_certs  <file>  cert for verifier to include in the output token
 -out_sign_short_circuit  Use short-circuit signature to sign with
 -out_encrypt_alg <alg> Alg is one of the COSE signing algorithms
 -out_encrypt_key public key to encrypt with


 -in_verify_key
 -in_verify_cert
 -in_decrypt_key

 -out_tag  none, full, cose

There must be an input that is either a file or some claims.
 If there is a file, it will be verified and key material must be given to do so.
 To skip verification use the -noverify option.


 Example of signing
  xclaim -out_sign_key foo.pem

 How to do key ID?
  - set COSE key ID header
  - add certificates in COSE headers
  - assume linkage to UEID or such
 */

struct ctoken_arguments {
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
    const char *out_sign_kid;
    const char *out_certs_file;
    int32_t     out_sign_algorithm;

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



#endif /* arg_parse_h */
