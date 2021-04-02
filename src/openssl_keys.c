/*
 * openssl_keys.c
 *
 * Copyright (c) 2021, Laurence Lundblade.
 *
 * Created by Laurence Lundblade on 3/8/21.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "openssl_keys.h"
#include <stdio.h>
#include <openssl/pem.h>
#include <string.h>
#include <sys/errno.h>


int read_private_ec_key_from_file(const char *file_name, struct t_cose_key *k)
{
    FILE     *key_file;
    EVP_PKEY *openssl_generic_private_key;
    EC_KEY   *ec_private_key;

    key_file = fopen(file_name, "r");
    if(key_file == NULL) {
        fprintf(stderr, "Error %s opening key file \"%s\"\n", strerror(errno), file_name);
        return 1;
    }

    // TODO: perhaps provide the password_cb so encrypted key files so encrypted files can work
    openssl_generic_private_key = PEM_read_PrivateKey(key_file,
                                                       NULL,
                                                       NULL, // pem_password_cb *cb,
                                                       NULL  // void *u;
                                                       );

    fclose(key_file);

    if(openssl_generic_private_key == NULL) {
        fprintf(stderr, "Unable to parse contents of key file \"%s\"\n", file_name);
        return 1;
    }

    ec_private_key = EVP_PKEY_get1_EC_KEY(openssl_generic_private_key);

    if(ec_private_key == NULL) {
        fprintf(stderr, "Key file \"%s\" does not contain a valid EC key\n", file_name);
        return 1;
    }

    k->crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    k->k.key_ptr = ec_private_key;

    // TODO: figure out about freeing the key.
    return 0;
}



int read_pub_ec_key_from_file(const char *file_name, struct t_cose_key *k)
{
    return read_private_ec_key_from_file(file_name, k);
}


void free_ec_key(struct t_cose_key k)
{
    if(k.crypto_lib == T_COSE_CRYPTO_LIB_OPENSSL &&
       k.k.key_ptr != NULL) {
        EC_KEY_free(k.k.key_ptr);
    }
}
