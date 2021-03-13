/*
 * openssl_keys.h
 *
 * Copyright (c) 2021, Laurence Lundblade.
 *
 * Created by Laurence Lundblade on 3/8/21.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */
#ifndef openssl_keys_h
#define openssl_keys_h

#include <t_cose/t_cose_common.h>


int read_private_ec_key_from_file(const char *file_name, struct t_cose_key *k);

int read_pub_ec_key_from_file(const char *file_name, struct t_cose_key *k);

void free_ec_key(struct t_cose_key k);


#endif /* openssl_keys_h */
