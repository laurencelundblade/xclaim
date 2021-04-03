# Makefile -- UNIX-style make for xclaim using OpenSSL crypto
#
# Copyright (c) 2019-2021, Laurence Lundblade. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# See BSD-3-Clause license in README.md
#

# ---- comment ---- 
# This is for OpenSSL Crypto. Adjust CRYPTO_INC and CRYPTO_LIB for the
# location of the openssl libraries on your build machine.

# This tries to find a local copy of QCBOR, t_cose and ctoken and use
# that. This is likely because xclaim was cloned recurively, but could
# also be because the makefile was pointed to a particular instance
# (by setting QCBOR_DIR, T_COSE_DIR or CTOKEN_DIR).  If a local copy
# can't be found, then the libraries are expected to be installed in
# /usr/local

# TODO: WARNING, this doesn't check dependency in QCBOR, t_cose and
# ctoken If you change these you have to manually rebuild them This
# needs to be fixed, but it isn't fixed yet.


# Place to look for include files for installed QCBOR, t_cose and ctoken
SYSTEM_INCLUDE=/usr/local/include


# ---- QCBOR location ----
# Location of local or recurively cloned QCBOR (if it is to be used)
QCBOR_DIR=QCBOR
ifneq ($(wildcard $(QCBOR_DIR)), )
    # This is for direct reference to QCBOR that is not installed in
    # /usr/local or some system location. 
    QCBOR_INC=-I $(QCBOR_DIR)/inc
    QCBOR_LIB=$(QCBOR_DIR)/libqcbor.a
    QCBOR_DEPENDENCY=$(QCBOR_LIB)
else
    # This is for reference to QCBOR that has been installed in
    # /usr/local/ or in some system location. This will typically
    # use dynamic linking if there is a libqcbor.so
    QCBOR_INC=-I $(SYSTEM_INCLUDE)
    QCBOR_LIB=-lqcbor
endif


# ---- t_cose location ----
# Location of local or recurively cloned t_cose (if it is to be used)
T_COSE_DIR=t_cose
ifneq ($(wildcard $(T_COSE_DIR)), )
    # This is for direct reference to t_cose that is not installed in
    # /usr/local or some system location. 
    T_COSE_INC= -I $(T_COSE_DIR)/inc
    T_COSE_LIB=$(T_COSE_DIR)/libt_cose.a
    T_COSE_DEPENDENCY=$(T_COSE_LIB)
else   

    # This is for reference to t_cose that has been installed in
    # /usr/local/ or in some system location. This will typically
    # use dynamic linking if there is a libqcbor.so
    T_COSE_INC=-I /usr/local/include
    T_COSE_LIB=-lt_cose
endif


# ---- ctoken location ----
# Location of local or recurively cloned ctoken (if it is to be used)
CTOKEN_DIR=ctoken
ifneq ($(wildcard $(CTOKEN_DIR)), )
    # This is for direct reference to ctoken that is not installed in
    # /usr/local or some system location. 
    CTOKEN_INC= -I $(CTOKEN_DIR)/inc
    CTOKEN_LIB=$(CTOKEN_DIR)/libctoken.a
else
    # This is for reference to ctoken that has been installed in
    # /usr/local/ or in some system location. This will typically
    # use dynamic linking if there is a libqcbor.so
    T_COSE_INC=-I /usr/local/include
    T_COSE_LIB=-lt_cose
endif


# ---- crypto configuration -----
# Set up for OpenSSL. This may have to be adjusted for your build environment.
#../../openssl/openssl-1.1.1b/include/openssl -I ../../openssl/openssl-1.1.1b/include
#../../openssl/openssl-1.1.1b/libcrypto.a
CRYPTO_INC=-I /usr/local/include
CRYPTO_LIB=-lcrypto


# ---- compiler configuration -----
# Optimize for size
C_OPTS=-Os -fPIC


# ---- the main body that is invariant ----
ALL_INC=$(CRYPTO_INC) $(QCBOR_INC) $(T_COSE_INC) $(CTOKEN_INC)
CFLAGS=$(ALL_INC) $(C_OPTS) $(CRYPTO_CONFIG_OPTS)

SRC_OBJ=src/arg_decode.o src/base64.o src/ctoken_adapt.o src/jtoken_adapt.o \
        src/jtoken_encode.o src/main.o src/useful_buf_malloc.o \
        src/useful_file_io.o src/xclaim.o src/openssl_keys.o src/help_text.o


all:	xclaim 

$(QCBOR_DIR)/libqcbor.a:
	make -C $(QCBOR_DIR)

$(T_COSE_DIR)/libt_cose.a:
	make -C $(T_COSE_DIR) -f Makefile.ossl

$(CTOKEN_DIR)/libctoken.a:
	make -C $(CTOKEN_DIR) -f Makefile.ossl


xclaim: $(SRC_OBJ) $(QCBOR_DEPENDENCY) $(T_COSE_DEPENDENCY) $(CTOKEN_DEPENDENCY)
	echo Lib locations: $(QCBOR_LIB) $(T_COSE_LIB) $(CTOKEN_LIB) $(CRYPTO_LIB)
	cc -o $@ $^ $(QCBOR_LIB) $(T_COSE_LIB) $(CTOKEN_LIB) $(CRYPTO_LIB) 


clean:
	rm -f $(SRC_OBJ) 

src/help_text.o: src/help_text.c
	cc -c src/help_text.c -o src/help_text.o


src/help_text.c:	src/help_text.txt
	echo 'const char *help_text =' > src/help_text.c
	cat src/help_text.txt | sed -e 's/^/    "/' -e 's/$$/\\n"/' >> src/help_text.c
	echo "    ;" >> src/help_text.c



# ---- source dependecies -----
src/arg_decode.o: src/arg_decode.h src/xclaim.h src/useful_buf_malloc.h
src/base64.o: src/base64.h
src/ctoken_adapt.o: src/ctoken_adapt.h src/xclaim.c
src/jtoken_adapt.o: src/jtoken_adapt.h src/jtoken_encode.h src/xclaim.h
src/jtoken_encode.o: src/jtoken_encode.h src/base64.h
src/main.o: src/arg_decode.h src/jtoken_adapt.h src/ctoken_adapt.h src/xclaim.h src/openssl_keys.h
src/useful_buf_malloc.o: src/useful_buf_malloc.h
src/useful_file_io.o: src/useful_file_io.h
src/claim.o: src/claim.h
src/openssl_keys.o: src/openssl_keys.h


# TODO: add dependency rules on local copy header files if configured to use them

