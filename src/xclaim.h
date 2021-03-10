/*
 * xclaim.h
 *
 * Copyright (c) 2021, Laurence Lundblade.
 *
 * Created by Laurence Lundblade on 2/17/21.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef xclaim_h
#define xclaim_h

#include "ctoken/ctoken.h"
#include "qcbor/qcbor_decode.h"

/*
 * This is a pair of abstract base classes for decoding and encoding
 * the contents of a token.
 *
 * This is designed to be implemented by calling various claim
 * decoding and encoding libraries like ctoken.
 */


/* This is the universal representation of an individual claim used to
 * go between the token decoders and the encoders. It may need
 * expanding as additional complex claims need to be handled.
 *
 * The identification of the type of the claim is in
 * claim->qcbor_item.label.int64 which is the integer label associated
 * with the CBOR format claim and the IANA CWT claim registry. If a
 * claim is not registered with IANA, values from the proprietary
 * space can be used here. If the claim identifier is not known to
 * this code and the data type for it is a non-aggregate type like a
 * text string, byte string, integer, float or boolean, then it will
 * be handled for the generic rules for thos well understood types.
 */
struct xclaim {
    QCBORItem  qcbor_item;
    union {
        struct ctoken_location_t location_claim;
    } u;
};


enum xclaim_error_t {
    XCLAIM_SUCCESS = 0,

    /* When decoding a token, there are no more claims or there are no
     * more submodules. */
    XCLAIM_NO_MORE = 1,

    /* When trying to open a submodule, the submodule is a nested
     * token. */
    XCLAIM_SUBMOD_IS_TOKEN = 2,

    XLCAIM_GENERAL_ERROR_BASE = 100,

    XCLAIM_CTOKEN_ERROR_BASE = 200,

    XCLAIM_JTOKEN_ERROR_BASE = 300,

    XCLAIM_ARG_ERROR_BASE = 400
};


/* This is an abstract base class for decoding a token. */
typedef struct {
    /* vtable */

    /* Get the next claim fom the input. This works for the top level
     * claims as well as for claims in the submodules.
     */
    enum xclaim_error_t (*next_claim)(void          *ctx,
                                      struct xclaim *claim);

    /* Enter the nth submodule so the claims and submodules in it can
     * be iterated over. The submodule's text name is returned.  This
     * should return XCLAIM_SUCCESS if the index is a submodule,
     * XCLAIM_SUBMOD_IS_TOKEN is a nested token and XCLAIM_NO_MORE if
     * the index is more than the number of submodules. 
     */
    enum xclaim_error_t (*enter_submod)(void *ctx,uint32_t     index,
                                        struct q_useful_buf_c *name);

    /* This is called when all the claims and submodules in a
     * submodule have been processed.
     */
    enum xclaim_error_t (*exit_submod)(void *ctx);

    /* This should be called when XCLAIM_SUBMOD_IS_TOKEN is returned
     * by enter_submod to get the nested token. It will not be
     * recursively entered. It will just be returned as an opaque
     * blob.
     */
    enum xclaim_error_t (*get_nested)(void                   *ctx,
                                      uint32_t               index,
                                      enum ctoken_type_t    *type,
                                      struct q_useful_buf_c *name,
                                      struct q_useful_buf_c *token);

    /* Some decoders will iterate over the whole token twice. The
     * first time is to calculate the size of the output. This is
     * called after the first pass. All decoders must support
     * rewind. */
    void (*rewind)(void *ctx);


    /* Context pointer for all above methods */
    void *ctx;
} xclaim_decoder;




/* This is an abstract base class for encoding a token. */
typedef struct  {
    /* vtable */

    /* Output an individual claim either at the main level or in a
     * submodule. */
    enum xclaim_error_t (*output_claim)(void                *ctx,
                                        const struct xclaim *claim);

    /* Called to start the submodules section. After this is called
     * only submodules will be output. There may be many submodules
     * per submodule section as submodules nest recursively. */
    enum xclaim_error_t (*start_submods_section)(void *ctx);

    /* Ends the submod section. */
    enum xclaim_error_t (*end_submods_section)(void *ctx);

    /* Starts a submodule. The submodules section must have been
     * started. Claims are added to a submodule by calling
     * output_claim. Submodules are added to a submodule recursively
     * by first starting a submodules section and then calling this
     * again.
     */
    enum xclaim_error_t (*open_submod)(void                       *ctx,
                                       const struct q_useful_buf_c submod_name);

    /* Close of a submodule. */
    enum xclaim_error_t (*close_submod)(void *ctx);

    /* Add a nested token to a submodules section. */
    enum xclaim_error_t (*output_nested)(void                       *ctx,
                                         const struct q_useful_buf_c submod_name,
                                         struct q_useful_buf_c       nested_token);

    /* Context pointer for all above methods */
    void *ctx;
} xclaim_encoder;




/* This will call will iterate over all claims from the decoder and
 * pass them to the encoder. The main complexity of work is the
 * recursive handling of submodules.
 *
 * Typical use is to configure the decoder object and the encoder
 * object and then call this.
 */
enum xclaim_error_t
xclaim_processor(xclaim_decoder *decoder, xclaim_encoder *encoder);


#endif /* xclaim_h */
