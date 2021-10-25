![Xclaim](https://github.com/laurencelundblade/xclaim/blob/master/xclaim-logo.png?raw=true)
 
*Xclaim* is a command line tool to encode and decode CWT, EAT, UCCS and at some point JWT. 
It is designed as a cross-bar switch to be able to transform any one format token 
into another. Here's a list of formats:

* CWT/EAT -- input and output supported
* UCCS -- input and output supported
* UNIX command line -- input only, an easy way to create tokens
* JSON -- output only, an easy-to-read text format 
* JWT -- planned for future, input and output

Since the CWT/EAT implementation can sign tokens, this works easily as
a tool to create signed tokens from the command line or to turn a UCCS
into a signed token and eventually to convert and re-sign a JWT token.
Similarly, it can be used to verify a CWT/EAT and output the claims
in an easy-to-ready JSON format, as an unsigned UCCS and eventually 
to re-sign as a JWT.  As of now CWT/EAT encryption is not supported,
but when it is, it will work the same way.

The following libraries are used to implement this:
* QCBOR for CBOR encoding and decoding
* t_cose for COSE signing and verification
* ctoken for EAT/CWT encoding and decoding
* OpenSSL or Mbed TLS crypto libraries

## Code State

Lots of code is working, but not tested and not very well bundled up into an easy-to-install package.
