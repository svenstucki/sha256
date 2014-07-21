# SHA-256 Implementation

This is a very basic implementation of a SHA-256 hash according to the [FIPS
180-4 standard](http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf)
in C. I did it for educational purposes, the code is not optimized at all.

It does not have any dependencies (except for the C standard library of course)
and can be compiled with `make`. When `sha256sum` is installed, a short test can
be run with `make test`.

