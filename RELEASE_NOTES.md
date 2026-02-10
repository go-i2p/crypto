Release notes for: `crypto` Version `0.1.4`
==============================================

This release adds preliminary, untested support for Argon2ID as a KeyDeriver.
It is unused in the rest of the `go-i2p` codebase at this time and should not affect anything.
Other than that, the library is unchanged.

Release notes for: `crypto` Version `0.1.3`
==============================================

This release resolves a compilation issue introduced during late December due to a peculiar build environment.
This code was intended to analyze information in the NetDB for unusual patterns by identifying(in a granular way) keys which are invalid.
It is necessary to resolve other compilation issues in the go-i2p library stack.

Thanks to @Nick2k4L for pointing out the issue.
