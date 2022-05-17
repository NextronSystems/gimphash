Build
-----

The C version currently depends on libyara (for PE parsing) and OpenSSL
(for SHA256 calculation). `pkg-config` is used to locate header files and static libraries.

Run `make` to compile.

Restrictions
------------
The C version is currently restricted to PE binaries. Other binary formats
(MACH-O. ELF, ...) are not yet supported.
