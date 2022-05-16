Build
-----

The C version currently depends on libyara (for PE parsing) and OpenSSL
(for SHA256 calculation).

Compile using:

`CFLAGS=-I<path/to/yarasource>/libyara/include -I<path/to/opensslinstall>/include`
`LDFLAGS=<path/to/opensslinstall>/lib64/libcrypto.a <path/to/yarainstall>/lib/libyara.a`

Restrictions
------------
The C version is currently restricted to PE binaries. Other binary formats
(MACH-O. ELF, ...) are not yet supported.