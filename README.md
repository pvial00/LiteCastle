# DarkCastle

*** Warning the cipher contained in this program is still undergoing cryptanalysis

*** Warning: this product is for non-production use.  If you want production level crypto, use OpenSSL or libsodium

*** This program may be used to encrypt arbitrary file sizes

LiteCastle is an authenticated file encryption program aiming to provide file encryption with a single cipher.  This program is intended for educational use until full cryptanalysis can be completed.

Please note these are efficient file encryption functions that buffer inputfile and write to the output file simultaneously

Complimenting LiteCastle is DarkPass, a password generator designed to give secure passwords compatible with LiteCastle.

https://github.com/pvial00/DarkPass

*** Tested on MacOS, FreeBSD, Linux, Solaris, OpenBSD, NetBSD


# Algorithms and authenticators

Zanderfish3 512 bit authenticated with Ganja 256 bit - 256 bit IV length

https://github.com/pvial00/Zanderfish3

Spock-CBC 256 bit authenticated with Ganja 256 bit - 128 bit nonce length

https://github.com/pvial00/Spock
