# LiteCastle

*** THIS PROJECT IS NO LONGER BEING DEVELOPED.  PLEASE USE DARKCASTLE.

*** Warning the cipher contained in this program is still undergoing cryptanalysis

*** This program may be used to encrypt arbitrary file sizes

LiteCastle is an authenticated file encryption program aiming to provide file encryption with a single symmetric cipher.  This program is intended for educational use until full cryptanalysis can be completed.

LiteCastle allows two people to exchange encrypted files using the Q'loQ public key encryption algorithm.  LiteCastle may also be used for general file encryption.

*** Works on Linux, MacOS X, FreeBSD

# Usage

Key generation:

qloq-keygen

Encryption:

lcastle -e inputfile outputfile pkfile skfile

Decryption:

lcastle -d inputfile outputfile skfile pkfile

# Algorithms and authenticators

Zanderfish3 512 bit authenticated with Ganja 256 bit - 256 bit IV length

https://github.com/pvial00/Zanderfish3
