#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ciphers/uvajda_oneshot.c"
#include "ciphers/amagus_oneshot.c"
#include "crypto_funcs.c"
#include "kdf/manja.c"
#include "ciphers/ganja.c"
#include "hmac/ghmac.c"
#include "ciphers/zanderfish3_cbc.c"

void usage() {
    printf("LiteCastle v1.0 - by KryptoMagik\n\n");
    printf("Algorithm:  zanderfish3      512 bit\n");
    printf("Usage: lcastle <-e/-d> <input file> <output file> <password>\n\n");
}

int main(int argc, char *argv[]) {
    unsigned char kdf_salt[] = "LiteCastleZFish";
    int kdf_iterations = 100000;
    int max_password_len = 256;

    char *encrypt_symbol = "-e";
    char *decrypt_symbol = "-d";

    int zanderfish3_nonce_length = 32;

    int zanderfish3_key_length = 32;
    int zanderfish3_512_key_length = 64;
    int zanderfish3_1024_key_length = 128;

    int zanderfish3_mac_length = 32;

    int zanderfish3_bufsize = 262144;

    if (argc != 5) {
        usage();
        return 0;
    }

    FILE *infile, *outfile;
    char *infile_name, *outfile_name;
    char *algorithm = "zanderfish3-512";
    char *mode = argv[1];
    infile_name = argv[2];
    outfile_name = argv[3];
    unsigned char *password = argv[4];
    if (strlen(password) > max_password_len) {
        printf("Max password limit %d bytes has been exceeded.\n", max_password_len);
        exit(1);
    }
    if (access(infile_name, F_OK) == -1 ) {
        printf("%s not found\n", infile_name);
        exit(1);
    }
    infile = fopen(infile_name, "rb");
    fseek(infile, 0, SEEK_END);
    long fsize = ftell(infile);
    fclose(infile);

    if (strcmp(algorithm, "zanderfish3") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander3_cbc_encrypt(infile_name, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, zanderfish3_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander3_cbc_decrypt(infile_name, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, zanderfish3_bufsize);
        }
    } 
    else if (strcmp(algorithm, "zanderfish3-512") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander3_cbc_encrypt(infile_name, outfile_name, zanderfish3_512_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, password, keywrap512_ivlen, zanderfish3_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander3_cbc_decrypt(infile_name, outfile_name, zanderfish3_512_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, password, keywrap512_ivlen, zanderfish3_bufsize);
        }
    } 
    else if (strcmp(algorithm, "zanderfish3-1024") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander3_cbc_encrypt(infile_name, outfile_name, zanderfish3_1024_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, password, keywrap1024_ivlen, zanderfish3_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander3_cbc_decrypt(infile_name, outfile_name, zanderfish3_1024_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, password, keywrap1024_ivlen, zanderfish3_bufsize);
        }
    } 
    return 0;
}
