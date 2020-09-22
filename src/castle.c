#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include "ciphers/uvajda_oneshot.c"
#include "ciphers/amagus_oneshot.c"
#include "crypto_funcs.c"
#include "kdf/manja.c"
#include "ciphers/ganja.c"
#include "hmac/ghmac.c"
#include "ciphers/zanderfish3_cbc.c"

void usage() {
    printf("LiteCastle v1.4 - by KryptoMagik\n\n");
    printf("Algorithm:  Zanderfish3-CBC      512 bit\n");
    printf("Usage:\nlcastle -e <input file> <output file> <public keyfile> <secret keyfile>\n");
    printf("lcastle -d <input file> <output file> <secret keyfile> <public keyfile>\n");
}

int main(int argc, char *argv[]) {
    unsigned char kdf_salt[] = "LiteCastleZFish";
    int kdf_iterations = 100000;
    int password_len = 256;

    char *encrypt_symbol = "-e";
    char *decrypt_symbol = "-d";

    int zanderfish3_nonce_length = 32;

    int zanderfish3_key_length = 32;
    int zanderfish3_512_key_length = 64;
    int zanderfish3_1024_key_length = 128;

    int zanderfish3_mac_length = 32;

    int zanderfish3_bufsize = 262144;

    if (argc != 6) {
        usage();
        return 0;
    }

    FILE *infile, *outfile;
    char *infile_name, *outfile_name, *keyfile1_name, *keyfile2_name;
    char *mode = argv[1];
    infile_name = argv[2];
    outfile_name = argv[3];
    keyfile1_name = argv[4];
    keyfile2_name = argv[5];
    if (access(infile_name, F_OK) == -1 ) {
        printf("%s not found\n", infile_name);
        exit(1);
    }
    infile = fopen(infile_name, "rb");
    fseek(infile, 0, SEEK_END);
    long fsize = ftell(infile);
    fclose(infile);
    struct termios tp, save;
    tcgetattr(STDIN_FILENO, &tp);
    save = tp;
    tp.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tp);

    unsigned char * passphrase[256];
    printf("Enter secret key passphrase: ");
    scanf("%s", passphrase);
    tcsetattr(STDIN_FILENO, TCSANOW, &save);

    if (strcmp(mode, encrypt_symbol) == 0) {
        zander3_cbc_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_512_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, password_len, keywrap512_ivlen, zanderfish3_bufsize, passphrase);
    }
    else if (strcmp(mode, decrypt_symbol) == 0) {
        zander3_cbc_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_512_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, password_len, keywrap512_ivlen, zanderfish3_bufsize, passphrase);
    }
    return 0;
}
