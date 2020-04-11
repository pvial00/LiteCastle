#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include "ciphers/uvajda_oneshot.c"
#include "ciphers/amagus_oneshot.c"
#include "crypto_funcs.c"
#include "kdf/manja.c"
#include "ciphers/ganja.c"
#include "hmac/ghmac.c"
#include "ciphers/zanderfish3_cbc.c"
#include "keygen/keygen.c"

int main(int argc, char *argv[]) {
    struct termios tp, save;
    tcgetattr(STDIN_FILENO, &tp);
    save = tp;
    tp.c_lflag &= ~ECHO; 
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tp);
    int kdf_iterations = 100000;
    unsigned char kdf_salt[] = "LiteCastleZFish";
    int psize = 1536;
    char * prefix = "QloQ";
    if (argc < 2) {
        psize = 1536;
    }
    else {
        psize = atoi(argv[1]);
    }
    printf("Enter passphrase:");
    unsigned char * passphrase[256];
    scanf("%s", passphrase);
    unsigned char * passphrase_confirm[256];
    printf("\nEnter passphrase again:");
    scanf("%s", passphrase_confirm);
    if (strcmp(passphrase, passphrase_confirm) != 0) {
        printf("Error: Passphrase mismatch\n");
        tcsetattr(STDIN_FILENO, TCSANOW, &save);
        exit(1);
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &save);
    qloq_keygen(psize, prefix, passphrase, kdf_salt, kdf_iterations);
    return 0;
}

