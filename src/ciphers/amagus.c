#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int amagus_rounds = 10;

struct amagus_state {
    uint64_t r[16];
    int keylen;
};

uint64_t amagus_rl(uint64_t a, uint64_t b) {
    return ((a << b) | (a >> (64 - b)));
}

uint64_t amagus_rr(uint64_t a, uint64_t b) {
    return ((a >> b) | (a << (64 - b)));
}

void *amagus_F(struct amagus_state *state) {
    int r;
    for (r = 0; r < amagus_rounds; r++) {
        state->r[0] += state->r[6];
        state->r[1] ^= state->r[15];
        state->r[2] = amagus_rl((state->r[2] ^ state->r[12]), 9);
        state->r[3] += state->r[9];
        state->r[4] ^= state->r[11];
        state->r[5] = amagus_rr((state->r[5] ^ state->r[10]), 6);
        state->r[6] += state->r[13];
        state->r[7] ^= state->r[8];
        state->r[8] = amagus_rl((state->r[8] ^ state->r[3]), 11);
        state->r[9] += state->r[1];
        state->r[10] ^= state->r[4];
        state->r[11] = amagus_rr((state->r[8] ^ state->r[7]), 7);
        state->r[12] += state->r[0];
        state->r[13] ^= state->r[2];
        state->r[14] = amagus_rl((state->r[14] ^ state->r[0]), 3);
        state->r[15] += state->r[5];
        
        state->r[15] += state->r[6];
        state->r[2] ^= state->r[15];
        state->r[14] = amagus_rl((state->r[14] ^ state->r[12]), 9);
        state->r[4] += state->r[9];
        state->r[13] ^= state->r[11];
        state->r[6] = amagus_rr((state->r[6] ^ state->r[10]), 6);
        state->r[12] += state->r[13];
        state->r[8] ^= state->r[8];
        state->r[11] = amagus_rl((state->r[11] ^ state->r[3]), 11);
        state->r[10] += state->r[1];
        state->r[1] ^= state->r[4];
        state->r[3] = amagus_rr((state->r[3] ^ state->r[7]), 7);
        state->r[5] += state->r[0];
        state->r[7] ^= state->r[2];
        state->r[9] = amagus_rl((state->r[9] ^ state->r[0]), 3);
        state->r[0] += state->r[5];
    }
}

void amagus_keysetup(struct amagus_state *state, unsigned char *key, unsigned char *nonce) {
    uint64_t n[2];
    int i;
    int m = 0;
    int inc = 8;
    memset(state->r, 0, (16*(sizeof(uint64_t))));
    for (i = 0; i < (state->keylen / 8); i++) {
        state->r[i] = 0;
        state->r[i] = ((uint64_t)(key[m]) << 56) + ((uint64_t)key[m+1] << 48) + ((uint64_t)key[m+2] << 40) + ((uint64_t)key[m+3] << 32) + ((uint64_t)key[m+4] << 24) + ((uint64_t)key[m+5] << 16) + ((uint64_t)key[m+6] << 8) + (uint64_t)key[m+7];
        m += inc;
    }
  
    n[0] = ((uint64_t)nonce[0] << 56) + ((uint64_t)nonce[1] << 48) + ((uint64_t)nonce[2] << 40) + ((uint64_t)nonce[3] << 32) + ((uint64_t)nonce[4] << 24) + ((uint64_t)nonce[5] << 16) + ((uint64_t)nonce[6] << 8) + (uint64_t)nonce[7];
    n[1] = ((uint64_t)nonce[8] << 56) + ((uint64_t)nonce[9] << 48) + ((uint64_t)nonce[10] << 40) + ((uint64_t)nonce[11] << 32) + ((uint64_t)nonce[12] << 24) + ((uint64_t)nonce[13] << 16) + ((uint64_t)nonce[14] << 8) + (uint64_t)nonce[15];

    state->r[14] = state->r[0] ^ n[0];
    state->r[15] = state->r[1] ^ n[1];


    for (int i = 0; i < amagus_rounds; i++) {
        amagus_F(state);
    }
}

void * amagus_crypt(unsigned char * data, unsigned char * key, int keylen, unsigned char * nonce, long datalen) {
    struct amagus_state state;
    state.keylen = keylen;
    long c = 0;
    int i = 0;
    int l = 8;
    uint64_t output;
    int k[8] = {0};
    long blocks = datalen / 8;
    long extra = datalen % 8;
    if (extra != 0) {
        blocks += 1;
    }
    amagus_keysetup(&state, key, nonce);
    for (long b = 0; b < blocks; b++) {
        amagus_F(&state);
        output = (state.r[0] ^ state.r[1] ^ state.r[2] ^ state.r[3] ^ state.r[4] ^ state.r[5] ^ state.r[6] ^ state.r[5] ^ state.r[6] ^ state.r[7] ^ state.r[8] ^ state.r[9] ^ state.r[10] ^ state.r[11] ^ state.r[12] ^ state.r[13] ^ state.r[14] ^ state.r[15]);
        k[0] = (output & 0x00000000000000FF);
        k[1] = (output & 0x000000000000FF00) >> 8;
        k[2] = (output & 0x0000000000FF0000) >> 16;
        k[3] = (output & 0x00000000FF000000) >> 24;
        k[4] = (output & 0x000000FF00000000) >> 32;
        k[5] = (output & 0x0000FF0000000000) >> 40;
        k[6] = (output & 0x00FF000000000000) >> 48;
        k[7] = (output & 0xFF00000000000000) >> 56;
        if (b == (blocks - 1) && (extra != 0)) {
            l = extra;
        }

	for (i = 0; i < l; i++) {
            data[c] = data[c] ^ k[i];
            c += 1;
	}
    }
}

void * amagus_encrypt(char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password,  int keywrap_ivlen, int bufsize) {
    FILE *infile, *outfile;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char nonce[nonce_length];
    amagus_random(&nonce, nonce_length);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    unsigned char *kwnonce[keywrap_ivlen];
    key_wrap_encrypt(keyprime, key_length, key, K, kwnonce);
    infile = fopen(inputfile, "rb");
    outfile = fopen(outputfile, "wb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    fwrite(kwnonce, 1, keywrap_ivlen, outfile);
    fwrite(nonce, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);
    struct amagus_state state;
    state.keylen = key_length;
    long c = 0;
    int i = 0;
    int l = 8;
    uint64_t output;
    int k[bufsize];
    memset(k, 0, bufsize);
    uint64_t blocks = datalen / bufsize;
    int extra = datalen % bufsize;
    if (extra != 0) {
        blocks += 1;
    }
    amagus_keysetup(&state, keyprime, nonce);
    for (uint64_t b = 0; b < blocks; b++) {
        fread(&buffer, 1, bufsize, infile);
        c = 0;
        if ((b == (blocks -1)) && (extra != 0)) {
            bufsize = extra;
        }
        for (i = 0; i < (bufsize / 8); i++) {
            amagus_F(&state);
            output = (state.r[0] ^ state.r[1] ^ state.r[2] ^ state.r[3] ^ state.r[4] ^ state.r[5] ^ state.r[6] ^ state.r[5] ^ state.r[6] ^ state.r[7] ^ state.r[8] ^ state.r[9] ^ state.r[10] ^ state.r[11] ^ state.r[12] ^ state.r[13] ^ state.r[14] ^ state.r[15]);
            k[c] = (output & 0x00000000000000FF);
            k[c+1] = (output & 0x000000000000FF00) >> 8;
            k[c+2] = (output & 0x0000000000FF0000) >> 16;
            k[c+3] = (output & 0x00000000FF000000) >> 24;
            k[c+4] = (output & 0x000000FF00000000) >> 32;
            k[c+5] = (output & 0x0000FF0000000000) >> 40;
            k[c+6] = (output & 0x00FF000000000000) >> 48;
            k[c+7] = (output & 0xFF00000000000000) >> 56;
            c += 8;
        }
        for (i = 0; i < bufsize; i++) {
            buffer[i] = buffer[i] ^ k[i];
        }
        fwrite(buffer, 1, bufsize, outfile);

    }
    fclose(infile);
    fclose(outfile);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(outputfile, ".tmp", mac_key, key_length);
}

void * amagus_decrypt(char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password,  int keywrap_ivlen, int bufsize) {
    FILE *infile, *outfile;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char nonce[nonce_length];
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    unsigned char *kwnonce[keywrap_ivlen];
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    datalen = datalen - key_length - mac_length - nonce_length - keywrap_ivlen;
    fseek(infile, 0, SEEK_SET);
    fread(&mac, 1, mac_length, infile);
    fread(kwnonce, 1, keywrap_ivlen, infile);
    fread(nonce, 1, nonce_length, infile);
    fread(keyprime, 1, key_length, infile);
    key_wrap_decrypt(keyprime, key_length, key, kwnonce);
    struct amagus_state state;
    state.keylen = key_length;
    long c = 0;
    int i = 0;
    int l = 8;
    uint64_t output;
    int k[bufsize];
    memset(k, 0, bufsize);
    uint64_t blocks = datalen / bufsize;
    int extra = datalen % bufsize;
    if (extra != 0) {
        blocks += 1;
    }
    fclose(infile);
    if (ganja_hmac_verify(inputfile, mac_key, key_length) == 0) {
        outfile = fopen(outputfile, "wb");
        infile = fopen(inputfile, "rb");
        fseek(infile, (mac_length + keywrap_ivlen + nonce_length + key_length), SEEK_SET);
        amagus_keysetup(&state, keyprime, nonce);
        for (uint64_t b = 0; b < blocks; b++) {
            fread(&buffer, 1, bufsize, infile);
            c = 0;
            if ((b == (blocks -1)) && (extra != 0)) {
                bufsize = extra;
            }
            for (i = 0; i < (bufsize / 8); i++) {
                amagus_F(&state);
                output = (state.r[0] ^ state.r[1] ^ state.r[2] ^ state.r[3] ^ state.r[4] ^ state.r[5] ^ state.r[6] ^ state.r[5] ^ state.r[6] ^ state.r[7] ^ state.r[8] ^ state.r[9] ^ state.r[10] ^ state.r[11] ^ state.r[12] ^ state.r[13] ^ state.r[14] ^ state.r[15]);
                k[c] = (output & 0x00000000000000FF);
                k[c+1] = (output & 0x000000000000FF00) >> 8;
                k[c+2] = (output & 0x0000000000FF0000) >> 16;
                k[c+3] = (output & 0x00000000FF000000) >> 24;
                k[c+4] = (output & 0x000000FF00000000) >> 32;
                k[c+5] = (output & 0x0000FF0000000000) >> 40;
                k[c+6] = (output & 0x00FF000000000000) >> 48;
                k[c+7] = (output & 0xFF00000000000000) >> 56;
                c += 8;
            }
            for (i = 0; i < bufsize; i++) {
                buffer[i] = buffer[i] ^ k[i];
            }
            fwrite(buffer, 1, bufsize, outfile);

        }
        fclose(infile);
        fclose(outfile);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}
