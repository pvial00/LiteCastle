#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct spock_state {
    uint32_t Ka[48];
    uint32_t Kb[48];
    uint32_t d[48][4];
    int rounds;
};

uint32_t spock_rotl(uint32_t a, int b) {
    return ((a << b) | (a >> (32 - b)));
}

uint32_t spock_rotr(uint32_t a, int b) {
    return ((a >> b) | (a << (32 - b)));
}

void roundF(struct spock_state *state, uint32_t *xla, uint32_t *xlb, uint32_t *xra, uint32_t *xrb) {
    uint32_t a, b, c, d;
    int r;
    a = *xla;
    b = *xlb;
    c = *xra;
    d = *xrb;
    for (r = 0; r < state->rounds; r++) {
        a = spock_rotr(a, 8);
	a += d;
        a ^= state->Ka[r];
        b = spock_rotr(b, 7);
	b += c;
        b ^= state->Kb[r];
	c = spock_rotl(c, 2);
	c ^= b;
	d = spock_rotl(d, 3);
	d ^= a;
	a += b;
	b += a;
	a += state->d[r][0];
	b += state->d[r][1];
	c += state->d[r][2];
	d += state->d[r][3];
    }
    *xla = a;
    *xlb = b;
    *xra = c;
    *xrb = d;
}

void roundB(struct spock_state *state, uint32_t *xla, uint32_t *xlb, uint32_t *xra, uint32_t *xrb) {
    uint32_t a, b, c, d;
    int r;
    a = *xla;
    b = *xlb;
    c = *xra;
    d = *xrb;
    for (r = state->rounds; r --> 0;) {
	d -= state->d[r][3];
	c -= state->d[r][2];
	b -= state->d[r][1];
	a -= state->d[r][0];
	b -= a;
	a -= b;
	d ^= a;
	d = spock_rotr(d, 3);
	c ^= b;
	c = spock_rotr(c, 2);
        b ^= state->Kb[r];
	b -= c;
        b = spock_rotl(b, 7);
        a ^= state->Ka[r];
	a -= d;
        a = spock_rotl(a, 8);
    }
    *xla = a;
    *xlb = b;
    *xra = c;
    *xrb = d;
}

void spock_ksa(struct spock_state *state, unsigned char * keyp, int keylen) {
    uint32_t temp = 0x00000001;
    struct spock_state tempstate;
    int m = 0;
    int b, i, r, x;
    uint32_t *k[8];
    memset(k, 0, 8*sizeof(uint32_t));
    memset(state->Ka, 0, state->rounds*sizeof(uint32_t));
    memset(state->Kb, 0, state->rounds*sizeof(uint32_t));
    memset(tempstate.Ka, 0, state->rounds*sizeof(uint32_t));
    memset(tempstate.Kb, 0, state->rounds*sizeof(uint32_t));
    memset(state->d, 0, 4*(state->rounds*sizeof(uint32_t)));
    memset(tempstate.d, 0, 4*(state->rounds*sizeof(uint32_t)));
    for (i = 0; i < 8; i++) {
        k[i] = 0;
        k[i] = (keyp[m] << 24) + (keyp[m+1] << 16) + (keyp[m+2] << 8) + keyp[m+3];
        m += 4;
    }
    
    for (r = 0; r < state->rounds; r++) {
        roundF(&tempstate, &k[0], &k[1], &k[2], &k[3]);
        roundF(&tempstate, &k[4], &k[5], &k[6], &k[7]);
        for (i = 0; i < 8; i++) {
            tempstate.Ka[r] ^= (uint32_t)k[i];
        }
    }
    for (r = 0; r < state->rounds; r++) {
        roundF(&tempstate, &k[0], &k[1], &k[2], &k[3]);
        roundF(&tempstate, &k[4], &k[5], &k[6], &k[7]);
        for (i = 0; i < 8; i++) {
            tempstate.Kb[r] ^= (uint32_t)k[i];
        }
    }
    for (r = 0; r < state->rounds; r++) {
        for (i = 0; i < 4; i++) {
            roundF(&tempstate, &k[0], &k[1], &k[2], &k[3]);
            roundF(&tempstate, &k[4], &k[5], &k[6], &k[7]);
            for (x = 0; x < 8; x++) {
	        tempstate.d[r][i] ^= (uint32_t)k[x];
            }
        }
    }
    for (r = 0; r < state->rounds; r++) {
        roundF(&tempstate, &k[0], &k[1], &k[2], &k[3]);
        roundF(&tempstate, &k[4], &k[5], &k[6], &k[7]);
        for (i = 0; i < 8; i++) {
            state->Ka[r] ^= (uint32_t)k[i];
        }
        roundF(&tempstate, &k[0], &k[1], &k[2], &k[3]);
        roundF(&tempstate, &k[4], &k[5], &k[6], &k[7]);
        for (i = 0; i < 8; i++) {
            state->Kb[r] ^= (uint32_t)k[i];
        }
    }
    for (r = 0; r < state->rounds; r++) {
        for (i = 0; i < 4; i++) {
            roundF(&tempstate, &k[0], &k[1], &k[2], &k[3]);
            roundF(&tempstate, &k[4], &k[5], &k[6], &k[7]);
            for (x = 0; x < 8; x++) {
                state->d[r][i] ^= (uint32_t)k[x];
            }
        }
    }
}

void * spock_cbc_encrypt(char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password,  int keywrap_ivlen, int bufsize) {
    int blocksize = 16;
    FILE *infile, *outfile;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char iv[nonce_length];
    amagus_random(&iv, nonce_length);
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
    fwrite(iv, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);

    uint8_t k[16];
    uint32_t block[4];
    uint32_t last[4];
    uint32_t next[4];
    struct spock_state state;
    int iv_length = 16;
    state.rounds = 48;
    int c = 0;
    spock_ksa(&state, keyprime, key_length);
    int v = 16;
    uint64_t i;
    int x,  b, ii, r;
    int t = 0;
    uint64_t blocks = datalen / bufsize;
    int extra = datalen % bufsize;
    int extrabytes = blocksize - (datalen % blocksize);
    if (extra != 0) {
        blocks += 1;
    }
    if (datalen < bufsize) {
        blocks = 1;
    }
    for (int i = 0; i < 4; i++) {
        last[i] = (iv[c] << 24) + (iv[c+1] << 16) + (iv[c+2] << 8) + iv[c+3];
        c += 4;
    }
    for (i = 0; i < (blocks); i++) {
        if ((i == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        fread(&buffer, 1, bufsize, infile);
        c = 0;
        if (((i == (blocks - 1)) && (extra != 0))) {
            for (int p = 0; p < extrabytes; p++) {
                buffer[(bufsize+extrabytes-1)-p] = (unsigned char *)extrabytes;
            }
            bufsize = bufsize + extrabytes;
        }
        int bblocks = bufsize / 16;
        int bextra = bufsize % 16;
        if (bextra != 0) {
            bblocks += 1;
        }
        for (b = 0; b < bblocks; b++) {
            block[0] = (buffer[c] << 24) + (buffer[c+1] << 16) + (buffer[c+2] << 8) + buffer[c+3];
            block[1] = (buffer[c+4] << 24) + (buffer[c+5] << 16) + (buffer[c+6] << 8) + buffer[c+7];
            block[2] = (buffer[c+8] << 24) + (buffer[c+9] << 16) + (buffer[c+10] << 8) + buffer[c+11];
            block[3] = (buffer[c+12] << 24) + (buffer[c+13] << 16) + (buffer[c+14] << 8) + buffer[c+15];
            for (r = 0; r < 4; r++) {
                block[r] = block[r] ^ last[r];
            }
            roundF(&state, &block[0], &block[1], &block[2], &block[3]);
            for (int r = 0; r < 4; r++) {
                last[r] = block[r];
            }
            buffer[c+3] = (block[0] & 0x000000FF);
            buffer[c+2] = (block[0] & 0x0000FF00) >> 8;
            buffer[c+1] = (block[0] & 0x00FF0000) >> 16;
            buffer[c] = (block[0] & 0xFF000000) >> 24;
            buffer[c+7] = (block[1] & 0x000000FF);
            buffer[c+6] = (block[1] & 0x0000FF00) >> 8;
            buffer[c+5] = (block[1] & 0x00FF0000) >> 16;
            buffer[c+4] = (block[1] & 0xFF000000) >> 24;
            buffer[c+11] = (block[2] & 0x000000FF);
            buffer[c+10] = (block[2] & 0x0000FF00) >> 8;
            buffer[c+9] = (block[2] & 0x00FF0000) >> 16;
            buffer[c+8] = (block[2] & 0xFF000000) >> 24;
            buffer[c+15] = (block[3] & 0x000000FF);
            buffer[c+14] = (block[3] & 0x0000FF00) >> 8;
            buffer[c+13] = (block[3] & 0x00FF0000) >> 16;
            buffer[c+12] = (block[3] & 0xFF000000) >> 24;
            c += 16;
        }
        fwrite(buffer, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(outputfile, ".tmp", mac_key, key_length);
}

void * spock_cbc_decrypt(char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password,  int keywrap_ivlen, int bufsize) {
    int blocksize = 16;
    FILE *infile, *outfile;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char iv[nonce_length];
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
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
    fread(iv, 1, nonce_length, infile);
    fread(keyprime, 1, key_length, infile);
    key_wrap_decrypt(keyprime, key_length, key, kwnonce);

    uint8_t k[16];
    uint32_t block[4];
    uint32_t last[4];
    uint32_t next[4];
    struct spock_state state;
    int iv_length = 16;
    state.rounds = 48;
    int c = 0;
    spock_ksa(&state, keyprime, key_length);
    int v = 16;
    uint64_t i;
    int x, b, ii, r;
    int t = 0;
    uint64_t blocks = datalen / bufsize;
    int extra = datalen % bufsize;
    if (extra != 0) {
        blocks += 1;
    }
    if (datalen < bufsize) {
        blocks = 1;
    }
    fclose(infile);
    if (ganja_hmac_verify(inputfile, mac_key, key_length) == 0) {
        outfile = fopen(outputfile, "wb");
        infile = fopen(inputfile, "rb");
        fseek(infile, (mac_length + keywrap_ivlen + nonce_length + key_length), SEEK_SET);
        c = 0;
        for (int i = 0; i < 4; i++) {
            last[i] = (iv[c] << 24) + (iv[c+1] << 16) + (iv[c+2] << 8) + iv[c+3];
            c += 4;
        }
        for (i = 0; i < (blocks); i++) {
            if (i == (blocks - 1) && (extra != 0)) {
                bufsize = extra;
            }
            fread(&buffer, 1, bufsize, infile);
            c = 0;
            int bblocks = bufsize / 16;
            int bextra = bufsize % 16;
            if (bextra != 0) {
                bblocks += 1;
            }
            for (b = 0; b < bblocks; b++) {
                block[0] = (buffer[c] << 24) + (buffer[c+1] << 16) + (buffer[c+2] << 8) + buffer[c+3];
                block[1] = (buffer[c+4] << 24) + (buffer[c+5] << 16) + (buffer[c+6] << 8) + buffer[c+7];
                block[2] = (buffer[c+8] << 24) + (buffer[c+9] << 16) + (buffer[c+10] << 8) + buffer[c+11];
                block[3] = (buffer[c+12] << 24) + (buffer[c+13] << 16) + (buffer[c+14] << 8) + buffer[c+15];
                for (r = 0; r < 4; r++) {
                    next[r] = block[r];
                }
                roundB(&state, &block[0], &block[1], &block[2], &block[3]);
                for (r = 0; r < 4; r++) {
                    block[r] = block[r] ^ last[r];
                    last[r] = next[r];
                }
                buffer[c+3] = (block[0] & 0x000000FF);
                buffer[c+2] = (block[0] & 0x0000FF00) >> 8;
                buffer[c+1] = (block[0] & 0x00FF0000) >> 16;
                buffer[c] = (block[0] & 0xFF000000) >> 24;
                buffer[c+7] = (block[1] & 0x000000FF);
                buffer[c+6] = (block[1] & 0x0000FF00) >> 8;
                buffer[c+5] = (block[1] & 0x00FF0000) >> 16;
                buffer[c+4] = (block[1] & 0xFF000000) >> 24;
                buffer[c+11] = (block[2] & 0x000000FF);
                buffer[c+10] = (block[2] & 0x0000FF00) >> 8;
                buffer[c+9] = (block[2] & 0x00FF0000) >> 16;
                buffer[c+8] = (block[2] & 0xFF000000) >> 24;
                buffer[c+15] = (block[3] & 0x000000FF);
                buffer[c+14] = (block[3] & 0x0000FF00) >> 8;
                buffer[c+13] = (block[3] & 0x00FF0000) >> 16;
                buffer[c+12] = (block[3] & 0xFF000000) >> 24;
                c += 16;
            }

            if (i == (blocks-1)) {
               int count = 0;
               int padcheck = buffer[(bufsize - 1)];
               int g = bufsize - 1;
               for (int m = 0; m < padcheck; m++) {
                   if ((int)buffer[g] == padcheck) {
                       count += 1;
                   }
                   g = (g - 1);
               }
               if (padcheck == count) {
                   bufsize = bufsize - count;
               }
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
