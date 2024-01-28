#include <stdio.h>

#pragma HLS INTERFACE s_axilite port=return bundle=CRTL_BUS
#pragma HLS INTERFACE s_axilite port=plaintext bundle=CRTL_BUS
#pragma HLS INTERFACE s_axilite port=ciphertext bundle=CRTL_BUS
#pragma HLS INTERFACE s_axilite port=key bundle=CRTL_BUS

unsigned char s_box[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};
// Inverse S-Box
unsigned char inv_s_box[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Multiplication by 9, 11, 13, and 14 for InvMixColumns
unsigned char mul_9[256], mul_11[256], mul_13[256], mul_14[256];

unsigned char galois_mul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    unsigned char hi_bit_set;
    for(int i = 0; i < 8; i++) {
        if(b & 1) {
            p ^= a;
        }
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if(hi_bit_set) {
            a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
        }
        b >>= 1;
    }
    return p;
}

unsigned char rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

unsigned char galois_mul_inverse(unsigned char b) {
    if(b <= 1) {
        return b;
    }
    unsigned char a = 0x1b; // for GF(2^8)
    unsigned char c = 1;
    do {
        if(b & 1) {
            c ^= a;
        }
        b >>= 1;
        a <<= 1;
        if(a & 0x100) {
            a ^= 0x1b;
        }
    } while(b);
    return c;
}

const int Nb = 4; // Number of columns in the state
const int Nk = 4; // Number of 32-bit words in the key
const int Nr = 10; // Number of rounds

// Function prototypes
void add_round_key(unsigned char state[4][4], unsigned char *key);
void sub_bytes(unsigned char state[4][4]);
void shift_rows(unsigned char state[4][4]);
void mix_columns(unsigned char state[4][4]);
void key_expansion(unsigned char *key, unsigned char round_keys[176]);
void inv_shift_rows(unsigned char state[4][4]);
void inv_sub_bytes(unsigned char state[4][4]);
void inv_mix_columns(unsigned char state[4][4]);


void generate_mul_arrays() {
    unsigned char x = 0;
    do {
        unsigned char y = x ? galois_mul_inverse(x) : 0;
        mul_9[x] = galois_mul(y, 9);
        mul_11[x] = galois_mul(y, 11);
        mul_13[x] = galois_mul(y, 13);
        mul_14[x] = galois_mul(y, 14);
    } while (++x);
}



void key_expansion_core(unsigned char *word, int round) {
    // Rotate the word
    unsigned char temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;

    // SubBytes on the word
    for (int i = 0; i < 4; i++) {
        word[i] = s_box[word[i]];
    }

    // XOR with round constant
    word[0] ^= rcon[round];
}

void key_expansion(unsigned char *key, unsigned char round_keys[176]) {
    // Copy the key to the round_keys
    for (int i = 0; i < Nk * 4; i++) {
        round_keys[i] = key[i];
    }

    for (int i = Nk; i < Nb * (Nr + 1); i++) {
        unsigned char temp[4];
        for (int j = 0; j < 4; j++) {
            temp[j] = round_keys[(i-1) * 4 + j];
        }

        if (i % Nk == 0) {
            key_expansion_core(temp, i / Nk);
        }

        for (int j = 0; j < 4; j++) {
            round_keys[i * 4 + j] = round_keys[(i - Nk) * 4 + j] ^ temp[j];
        }
    }
}
void add_round_key(unsigned char state[4][4], unsigned char *key) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] ^= key[i*4 + j];
        }
    }
}

void sub_bytes(unsigned char state[4][4]) {
    unsigned char s_box[16] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
    };

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = s_box[state[i][j]];
        }
    }
}

void shift_rows(unsigned char state[4][4]) {
    for (int i = 1; i < 4; i++) {
        for (int k = 0; k < i; k++) {
            unsigned char temp = state[i][0];
            for (int j = 0; j < 3; j++) {
                state[i][j] = state[i][j + 1];
            }
            state[i][3] = temp;
        }
    }
}

void mix_columns(unsigned char state[4][4]) {
    for (int i = 0; i < 4; ++i) {
        unsigned char a[4], b[4];
        for (int j = 0; j < 4; ++j) {
            a[j] = state[j][i];
            b[j] = (state[j][i] << 1) ^ ((state[j][i] & 0x80) ? 0x1b : 0x00);
        }

        state[0][i] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
        state[1][i] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
        state[2][i] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
        state[3][i] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3];
    }
}


void aes_encrypt(unsigned char *plaintext, unsigned char *ciphertext, unsigned char *key) {
    unsigned char state[4][4];
    int i, j, round;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[j][i] = plaintext[i*4 + j];
        }
    }

    add_round_key(state, key);

    for (round = 1; round < 10; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, key + round*16);
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, key + 10*16);

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            ciphertext[i*4 + j] = state[j][i];
        }
    }
}
void aes_decrypt(unsigned char *ciphertext, unsigned char *plaintext, unsigned char *key) {
    unsigned char state[4][4];
    int i, j, round;

    // Initialize state array with ciphertext, transposed
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[j][i] = ciphertext[i*4 + j];
        }
    }

    // Initial AddRoundKey step
    add_round_key(state, key + 10*16);

    // 9 main rounds
    for (round = 9; round > 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, key + round*16);
        inv_mix_columns(state);
    }

    // Final round
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, key);

    // Copy state to plaintext
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            plaintext[i*4 + j] = state[j][i];
        }
    }

    // Add null character at the end of the plaintext
    plaintext[16] = '\0';
}

void inv_shift_rows(unsigned char state[4][4]) {
    unsigned char temp;

    // Rotate first row 1 columns to right  
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    // Rotate second row 2 columns to right 
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;

    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Rotate third row 3 columns to right
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

void inv_sub_bytes(unsigned char state[4][4]) {
    for(int i=0; i<4; ++i) {
        for(int j=0; j<4; ++j) {
            state[j][i] = inv_s_box[state[j][i]];
        }
    }
}

void inv_mix_columns(unsigned char state[4][4]) {
    unsigned char temp[4][4];

    for(int i=0; i<4; ++i) {
        for(int j=0; j<4; ++j) {
            temp[j][i] = state[j][i];
        }
    }

    for(int i=0; i<4; ++i) {
        state[0][i] = mul_14[temp[0][i]] ^ mul_11[temp[1][i]] ^ mul_13[temp[2][i]] ^ mul_9[temp[3][i]];
        state[1][i] = mul_9[temp[0][i]] ^ mul_14[temp[1][i]] ^ mul_11[temp[2][i]] ^ mul_13[temp[3][i]];
        state[2][i] = mul_13[temp[0][i]] ^ mul_9[temp[1][i]] ^ mul_14[temp[2][i]] ^ mul_11[temp[3][i]];
        state[3][i] = mul_11[temp[0][i]] ^ mul_13[temp[1][i]] ^ mul_9[temp[2][i]] ^ mul_14[temp[3][i]];
    }
}



int main() {
    generate_mul_arrays();
    unsigned char plaintext[16] = "Manos";
    unsigned char ciphertext[16];
    unsigned char decryptedtext[16];
    unsigned char key[16] = "1234567890123456";

    // Encrypt the plaintext
    aes_encrypt(plaintext, ciphertext, key);

    // Print the ciphertext
    for (int i = 0; i < 16; i++) {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");

    // Decrypt the ciphertext
    aes_decrypt(ciphertext, decryptedtext, key);

    // Print the decrypted text
    printf("%s\n", decryptedtext);

    return 0;
}