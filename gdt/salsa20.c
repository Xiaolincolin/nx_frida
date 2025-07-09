#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Salsa20 constants
static const uint8_t sigma[16] = "expand 32-byte k";

// Rotate left
#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

// Quarter round macro
#define QR(a, b, c, d) \
    b ^= ROTL(a + d, 7); \
    c ^= ROTL(b + a, 9); \
    d ^= ROTL(c + b, 13); \
    a ^= ROTL(d + c, 18);

// Salsa20 block function
void salsa20_block(uint8_t output[64], const uint8_t key[32], const uint8_t nonce[8], uint64_t counter) {
    uint32_t state[16], working[16];

    // Set up state
    memcpy(&state[0], sigma + 0, 4);   // "expa"
    memcpy(&state[1], key + 0, 4);
    memcpy(&state[2], key + 4, 4);
    memcpy(&state[3], key + 8, 4);
    memcpy(&state[4], key + 12, 4);
    memcpy(&state[5], sigma + 4, 4);   // "nd 3"
    memcpy(&state[6], nonce + 0, 4);
    memcpy(&state[7], nonce + 4, 4);
    state[8] = counter & 0xFFFFFFFF;
    state[9] = (counter >> 32) & 0xFFFFFFFF;
    memcpy(&state[10], sigma + 8, 4);   // "2-by"
    memcpy(&state[11], key + 16, 4);
    memcpy(&state[12], key + 20, 4);
    memcpy(&state[13], key + 24, 4);
    memcpy(&state[14], key + 28, 4);
    memcpy(&state[15], sigma + 12, 4);   // "te k"

    memcpy(working, state, sizeof(state));

    // 20 rounds = 10 double rounds
    for (int i = 0; i < 10; ++i) {
        // Column rounds
        QR(working[0], working[4], working[8], working[12]);
        QR(working[5], working[9], working[13], working[1]);
        QR(working[10], working[14], working[2], working[6]);
        QR(working[15], working[3], working[7], working[11]);
        // Row rounds
        QR(working[0], working[1], working[2], working[3]);
        QR(working[5], working[6], working[7], working[4]);
        QR(working[10], working[11], working[8], working[9]);
        QR(working[15], working[12], working[13], working[14]);
    }

    for (int i = 0; i < 16; ++i)
        working[i] += state[i];

    for (int i = 0; i < 16; ++i) {
        output[i * 4 + 0] = working[i] & 0xff;
        output[i * 4 + 1] = (working[i] >> 8) & 0xff;
        output[i * 4 + 2] = (working[i] >> 16) & 0xff;
        output[i * 4 + 3] = (working[i] >> 24) & 0xff;
    }
}

// Encrypt function
void salsa20_encrypt(uint8_t *output, const uint8_t *input, size_t len,
                     const uint8_t key[32], const uint8_t nonce[8]) {
    uint8_t keystream[64] = {
            0x5d, 0x64, 0xe2, 0x88, 0x0c, 0xb5, 0xe2, 0x4f, 0x73, 0x43,
            0xcb, 0x07, 0xeb, 0xa9, 0xa8, 0x7b, 0x5f, 0xbb, 0xf6, 0x2b,
            0xdc, 0xd6, 0x12, 0x54, 0xc1, 0x85, 0xce, 0x4e, 0xc6, 0xb6,
            0xca, 0x96, 0xc8, 0x9e, 0xb0, 0x8f, 0x82, 0x41, 0x72, 0x5e,
            0xd2, 0xa2, 0xd2, 0x2b, 0xae, 0x59, 0x9b, 0x85, 0xfc, 0xa1,
            0x3f, 0x03, 0x02, 0x23, 0xb3, 0x83, 0xd0, 0x0f, 0x6b, 0x35,
            0xb5, 0xa7, 0xe6, 0x70
    };
    uint64_t counter = 0;

    for (size_t i = 0; i < len; i += 64) {
//        salsa20_block(keystream, key, nonce, counter++);

        for (int i1 = 0; i1 < 64; ++i1) {
            printf("%02x ", keystream[i1]);
            if ((i1 + 1) % 16 == 0) printf("\n");
        }

        size_t block_size = (len - i < 64) ? (len - i) : 64;
        for (size_t j = 0; j < block_size; ++j)
            output[j] = input[j] ^ keystream[j];
    }
}

// Example usage
typedef uint8_t u8;

int main() {
    u8 key[32] = {
            0x2c, 0xe7, 0x29, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
    };
    u8 nonce[8] = {0};
    u8 plaintext[16] = {
            0xc0, 0x74, 0x03, 0xd1, 0x55, 0x56, 0x93, 0x32, 0xbe, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    u8 ciphertext[64] = {};

    // Example key/nonce can be set here
    nonce[0] = 0x65;
    nonce[1] = 0xa4;
    nonce[2] = 0xe5;
    nonce[3] = 0x7f;
    nonce[4] = 0xef;
    nonce[5] = 0x44;
    nonce[6] = 0xa2;
    nonce[7] = 0xa3;

    salsa20_encrypt(ciphertext, plaintext, sizeof(plaintext), key, nonce);

    printf("[*] Keystream Block (C):\n");
    for (int i = 0; i < 64; ++i) {
        printf("%02x ", ciphertext[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    return 0;
}