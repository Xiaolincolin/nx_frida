#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CONSTANT_0 0x61707865
#define CONSTANT_1 0x3320646e
#define CONSTANT_2 0x79622d32
#define CONSTANT_3 0x6b206574

static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

#define QUARTERROUND(a, b, c, d) \
    a += b; d ^= a; d = rotl32(d, 16); \
    c += d; b ^= c; b = rotl32(b, 12); \
    a += b; d ^= a; d = rotl32(d, 8); \
    c += d; b ^= c; b = rotl32(b, 7);

void print_block(const uint32_t block[16]) {
    const uint8_t *bytes = (const uint8_t *) block;
    for (int i = 0; i < 64; i++) {
        printf("%02x", bytes[i]);
        if ((i + 1) % 4 == 0) printf(" ");
        if ((i + 1) % 16 == 0) printf("\n");
    }
}

void chacha20_block(uint32_t out[16], const uint8_t key[32], const uint8_t nonce[8], uint64_t counter) {
    uint32_t state[16];

    state[0] = CONSTANT_0;
    state[1] = CONSTANT_1;
    state[2] = CONSTANT_2;
    state[3] = CONSTANT_3;

    memcpy(&state[4], key, 32);

    state[12] = (uint32_t) counter;
    state[13] = (uint32_t) (counter >> 32);
    memcpy(&state[14], nonce, 8);

    uint32_t initial_state[16];
    memcpy(initial_state, state, sizeof(state));

    for (int i = 0; i < 10; i++) {
        QUARTERROUND(state[0], state[4], state[8], state[12]);
        QUARTERROUND(state[1], state[5], state[9], state[13]);
        QUARTERROUND(state[2], state[6], state[10], state[14]);
        QUARTERROUND(state[3], state[7], state[11], state[15]);

        QUARTERROUND(state[0], state[5], state[10], state[15]);
        QUARTERROUND(state[1], state[6], state[11], state[12]);
        QUARTERROUND(state[2], state[7], state[8], state[13]);
        QUARTERROUND(state[3], state[4], state[9], state[14]);
    }

    for (int i = 0; i < 16; i++) {
        out[i] = state[i] + initial_state[i];
    }
}

void chacha20_encrypt(uint8_t *ciphertext, const uint8_t *plaintext, size_t len,
                      const uint8_t key[32], const uint8_t nonce[8], uint64_t counter) {
    uint32_t keystream[16];
    uint8_t *keystream_bytes = (uint8_t *) keystream;

    for (size_t i = 0; i < len; i += 64) {
        chacha20_block(keystream, key, nonce, counter + i / 64);
        print_block(keystream);
        size_t block_len = (len - i) < 64 ? (len - i) : 64;
        for (size_t j = 0; j < block_len; j++) {
            ciphertext[ j] = keystream_bytes[j] ^ plaintext[j];
        }
    }
}


void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main() {
    // 密钥和nonce（与之前匹配的配置相同）
    uint8_t key[32] = {
            0xc2, 0x35, 0xd1, 0xf3, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    uint8_t nonce[8] = {0xa3, 0xa2, 0x44, 0xef, 0x7f, 0xe5, 0xa4, 0x65};
    uint64_t counter = 0;

    // 明文
    uint8_t plaintext[16] = {
            0x46, 0x03, 0x01, 0x91, 0x53, 0xfb, 0x26, 0xf5, 0x17, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    // 加密
    uint8_t ciphertext[16];
    chacha20_encrypt(ciphertext, plaintext, 16, key, nonce, counter);

    // 打印结果
    print_hex("明文      ", plaintext, 16);
    print_hex("密文      ", ciphertext, 16);

    return 0;
}