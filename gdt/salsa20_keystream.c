//
// Created by xuxiaolin on 2025/7/10.
//
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// 自定义常量 (从.rodata提取)
#define CONSTANT_0 0x61707865  // "expa" little-endian
#define CONSTANT_1 0x3320646e  // "nd 3" little-endian
#define CONSTANT_2 0x79622d32  // "2-by" little-endian
#define CONSTANT_3 0x6b206574  // "te k" little-endian

// 循环左移
static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// ChaCha20四分之一轮操作
#define QUARTERROUND(a, b, c, d) \
    a += b; d ^= a; d = rotl32(d, 16); \
    c += d; b ^= c; b = rotl32(b, 12); \
    a += b; d ^= a; d = rotl32(d, 8); \
    c += d; b ^= c; b = rotl32(b, 7);

void chacha20_block(uint32_t out[16], const uint8_t key[32], const uint8_t nonce[8], uint64_t counter) {
    uint32_t state[16];

    // 使用反汇编中找到的常量初始化
    state[0] = CONSTANT_0;
    state[1] = CONSTANT_1;
    state[2] = CONSTANT_2;
    state[3] = CONSTANT_3;

    // 加载256-bit密钥 (直接字节拷贝)
    memcpy(&state[4], key, 32);

    // 加载64-bit计数器和64-bit nonce
    state[12] = (uint32_t)counter;
    state[13] = (uint32_t)(counter >> 32);
    memcpy(&state[14], nonce, 8);

    uint32_t initial_state[16];
    memcpy(initial_state, state, sizeof(state));

    // 20轮ChaCha (10次双四分之一轮)
    for (int i = 0; i < 10; i++) {
        // 列轮
        QUARTERROUND(state[0], state[4], state[8], state[12]);
        QUARTERROUND(state[1], state[5], state[9], state[13]);
        QUARTERROUND(state[2], state[6], state[10], state[14]);
        QUARTERROUND(state[3], state[7], state[11], state[15]);

        // 对角轮
        QUARTERROUND(state[0], state[5], state[10], state[15]);
        QUARTERROUND(state[1], state[6], state[11], state[12]);
        QUARTERROUND(state[2], state[7], state[8], state[13]);
        QUARTERROUND(state[3], state[4], state[9], state[14]);
    }

    // 最终相加
    for (int i = 0; i < 16; i++) {
        out[i] = state[i] + initial_state[i];
    }
}

void print_block(const uint32_t block[16]) {
    const uint8_t *bytes = (const uint8_t *)block;
    for (int i = 0; i < 64; i++) {
        printf("%02x", bytes[i]);
        if ((i + 1) % 4 == 0) printf(" ");
        if ((i + 1) % 16 == 0) printf("\n");
    }
}

int main() {
    // 根据您最初提供的keyBytes
    uint8_t key[32] = {
            0xbe, 0x3b, 0x81, 0xf3, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    // Nonce和counter (小端序)
    uint8_t nonce[8] = {0xa3, 0xa2, 0x44, 0xef, 0x7f, 0xe5, 0xa4, 0x65}; // 0x65a4e57fef44a2a3
    uint64_t counter = 0;

    uint32_t out[16];
    chacha20_block(out, key, nonce, counter);

    printf("生成的ChaCha20密钥流块:\n");
    print_block(out);

    // 您期望的输出
    const uint8_t expected[64] = {
            0x9d, 0x46, 0x46, 0x56, 0x20, 0x23, 0x13, 0xbe, 0x82, 0xf1, 0x9a, 0xc6, 0x51, 0xf3, 0xb6, 0x6d,
            0x58, 0xae, 0xe2, 0x7e, 0x64, 0xb7, 0xd3, 0x98, 0x71, 0xac, 0x63, 0xf7, 0x41, 0x9e, 0xf7, 0x6a,
            0x78, 0xb6, 0x9e, 0xc6, 0x5f, 0x84, 0x46, 0xf3, 0xcc, 0x20, 0xff, 0x73, 0x77, 0x3a, 0x29, 0x08,
            0x5b, 0xa7, 0xdf, 0xe1, 0xd0, 0xd1, 0x4d, 0x88, 0x74, 0x0b, 0xf1, 0x0d, 0xb1, 0x1f, 0x2c, 0xc1
    };

    printf("\n期望的输出:\n");
    for (int i = 0; i < 64; i++) {
        printf("%02x", expected[i]);
        if ((i + 1) % 4 == 0) printf(" ");
        if ((i + 1) % 16 == 0) printf("\n");
    }

    // 验证
    int match = memcmp(out, expected, 64) == 0;
    printf("\n验证结果: %s\n", match ? "匹配成功" : "匹配失败");

    return 0;
}