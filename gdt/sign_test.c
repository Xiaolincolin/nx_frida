#include <stdio.h>
#include <stdint.h>
#include <string.h>

// 设置第 n 字节（小端）
#define SET_BYTE(val, n, byte) (((uint8_t*)&(val))[n] = (byte))

int main() {
    uint8_t v27 = 0x2f;
    uint8_t v28 = 0x67;

    uint8_t v42[16] = {
            0X28, 0x00, 0x47, 0x2B, 0x00, 0x2C, 0x4C, 0x4B,
            0X28, 0x00, 0x47, 0x2B, 0x00, 0x2C, 0x4C, 0x4B
    };
    v42[1] = v27;
    v42[4] = v28;
    v42[9] = v27;
    v42[12] = v28;
    // 输出 v42
    printf("v42:\n");
    for (int i = 0; i < 16; ++i)
        printf("%02x ", v42[i]);
    printf("\n");

    // [+] sub_10028 returned v41:  第二次
    uint8_t v42_2[16] = {
            0x02, 0x23, 0xcf, 0xfc, 0xa2, 0x2e, 0x86, 0x13,
            0x90, 0xf9, 0xec, 0xe2, 0x3e, 0x67, 0x0b, 0x9d
    };
    // 输出 v42
    printf("v42_2:\n");
    for (int i = 0; i < 16; ++i)
        printf("%02x ", v42_2[i]);
    printf("\n");

    uint8_t v35[16] = {0};
    for (int i = 0; i < 16; ++i) {
        *(v35 + i) = v42_2[i] ^ v42[i];
    }
    // 输出 v35
    printf("v35:\n");
    for (int i = 0; i < 16; ++i)
        printf("%02x ", v35[i]);
    printf("\n");


    uint8_t v38[16] = {0};
    // [+] sub_10028 returned v41: 第一次
    uint8_t v36[16] = {
            0x46, 0xcb, 0xf8, 0x1d,
            0x00, 0x00, 0x00, 0x00,
            0xa2, 0xdf, 0xfa, 0xcd,
            0x78, 0x56, 0x34, 0x12
    };;


    v36[4] = 0xf8; //时间戳的第1个字节
    printf("v36:\n");
    for (int i = 0; i < 16; ++i)
        printf("%02x ", v36[i]);
    printf("\n");

    for (int j = 0; j < 16; j++) {
        v38[j] = v35[j] ^ v36[j];
    }
    printf("v38:\n");
    for (int i = 0; i < 16; ++i)
        printf("%02x ", v38[i]);
    printf("\n");

    return 0;
}
