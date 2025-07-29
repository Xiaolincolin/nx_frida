# -*- encoding: utf-8 -*-
# @ModuleName: m11_encrypt
# @Function:
# @Author:
# @Time: 2025/7/28 16:17
import struct

import hexdump

XX_TEA_KEY = [
    0xD2785EF1,
    0xC4C23330,
    0x25A9C8BA,
    0x3A867E67
]
import zlib


def compress_data(data):
    """压缩数据"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return zlib.compress(data)


def decompress_data(compressed_data):
    """解压缩数据"""
    return zlib.decompress(compressed_data)


def xx_tea_decrypt(data: bytes) -> bytes:
    key = XX_TEA_KEY
    if len(data) % 4 != 0 or len(data) < 8:
        raise ValueError("Invalid encrypted data length")

    v = list(struct.unpack('<%dI' % (len(data) // 4), data))
    n = len(v)
    delta = 0x9E3779B9  # 注意：这是正确的XXTEA delta值，0x61C88647是其补数
    rounds = 6 + 52 // n
    sum_ = (rounds * delta) & 0xFFFFFFFF

    for _ in range(rounds):
        e = (sum_ >> 2) & 3
        for p in reversed(range(n)):  # 从后向前处理
            if p == 0:
                z = v[-1]  # 处理第一个元素时，z是最后一个元素
            else:
                z = v[p - 1]

            y = v[(p + 1) % n]  # 处理边界情况
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum_ ^ y) + (key[(p & 3) ^ e] ^ z))
            v[p] = (v[p] - mx) & 0xFFFFFFFF
        sum_ = (sum_ - delta) & 0xFFFFFFFF  # 解密时delta应该是递减

    # 取原始长度
    orig_len = v[-1]
    decrypted = struct.pack('<%dI' % (n - 1), *v[:-1])
    return decrypted[:orig_len]


def xx_tea_encrypt(input_bytes: bytes) -> bytes:
    # 填充：4字节对齐 + 附加原始长度
    key = XX_TEA_KEY
    n = len(input_bytes)
    pad = (4 - (n % 4)) % 4
    padded = input_bytes + b'\x00' * pad
    padded += struct.pack('<I', n)  # 原始长度追加到末尾
    v = list(struct.unpack('<%dI' % (len(padded) // 4), padded))

    # 加密过程
    delta = 0x61C88647  # -0x3C6EF372
    rounds = 6 + 52 // len(v)
    sum_ = 0
    n = len(v)
    z = v[-1]

    for _ in range(rounds):
        sum_ = (sum_ - delta) & 0xFFFFFFFF
        e = (sum_ >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum_ ^ y) + (key[(p & 3) ^ e] ^ z))
            v[p] = (v[p] + mx) & 0xFFFFFFFF
            z = v[p]
        y = v[0]
        mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum_ ^ y) + (key[((n - 1) & 3) ^ e] ^ z))
        v[-1] = (v[-1] + mx) & 0xFFFFFFFF
        z = v[-1]

    # 输出加密数据
    return struct.pack('<%dI' % n, *v)


def encrypt_main():
    ori_data = "0000013810032c3c4003560b6765745446436f6e666967660b6765745446436f6e6669677d0001010a08000106037265711d000100fd0a0300000198500da28b18000a0608706c6174666f726d160132060776657273696f6e1602393006026c6316104244344645323343333532323532444306076368616e6e656c160631303534393806056170706964160a313130313135323537300603706b671619636f6d2e71712e652e756e696f6e2e64656d6f2e756e696f6e060a706b67566572496e666f1613342e3634302e313531302e3231392c3135313006086170694c6576656c1602333206056272616e641606676f6f676c6506056d6f64656c1607506978656c20342a0c10012c380c480c5c0b362038343433633735346139383134616134613765336534653166356336646631330b8c980ca80c"
    data_bytes = bytes.fromhex(ori_data)
    zlib_bytes = compress_data(data_bytes)
    enc = xx_tea_encrypt(zlib_bytes)
    hexdump.hexdump(enc)


def decrypt_main():
    ori_data = "8d3a44535874ba23aa45fae0be6248f92321ba2d2c2af224a04d1c45499edcae5ee01431e3b9684d54c49f04155134ac7a10a314cfb5c6f3477591a22dbbfc3fb6b2e5d40ff02f7b1671b6813e18e1c55d0e619c8cab9d0aa84fe0a3bbfeedba3c1a62025ac63f5ca1fdbfc2a4f05a11648ae3a689b428db47f8f3767d6cc9b6165b2aa9186120094f20ef5dfe61ec7e46a550273b4245d54b59ca4df60609a2170ece84d8622646b2b9982d6046cdeae5b2009583ec17dde9ba780e17db02d497b5dd1d7f29df531a14081ae3e6d5e102adb00d19f36ca5c41bad07bbeb79b1375a1e321aff1e44c0eeb3a86e4f754d8d2c963b4f61f632360ae736cd2fe16793cf4e37f0b47c3d481208475312d1870436483e16cdd43acb12e0515908b5c2"
    data_bytes = bytes.fromhex(ori_data)
    enc_bytes = xx_tea_decrypt(data_bytes)
    un_zlib_bytes = decompress_data(enc_bytes)
    hexdump.hexdump(un_zlib_bytes)


if __name__ == '__main__':
    decrypt_main()
