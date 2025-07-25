# -*- encoding: utf-8 -*-
# @ModuleName: modify_sha256
# @Function:
# @Author:
# @Time: 2025/7/23 13:56

# 初始哈希值（前8个质数的平方根小数部分前32位）
INITIAL_HASH = [
    0x6a09a669, 0xba67ae87, 0x7b6bf372, 0xa56cf53a,
    0x511e527f, 0x5b25688c, 0x1f73c9ab, 0x3bd0bd19
]

# 轮常量（前64个质数的立方根小数部分前32位）
ROUND_CONSTANTS = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


def right_rotate(x, n):
    """循环右移n位（32位整数）"""
    return (x >> n) | (x << (32 - n)) & 0xFFFFFFFF


def preprocess_message(message: str):
    """消息填充：补位+长度追加"""
    if isinstance(message, str):
        message = bytearray(message, 'utf-8')
    elif isinstance(message, bytes):
        message = bytearray(message)
    else:
        raise TypeError("Input must be string or bytes")

    # 原始长度（位）
    original_bit_len = len(message) * 8

    # 补1 + 补0直到长度 ≡ 448 mod 512
    message.append(0x80)
    while (len(message) * 8 + 64) % 512 != 0:
        message.append(0x00)

    # 追加原始长度（64位大端序）
    message.extend(original_bit_len.to_bytes(8, 'big'))
    return message


def modify_sha256(message: str):
    """计算SHA-256哈希值"""
    # 初始化哈希值
    hash_values = list(INITIAL_HASH)

    # 消息预处理
    processed_msg = preprocess_message(message)

    # 分块处理（每块64字节）
    for i in range(0, len(processed_msg), 64):
        block = processed_msg[i:i + 64]

        # 1. 准备消息调度表（W[0..63]）
        w = [0] * 64
        for t in range(16):
            w[t] = int.from_bytes(block[t * 4:t * 4 + 4], 'big')
        for t in range(16, 64):
            s0 = right_rotate(w[t - 15], 7) ^ right_rotate(w[t - 15], 18) ^ (w[t - 15] >> 3)
            s1 = right_rotate(w[t - 2], 17) ^ right_rotate(w[t - 2], 19) ^ (w[t - 2] >> 10)
            w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & 0xFFFFFFFF

        # 2. 初始化工作变量
        a, b, c, d, e, f, g, h = hash_values

        # 3. 64轮压缩
        for t in range(64):
            Σ1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            Ch = (e & f) ^ ((~e) & g)
            temp1 = (h + Σ1 + Ch + ROUND_CONSTANTS[t] + w[t]) & 0xFFFFFFFF
            Σ0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            Maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (Σ0 + Maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        # 4. 更新哈希值
        hash_values[0] = (hash_values[0] + a) & 0xFFFFFFFF
        hash_values[1] = (hash_values[1] + b) & 0xFFFFFFFF
        hash_values[2] = (hash_values[2] + c) & 0xFFFFFFFF
        hash_values[3] = (hash_values[3] + d) & 0xFFFFFFFF
        hash_values[4] = (hash_values[4] + e) & 0xFFFFFFFF
        hash_values[5] = (hash_values[5] + f) & 0xFFFFFFFF
        hash_values[6] = (hash_values[6] + g) & 0xFFFFFFFF
        hash_values[7] = (hash_values[7] + h) & 0xFFFFFFFF

    # 最终哈希拼接
    return ''.join(f'{x:08x}' for x in hash_values)


if __name__ == "__main__":
    test_msg = '122-60130.5335+80k:050-67182830300;300000000;4816933bd;51168;61768;7254;820;919ae-5c47-fd4b50b2;1:7;1:;1:050-67182830300;1:050-65943206500;1:94k61;1:050-30426612700;1:050-30426612700;1:559k04k122-72143.1898+80k222-72143.1898+80k3838;2:;2:050-15682578500;2:900-66337339500;2:28;2:5k9;3:k1;3:k322-60132.8023+80k422-71154.6729+80k537;3:9k722-60132.8023+80k822-60132.8023+80k937;4:;4:k2;4:k4;4:050-67138835300;4:64k722-60130.7334+80k822-60130.6337+80k922-60132.6024+80k020;5:k2;5:k422-60130.7334+80k59;5:53k720;5:050-67138169700;5:050-67138169700;6:90k158;6:050-67141836000;6:67k422-60132.1687+80k529;6:7;6:050-67167162400;6:8;6:k013k122-60130.7334+80k214k322-60130.8668+80k422-60130.2671+80k5;1:Adod1,ee 2ie 0N0YX5BH212146011.1pzotrcm869'
    print(modify_sha256(test_msg))
