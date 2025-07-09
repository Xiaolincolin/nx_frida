# -*- encoding: utf-8 -*-
# @ModuleName: d5
# @Function:
# @Author:
# @Time: 2025/7/7 17:34
from Crypto.Cipher import Salsa20

key = bytes.fromhex('cd14e8ed00000000000000000000000000000000000000000000000000000000'.replace(' ', ''))
print(key.hex())

# 8 字节 nonce（PyCryptodome 要求是 8 字节）
nonce = bytes.fromhex('65a4e57fef44a2a3'.replace(' ', ''))
print(nonce.hex())

# 明文数据
plaintext = bytes.fromhex('b618f03f4684f404e400000000000000'.replace(' ', ''))
print(plaintext.hex())
# 32 字节密钥


# 加密
cipher = Salsa20.new(key=key, nonce=nonce)
ciphertext = cipher.encrypt(plaintext)

# 解密
# decipher = Salsa20.new(key=key, nonce=nonce)
# decrypted = decipher.decrypt(ciphertext)

# 打印结果
# print("Plaintext:", plaintext)
print("r:", ciphertext.hex())
# print("Decrypted:", decrypted)
