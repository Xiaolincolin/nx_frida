# -*- encoding: utf-8 -*-
# @ModuleName: salsa20
# @Function:
# @Author:
# @Time: 2025/7/9 14:08
from Crypto.Cipher import ChaCha20

# Python 示例（使用 PyCryptodome 库）
key = bytes.fromhex("9b90152f" + "00" * 28)
nonce = bytes.fromhex("a3a244ef7fe5a465")
plaintext = bytes.fromhex("fa 7c ac 43 f3 54 54 25 7a b1 94 59 ea 71 f9 24".replace(' ', ''))
cipher = ChaCha20.new(key=key, nonce=nonce)
print(cipher.encrypt(plaintext).hex())
