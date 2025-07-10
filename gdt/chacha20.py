# -*- encoding: utf-8 -*-
# @ModuleName: salsa20
# @Function:
# @Author:
# @Time: 2025/7/9 14:08
from Crypto.Cipher import ChaCha20

# Python 示例（使用 PyCryptodome 库）
key = bytes.fromhex("cde75426" + "00" * 28)
nonce = bytes.fromhex("a3a244ef7fe5a465")
plaintext = bytes.fromhex("07 f0 51 05 47 b2 db cb d9 d3 51 cb 3c 39 f0 f5".replace(' ', ''))
cipher = ChaCha20.new(key=key, nonce=nonce)
print(cipher.encrypt(plaintext).hex())
