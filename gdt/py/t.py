# -*- encoding: utf-8 -*-
# @ModuleName: t
# @Function:
# @Author:
# @Time: 2025/7/23 17:43
import base64

from Cryptodome.Cipher import PKCS1_v1_5

from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.Padding import pad, unpad


def aes_decrypt(ciphertext: bytes, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


if __name__ == '__main__':
    a = "MRkxDKY3gaRzIXXWAiEP0+RUHWw4yf1Lq8XduoycIur7dw9oMzSarfQraeFEUq6EPjdkaBTRxeVEDsLWpFTdsevNwe3HeejIeITmnUqn6zAHvXKX7PJVeQ5ZVzNBzIINA9laoYengRtzzWnCwLFSqQ=="
    second_aes_key = bytes.fromhex('dcac00dc20065efb6854491b049126e0')
    second_aes_iv = bytes.fromhex('aeb1fb2a20f9d9df2f4b81b997c948b1')
    a = base64.b64decode(a)
    r = aes_decrypt(a, second_aes_key, second_aes_iv)
    print(r.decode().strip().split('\x12'))
