# -*- encoding: utf-8 -*-
# @ModuleName: m9_encrypt
# @Function:
# @Author:
# @Time: 2025/6/25 16:00
import base64
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


class M9Encrypt:
    def __init__(self):
        pass

    @staticmethod
    def aes_encrypt_ecb(plaintext, key):
        plaintext = plaintext.encode() if not isinstance(plaintext, bytes) else plaintext
        key = key.encode() if not isinstance(key, bytes) else key
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(plaintext, AES.block_size))
        return encrypted

    def main(self):
        data_str = json.dumps({"imei": "", "androidid": "b1349b36b6571cb0"}, separators=(',', ':'))
        key = base64.b64decode("Kxge1FYXZWov7gg01ELhcQ==")
        r = self.aes_encrypt_ecb(data_str.encode(), key)
        final_bArr = base64.urlsafe_b64encode(r).decode().replace("=", "")
        print(final_bArr)


if __name__ == '__main__':
    M9Encrypt().main()
