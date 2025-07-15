# -*- encoding: utf-8 -*-
# @ModuleName: mu_p_encrypt
# @Function:
# @Author:
# @Time: 2025/6/24 16:48
import base64
import hashlib
import json
import zlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class MuPEncrypt:
    def __init__(self, ):
        pass

    @staticmethod
    def get_data():
        data = {
            "pw": "393",
            "ph": "829",
            "fg": "1",
            "co": "0",
            "sl": "0",
            "xi": "0",
            "ic": "1",
            "uc": "1",
            "id": "0",
            "sp": "0",
            "pk": "com.qq.e.union.demo.union",
            "si": "812EDD5567C5D1DADDACB9D0522567C1",
            "as": "23417533",
            "cpk": "com.qq.e.union.demo.union",
            "csi": "812EDD5567C5D1DADDACB9D0522567C1",
            "cas": "23417533",
            "td": "0101869FBA50978E2C4CF377A18A6C7B73CA5170146F4358935C88196C4C5CAEEB61D0BAC10BF3F095837B1F",
            "od": "-999",
            "br": "google",
            "mf": "Google",
            "hw": "flame",
            "media_ext": "{}",
            "bfn": "5",
            "bfon": "0",
            "sm": "0",
            "in": "0",
            "pcs": "0",
            "do": "0",
            "ot": "2",
            "expid": "-999",
            "expvalue": "-999"
        }
        return json.dumps(data, separators=(',', ':'))

    @staticmethod
    def gzip_android_style(data: bytes) -> bytes:
        # deflate 数据（gzip压缩算法）
        compressed = zlib.compress(data)[2:-4]  # 去掉zlib头尾
        # 构造gzip header：1f 8b 08 00 00 00 00 00 00 00
        header = b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x00'
        # 构造gzip尾部：CRC32 + 输入长度（均为小端）
        crc32 = zlib.crc32(data) & 0xFFFFFFFF
        i_size = len(data) & 0xFFFFFFFF
        trailer = crc32.to_bytes(4, 'little') + i_size.to_bytes(4, 'little')
        return header + compressed + trailer

    @staticmethod
    def aes_encrypt_ecb(plaintext, key):
        plaintext = plaintext.encode() if not isinstance(plaintext, bytes) else plaintext
        key = key.encode() if not isinstance(key, bytes) else key
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(plaintext, AES.block_size))
        return encrypted

    @staticmethod
    def decrypt_aes_key(result, key) -> bytes:
        result = result.encode() if not isinstance(result, bytes) else result
        key = key.encode() if not isinstance(key, bytes) else key
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(result)
        return unpad(decrypted, AES.block_size)

    @staticmethod
    def encrypt_sha1(sha1_str: str) -> str:
        return hashlib.sha1(sha1_str.encode()).hexdigest()

    @staticmethod
    def encrypt_aes_key(v40: str) -> bytes:
        v30 = 7
        v39 = 0
        base_offset = (v39 & 1) + v30
        a5 = ''.join(v40[(base_offset + 2 * i) % 40] for i in range(32))
        return a5.encode()

    @staticmethod
    def get_mu_p_ori_key_str(ts, imei_md5):
        right_code = 9
        ts_move_right = ts >> right_code
        return f'AdNet{ts_move_right}{imei_md5}'

    def test(self):
        ts = 1750833011
        data_str = self.get_data()

        imei_md5 = 'd41d8cd98f00b204e9800998ecf8427e'  # 空字符串的md5值
        ori_key_str = self.get_mu_p_ori_key_str(ts, imei_md5)
        key_sha1 = self.encrypt_sha1(ori_key_str)
        key_encrypted = self.encrypt_aes_key(key_sha1)

        # 数据体data_zip
        data_zip = self.gzip_android_style(data_str.encode())
        result = self.aes_encrypt_ecb(data_zip, key_encrypted)

        # 加密内容做头部填充
        b_prefix = bytearray([0x61, 0xe3, 0x02, 0x01])
        out_bArr = bytearray(len(result) + 12 + 32)
        out_bArr[:4] = b_prefix
        b_ts = bytes.fromhex(hex(ts)[2:])[::-1]
        out_bArr[4:8] = b_ts
        out_bArr[12:44] = imei_md5.encode()
        out_bArr[44:] = result
        final_bArr = base64.urlsafe_b64encode(out_bArr).decode().replace("=", "")
        print(final_bArr)


if __name__ == '__main__':
    MuPEncrypt().test()
