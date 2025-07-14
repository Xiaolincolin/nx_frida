import hashlib
import time
from Crypto.Cipher import ChaCha20


def get_now_ts() -> hex:
    ts = int(time.time() * 1000)
    r = hex(ts & 0xFFFFFFFF).replace('0x', '')
    return r


class M12Sign:
    def __init__(self):
        pass

    @staticmethod
    def sign_test():
        """
        4c438510f34a2f15909b9a7e1f44b97e1e1f1a1553987185e7b70000000000000000
        1.固定头文件(4字节)
            4c 43 85 10
        2.2个标志位(2字节)
            f3 4a
        3.时间戳低4字节(4字节)
            2f 15 90 9b
        4.两个标志位的md5再进行计算的结果(16字节)
            9a 7e 1f 44 b9 7e 1e 1f 1a 15 53 98 71 85 e7 b7
        5.尾巴补0(8字节)
            00 00 00 00 00 00 00 00
        :return:
        """

    @staticmethod
    def cha_cha_20(sign_ts_hex, plaintext):
        pad = "00" * 28
        # 小端序转化
        value = int(sign_ts_hex, 16)
        little_endian_bytes = value.to_bytes(4, byteorder='little')
        key = little_endian_bytes.hex()
        key_hex = f"{key}{pad}"
        key = bytes.fromhex(key_hex)
        nonce = bytes.fromhex("a3a244ef7fe5a465")
        plaintext = bytes.fromhex(plaintext)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        return cipher.encrypt(plaintext).hex()

    @staticmethod
    def sign_eor(v27: str, v28: str, first_md5, sign_ts_hex, second_cc_20):
        v42 = [
            "28", v27, "47", "2B", v28, "2C", "4C", "4B",
            "28", v27, "47", "2B", v28, "2C", "4C", "4B",
        ]
        v42_str = "".join(v42)
        v42_bytes = bytes.fromhex(v42_str)

        # 固定值
        v42_m2_first = [
            "6d", "b5", "79", "08", "3f", "fb", "21", "1c",
            "7c", "8d", "91", "74", "94", "fc", "45", "61"
        ]
        v42_m2_second = [
            "28", v27, "47", "2B", v28, "2C", "4C", "4B",
        ]
        v42_m2_ori = v42_m2_first + v42_m2_second
        v42_m2_ori_bytes = bytes.fromhex("".join(v42_m2_ori))
        v42_m2_hex = hashlib.md5(v42_m2_ori_bytes).hexdigest()
        v42_m2_bytes = bytes.fromhex(v42_m2_hex)

        v35_bytes = []
        for i in range(16):
            v35_eor = v42_m2_bytes[i] ^ v42_bytes[i]
            v35_bytes.append(v35_eor)

        v36_1 = first_md5[0:8]  # 四个16进制字节
        v36_sign_ts_first = sign_ts_hex[0:2]
        v36_half = f"{v36_1}{v36_sign_ts_first}000000"  # 前8个字节

        v36_second = second_cc_20[2:10]
        v36 = f'{v36_half}{v36_second}78563412'  # 固定尾巴小端序
        v36_bytes = bytes.fromhex(v36)

        v38_hex = []
        for i in range(16):
            v38_eor = v35_bytes[i] ^ v36_bytes[i]
            v38_hex_per = f"{v38_eor:02x}"
            v38_hex.append(v38_hex_per)
        v38 = ''.join(v38_hex)
        return v38

    @staticmethod
    def get_key_rsa_tmp():
        key_rsa = "FmINxhUD9sV/bb5nsnI1/QOCCPaEl7dvDh1qWGmH1XTu2wPkTLxRrKLbPtI9TUtYR7CDqMsP0RE7N0zRnVSJA1E+9hys4ee0aT/IuchAU7WtJMwKnCkM5dh8iD4J6fdpLocNqARqrQmOWhUggWA48+PLDRtlVRryKFYmXM3k9TQ8mCKXhUV5fBE2URbkJ3gXzNuZ9SYqY8AgrdJLVrLTpqYfdBAAO07FTqlWDdUj0jLzUWoJM+GG1ou6FLGkIi3yDABgDrmHu2E1PcYokH7qwprUQbOl4I6iu6+5/72a5mCkIzag9ZG03IGqid64tUZ2Tfq3Gjl9nMlGWPcIueA+aw=="
        return key_rsa

    @staticmethod
    def get_params_aes_tmp():
        params_aes = "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"
        return params_aes

    @staticmethod
    def get_nonce_tmp():
        return "c782add062d6e9a8"

    @staticmethod
    def get_sign_magic():
        magic_header = "4c 43 85 10".replace(' ', '')
        return magic_header

    @staticmethod
    def get_ts():
        ts = int(time.time() * 1000)
        r = hex(ts & 0xFFFFFFFF).replace('0x', '')
        return r

    @staticmethod
    def get_first_flag(key_ras, params_aes, ts, android_id):
        md5_str = f'1{key_ras}{params_aes}{ts}{android_id}'
        md5_result = hashlib.md5(md5_str.encode()).hexdigest()
        return md5_result

    @staticmethod
    def get_ts_hex(sign_ts):
        sign_ts_hex = hex(int(sign_ts) & 0xFFFFFFFF).replace('0x', '')
        return sign_ts_hex

    def get_sign(self):

        sign_ts = '1740278289132'  # 当前时间

        # 都和params有关
        params_ts = '1740278289115'  # 当前时间
        key_ras = self.get_key_rsa_tmp()
        params_aes = self.get_params_aes_tmp()
        param_nonce = self.get_nonce_tmp()

        sign_ts_hex = self.get_ts_hex(sign_ts)
        magic_header = self.get_sign_magic()
        first_md5 = self.get_first_flag(key_ras, params_aes, params_ts, param_nonce)
        second_cc_20 = self.cha_cha_20(sign_ts_hex, first_md5)
        first_flag = first_md5[8:10]
        second_flag = second_cc_20[10:12]
        sign_hex_str = self.sign_eor(second_flag, first_flag, first_md5, sign_ts_hex, second_cc_20)
        sign_end = "0000000000000000"
        sign = f'{magic_header}{first_flag}{second_flag}{sign_ts_hex}{sign_hex_str}{sign_end}'
        print(sign)


if __name__ == '__main__':
    M12Sign().get_sign()
