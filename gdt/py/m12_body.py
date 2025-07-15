# -*- encoding: utf-8 -*-
# @ModuleName: m12_params
# @Function:
# @Author:
# @Time: 2025/7/2 14:12
import json
import os
from base64 import b64decode, b64encode
from Cryptodome.Cipher import PKCS1_v1_5

from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.Padding import pad, unpad
from hexdump import hexdump
import hashlib
import time
from Crypto.Cipher import ChaCha20

import params_pb2


class M12Params:
    def __init__(self):
        pass

    @staticmethod
    def get_sign_magic():
        magic_header = "4c 43 85 10".replace(' ', '')
        return magic_header

    @staticmethod
    def get_first_flag(m12_crypt, key_ras, params_aes, ts, android_id):
        md5_str = f'{m12_crypt}{key_ras}{params_aes}{ts}{android_id}'.replace('\\', '')
        print(md5_str)
        md5_result = hashlib.md5(md5_str.encode()).hexdigest()
        return md5_result

    @staticmethod
    def get_ts_hex(sign_ts):
        sign_ts_int = int(sign_ts) & 0xFFFFFFFF
        sign_ts_hex = f"{sign_ts_int:08x}"
        return sign_ts_hex

    @staticmethod
    def cha_cha_20(sign_ts_hex, plaintext):
        pad_end = "00" * 28
        # 小端序转化
        value = int(sign_ts_hex, 16)
        little_endian_bytes = value.to_bytes(4, byteorder='little')
        key = little_endian_bytes.hex()
        key_hex = f"{key}{pad_end}"
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
    def get_key():
        random_bytes = os.urandom(32)  # 生成 32 字节的随机字节
        return random_bytes.hex()

    @staticmethod
    def get_rsa_pub_key():
        # 公钥（Base64 编码）
        pub_key_b64 = """
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApLEpcsiHA/PE4MKl7WS7r11RijhytmEQ
            H8jaY3nKhvq/KC29yEpJVAu+/asRp9mpoxCAiaTxJynVZMw5amwe24ff0Eau/MLCcfG9jFq8fp0L
            JwXmKtJuwha2hVr6zhW1+Q1h8f3T9hu+QMZTRxqQnIY1mjqDY1/ARAK2hMzS+uoB+COosppWgFxO
            cQhzkjcM7Oa0RO+rSaatWsgBrKspVEXFMYfHS+awD8qGXZyyOVaiDNvXgLfPecJerKCOFdujwR3i
            sgtEEe8yyRryUm1FZgdIi8e+t23Lp0XDDB6LCox7DWLKmRjQ5K/5R7+HmSwNLANkw6yTUuLtYcoM
            Y2nOUwIDAQAB
            """.replace("\n", "")
        return pub_key_b64

    @staticmethod
    def encrypt_rsa(pub_key_b64, plaintext):
        key_der = b64decode(pub_key_b64)
        rsa_key = RSA.import_key(key_der)

        # 执行加密（PKCS#1 v1.5 padding）
        cipher = PKCS1_v1_5.new(rsa_key)
        ciphertext = cipher.encrypt(plaintext)
        return ciphertext

    @staticmethod
    def aes_encrypt(plaintext: bytes, key, iv):
        text = pad(plaintext, AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(text)
        return ct

    @staticmethod
    def aes_decrypt(ciphertext: bytes, key, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)

    @staticmethod
    def create_params(check_b64):
        m12_params = params_pb2.M12Params()
        app_info = params_pb2.AppInfo()
        device_info = params_pb2.DeviceInfo()
        default_info = params_pb2.DefaultInfo()

        # 组装app_info
        app_info.flag = 1
        app_info.ts_nonce = "1752568612521edd1e00bae86eac0"
        app_info.status = 0
        app_info.unknow_1 = "0AND05YQXE52BNH0"
        app_info.js_version = "2.1.2.17"
        app_info.sdk_version = "4.640.1510.219"
        app_info.os_version = "Android 12,level 32"
        app_info.model = "Pixel 4"
        app_info.default_info_1.CopyFrom(default_info)
        app_info.default_info_2.CopyFrom(default_info)
        app_info.package_name = "com.qq.e.union.demo.union"
        app_info.network = "wifi"
        app_info.network_type = 2
        # 组装device_info
        device_info.default_info_3.CopyFrom(default_info)
        device_info.unknow_2 = "35"
        device_info.qm_uin = '{"QmUin":"1752568612521edd1e00bae86eac0"}'
        device_info.brand = "google"
        device_info.k_list = "k1:2025-06-06173101.558333356+0800;k2:2025-06-06173128.228336013+0800;k3:0000000000000000;k4:8a196b9a3e36b6db;k5:13106683;k6:12786688;k7:215040;k8:2800;k9:e7ce6953-761e-4864-a8f6-ccd87a76a7dc;k11:171;k12:4;k13:2025-06-06173128.228336013+0800;k14:2025-06-26153944.322408685+0800;k15:2954;k16:16;k17:2025-07-15163651.947917450+0800;k18:2025-07-15163651.947917450+0800;k19:659358;k20:4;k21:2025-07-15163651.947917450+0800;k22:2025-07-15163651.947917450+0800;k23:659359;k24:2;k25:2025-07-15144420.113911509+0800;k26:1970-02-19064925.840000631+0800;k27:22042;k28:15;k29:;k30:;k31:;k32:;k33:2025-06-06173128.785002735+0800;k34:2025-06-12191233.638222757+0800;k35:3773;k36:17;k37:2025-06-06173128.785002735+0800;k38:2025-06-06173128.785002735+0800;k39:3772;k40:5;k41:;k42:;k43:;k44:;k45:2025-06-06173123.808335573+0800;k46:2604;k47:2025-06-06173101.478333348+0800;k48:2025-06-06173103.768333576+0800;k49:2025-06-06173123.865002245+0800;k50:2606;k51:;k52:;k53:;k54:2025-06-06173101.478333348+0800;k55:99;k56:2593;k57:2605;k58:2025-06-06173113.881667917+0800;k59:2025-06-06173113.881667917+0800;k60:1990;k61:5582;k62:2025-06-06173124.188335610+0800;k63:2627;k64:2025-06-06173123.511668876+0800;k65:2599;k66:171;k67:2025-06-06173106.721667204+0800;k68:382;k69:;k70:113;k71:2025-06-06173101.478333348+0800;k72:114;k73:2025-06-06173101.481666682+0800;k74:2025-06-06173106.821667214+0800;k75:;k10:1"
        device_info.default_info_4.CopyFrom(default_info)
        device_info.unknow_3 = "df5abd5bc6536767086732bdd03525d05a3dc68e08500870bd9a5b3adb329e22"
        device_info.default_info_5.CopyFrom(default_info)
        device_info.default_info_6.CopyFrom(default_info)
        device_info.default_info_7.CopyFrom(default_info)
        device_info.default_info_8.CopyFrom(default_info)
        device_info.system_info = '{"harmony":"0","clone":"0","containe":"","oz":"ZyjSxsx+BaNjy+w4fD1MC+4h9HkvETw+\/QhmVTHoSR0=","oz2":"","oo":"7FszTxhlP42TZPpH1M2Eyg==","kelong":"0","ip":"192.168.66.25","multiUser":"0","bod":"flame","brd":"google","dv":"flame","firstLevel":"29","manufact":"Google","name":"flame","host":"abfarm848","kernel":"Linux localhost 4.14.261-gdbc92b7a2b83-ab8577204 #1 SMP PREEMPT Thu May 12 09:07:20 UTC 2022 aarch64","pre":"0","av":"4.640.1510.219","ch":"","svr":"","fit":1749609461905,"jv":"2.1.2.17"}'
        device_info.default_info_9.CopyFrom(default_info)
        device_info.platform = "Phone"
        device_info.ts = "1752459011"
        device_info.default_info_10.CopyFrom(default_info)
        device_info.unknow_4 = check_b64
        m12_params.app_info.CopyFrom(app_info)
        m12_params.device_info.CopyFrom(device_info)
        return m12_params

    def get_m12_key(self):
        m12_key_ori = self.get_key()
        plaintext = bytes.fromhex(m12_key_ori)
        rsa_pub_key = self.get_rsa_pub_key()
        ciphertext = self.encrypt_rsa(rsa_pub_key, plaintext)
        m12_key = b64encode(ciphertext).decode()
        # rsa有随机值，验证时固定 todo
        m12_key = self.test().get('key')
        # rsa有随机值，验证时固定 todo
        return m12_key, m12_key_ori

    def get_m12_params(self, m12_params_protobuf, second_aes_key, second_aes_iv):
        # 固定的key,iv
        first_aes_key = bytes.fromhex("ff802003f67f55be8b535a97b01b459d")
        first_aes_iv = bytes.fromhex("b8221969c27a8019d533b139ade71bcc")
        params_first_result_bytes = self.aes_encrypt(m12_params_protobuf, first_aes_key, first_aes_iv)
        params_second_start = bytes.fromhex("0300000001")
        params_second = params_second_start + params_first_result_bytes
        params_first_result_bytes = self.aes_encrypt(params_second, second_aes_key, second_aes_iv)
        m12_params = b64encode(params_first_result_bytes).decode()
        return m12_params

    def get_m12_nonce(self):
        nonce_ori = self.get_key()
        m12_nonce = nonce_ori[0:16]
        # 验证时固定nonce todo
        m12_nonce = self.test().get('nonce')
        # 验证时固定nonce todo
        return m12_nonce

    def get_m12_sign(self, m12_crypt, sign_ts, m12_key, m12_ts, m12_params, m12_nonce):
        sign_ts_hex = self.get_ts_hex(sign_ts)
        magic_header = self.get_sign_magic()
        first_md5 = self.get_first_flag(m12_crypt, m12_key, m12_params, m12_ts, m12_nonce)
        second_cc_20 = self.cha_cha_20(sign_ts_hex, first_md5)
        first_flag = first_md5[8:10]
        second_flag = second_cc_20[10:12]
        sign_hex_str = self.sign_eor(second_flag, first_flag, first_md5, sign_ts_hex, second_cc_20)
        sign_end = "0000000000000000"
        m12_sign = f'{magic_header}{first_flag}{second_flag}{sign_ts_hex}{sign_hex_str}{sign_end}'
        return m12_sign

    @staticmethod
    def get_check_info():
        check_info_ori = {
            "0": 1752569137,
            "10": 0,
            "11": 0,
            "12": 0,
            "13": "",
            "15": 1,
            "16": 0,
            "17": 642918629,
            "18": "guocao.tencent",
            "2": [{
                "2.1": ":\/memfd:frida-agent-64.so",
                "2.2": 0
            }],
            "20": 3,
            "21": 2,
            "22": "arm64-v8a",
            "23": [],
            "25": 1
        }
        return json.dumps(check_info_ori, separators=(',', ':')).replace('\\', '').replace('/', '\/').encode()

    @staticmethod
    def test():
        data = {
            "crypt": "1",
            "extra": "{\"appKey\":\"0AND05YQXE52BNH0\",\"crypt\":\"1\"}",
            "key": "OS+rKHoN5X5LbCqT6rREr5oUeEfib+Tr7KWFHWjdjhfB5gUlbUUOy1peAsQ9LrH8yHU6WM4Jvdj839mtUWT9k+6HkTg0WH+li\/X8kT5cTwPWDi2VKbqjDyOvlfj2Y7QD0jtoa+yaHYoavf0NleCwJuJaBJ9ZISA6xC3eT4wZJSvUmYDrBW+c5XgcJWLylzuwUJ3Z244CXYZjQESlcyCEXP+SEKeoexaFvj4uWhWDJdBo2iAlbnYyXekXfLrq5cGkUsHt9rG9aITqRkDRhce0T+b4ID09XBArobohKddwmxPasqKnMIyxoojlI3CsABewhRfWXS225kqWB2mFcn1x3A==",
            "nonce": "1b33c64e0e66b39b",
            "params": "YabqSC+rhODm6g4Dz0qZOSD53u8Dq54R3vf4H\/FjSzR+TaHRthPPs3DNpadlD+eTmCSEBP4mHMsV9\/huk94NQ1qXtavyo8lkrSff3dCQ\/0KVabu5EZE1tVCx3kZ+BUZS9ltITRdhDMaOyvqHpVSSrFQFu8iTMtn0bXaMNyxBNTd4JAwUAM3GcswepQ6q9WZ5y68eX7R3D08187\/L5hniXtZ2AQna4MbkUVtCGJHcXb0C7Oz+MOZrHLinFBFuzS2Cr5e+0OMVGt7y6Ryr9P\/UUHC67ZP7UJ0IgL3CwYvIeyqFjSQJKTGa6LwSQcFvWmbiKsLGMpvZHVWCaymxUXx9nGSU0qnsARhGMPgE\/cVjZtKFUY2FcHVjTmChZ3xH6hytFsNxY+zdWFWMciapJDcrAALSMtkuis7obp6iwjxdVe0sOq6EehL1H7HNFXXl0td28IzkNSwhVVROmx8N73d2zdOnJqsn4sn85tzLNtX5WdsofyeGjxS\/7PZwtTT8vPNpcKUOZFcEjRkJIJZls3gsk0bgaK3H4hB\/hNZ2mKJNgjHQdpQv1mchNAx+RqRCDExmt2UeKBa6P\/E3+a+UGxzTh7ElvV6Y5o9d85uL9VG\/GwAXFSZORFncdB6IA9TXkWbqUw4O3WF\/M0yQ2EvwxGPwT6DkBHjkEO2tuIzM2cdDC7sg4KNIT7adxn4Vx+ef38BDh34rEUdG7jyDTzJx3WxQ1n1Fgovkr2NLi7k69PGtQObgJvviE1wjvzBzGvy665EtfHdqEGrmkd9xT3AtqH7wHCWqXZv9w1TpaEAsbeuDJF+jXto2R+GTtMz584mFY71HCARfRp4qjmTPICt2WfUApjsMOO9qd4fD8klFpOM+6cmDsWHh3I8H3gjH0i6WhyPKsdoMt4\/0NKskNMj6hJueRgp0QJ1XoNw2NVqzwPIx3zGyIzlwiTqiArXGmD\/t8qYThYtT5d36NhdzVQi4WBdIbMSYG2PECDlEV4YLZLa19iQhkfr3a43T4MyQXs0Mtgw5vGRj5d+1Q7R61x\/XQtJYFiI8YyVtlDCbJ0BK\/izDU1qY8c\/+QVIPVawVU4L\/IfwPCpNj0MbUWLAIZ5hA9LkXsLPSphqulY+KAI\/Do6MtLb03CWRgKMsUmAGgE5bCxe4mTw3h1Y8hGnLSJb5NIn+MY989ye4zMo4P\/9teo7Rl9axCOAeBFZCIA3zUC2wE4UT13kZIe1D5fiNRN7Kwx9VZ\/2QbqyKZtcW7GPws7XINsqrw4z4VcRjR4aemWwQExoxVexmLOTS42L1GItGMZ5XTyIj8S1V8sux9xwBLUR5jH3h5kXwidGc3whNYUtP918\/T28rsGViZk70LzG+IS\/xHEXj31q3NujMa75P1bSG868TDGRwdW790ak4shQKeqOChEARIrsKDRSWMZgiDqdcPnZL8b3uYw68C7hKVp2LpggAKASKUFRnWr3YK4uzxmBuS8JR1eEq8cDW2m5X5DaOWNYjjqt+MJ\/MSfCRPeh5UvtSg58dKUuU1myQlwLZUdfvSo9N5hNhUxv6vy6l\/FyQ4VxH6aN5llv7INsEe\/AQgww3WUJrX+CcHkEWglwLzhVfNw2AiT+US4dqWU+wSEw0QgO8i9JNWacZPixiv3x5eNHT5hzVGxrffUMxaXL7kdlayuJrq7Ly19jj4lDdZXvaX2pT\/cTIQE7s4fCKbjhOsvL1EktFt217XHtLN6BYEyz75tqCs8KnHuBZPrYaAyZ4BslMNGw5EyC61QDKm2CL2aLY6NLrm+kKYUMsE9HAJeH8w59sCvet4P4m5oYEHwQKLlDWFydLdYNRyjubzv\/aXQ1CCnulf7Qb953WQYfJw3W20zuQyijg21ET9NYTbEKONx4sunks2+EhXRIq4hgdBBVqvoPefQ3FQXG4XulVlqN2EhqyUNULE\/V8wKNk4C1NrTlZeud6xdY3IWDceWsxMKhNAXox31pIjN\/Hnr8C8noRF8kSBoT5v6QCah72\/by5HkzLgNphk71Tvb+eNLNaBEc3b4A9mRYnU14dG5rubaLEqX9UYZ3SUDb+6OlzJCMQobIkXmn3i6rPnoOVSJI5nkdRaozlqrbcRNX8dyk1ZKqeSNgzYq5iYclrlieQD+ortusQ6lN1RrJB\/c05Ziy3hdX4f81\/cxbOJ8DN3zjX0zQf+zo9BEQiEp51jBEioFtlveW9dkdgO\/espY+hDOhZpO9vuR+Sff+2\/ccEvoXkJl1NP4ukOmjgV2U3lg3I4JEwbDvYVlo\/0kG7DN6Kx95CztG8MLEjX5KSUno4IpYzmgEQo1bONj7nVyYs6cnwUZexsseKeEV\/rNle4ayiQFvYtXZRwYurp6VJ2LI8wm5GNP4TqdyZoS82m7zwhLLN6MSUCVd4mhO05Rl1\/hO\/aAE7ylI3YTIbFIR7kBoHX0RJxyvXzPWvShuVYNUSGxZoGOY3AlcBeL0UkJipg+P1tF1l975\/Cn0BLedC4Zuw\/ENwwPFXaIXc7+Owj0jvSnDqdE39seG2BQfSrnGvI12QXjEsn7B8SyeirKSLgx62eb8AsQg6cI50dQGgpnh5tuhxR1Csu6M\/oldgzzKIklFExvxNp7b2gbcRzFjysLPnGveMTFgHavv\/mOupA5ZBMxQUw88JJRUqexfSbHdh0KEt2C5SCtpa4HM9vGb2STbwhSjg+N5Mkikv2vFDstxO4lFk3c6NguMMzurh5LFd5fdxS0xWXCEgloVy0kpn3K82BC8CKC+6xQGES00aMtwVy\/SIbgMdbneoFwQjkslcRdC4LMd\/ra0G\/TRTtQBPfwmCCHknnj4DI2nKtodA0qZyQm8UO1f0NY+1pzr9AoVBWYGlJ76pRd1TZ\/IcbbSzNFHbSASmxKbL\/L3do2K9HZMdP65CeMAO6O3yOVuXvbqR6iS5oyL7v5iHXhyLFNR1vwT1FcFFyZGyqGUgoOZUL6yR7By8AidbeJ6gZIa66bNFSmD2PZ3krRx\/y+KN4qplY4zaFA4tuRNAoJNGO1QJJnOvC5b9wH5k\/FL9GCQxLzFmt+YnTlBSyJgZjxyU6lAB80VtolNvP1x2lO4RGoS7cxSGKlprPjK2DSvNE2C\/ZWiQpPk91wlCQBKM2Odcm3B66NqtxRCzUWIlG3jhJbLeCQ+xN4zWT\/j+Vb3TjDAWlwfXqpwyWYKskKEJwkpwVeBj1C45NlriW96+lqdFKLmqksmntNjMv+0CZo6vjlwgjp8KFKTWQQcRANeH5Aq\/MQIEZ8dJRvAhnPpHERvoVPVb0gmunJe+\/gsA82gocN+PKDIMQ0wllnnVHxJ6BILIqyKwetbBRFaxL8XeEEgTNgNnytce2atCcp3A7Jg==",
            "sign": "4c4385102ccd0d3ac8b0f1c864aa0fb061036abf17d73ce050d50000000000000000",
            "time": "1752568613022"
        }
        return data

    def main(self):
        m12_crypt = '1'  # 前两次是1，后1次是2
        # key计算
        m12_key, m12_key_ori = self.get_m12_key()
        second_aes_key = bytes.fromhex(m12_key_ori[0:32])
        second_aes_iv = bytes.fromhex(m12_key_ori[32:])
        # 验证时固定 todo
        second_aes_key = bytes.fromhex("1b7013a5ec217e52bd6bc049f9e8518a")
        second_aes_iv = bytes.fromhex("0ebe5f888820c93ad63866802440198b")
        # 验证时固定 todo
        print('key:\n', m12_key)

        # params计算
        check_info = self.get_check_info()
        check_aes_key = bytes.fromhex("65626165636665346665343863393235")
        check_aes_iv = bytes.fromhex("62626633353932366533333231303632")
        check_bytes = self.aes_encrypt(check_info, check_aes_key, check_aes_iv)
        check_b64 = b64encode(check_bytes).decode()
        print('check_b64:\n', check_b64)

        m12_params_ori = self.create_params(check_b64)
        m12_params_protobuf = m12_params_ori.SerializeToString()
        m12_params = self.get_m12_params(m12_params_protobuf, second_aes_key, second_aes_iv)
        print('m12_params:\n', m12_params)

        # nonce生成
        m12_nonce = self.get_m12_nonce()
        print('m12_nonce:\n', m12_nonce)

        # sign生成
        sign_ts = str(int(time.time() * 1000))
        # 验证时固定时间 todo
        sign_ts = '1752568613040'
        # 验证时固定时间 todo

        # 都和params有关
        m12_ts = str(int(time.time() * 1000))
        # 验证时固定时间 todo
        m12_ts = self.test().get('time')
        # 验证时固定时间 todo

        m12_sign = self.get_m12_sign(m12_crypt, sign_ts, m12_key, m12_ts, m12_params, m12_nonce)
        print('m12_sign:\n', m12_sign)
        m12_data = {
            "crypt": m12_crypt,
            "extra": '{"appKey":"0AND05YQXE52BNH0","crypt":"1"}',
            "key": m12_key,
            "nonce": m12_nonce,
            "params": m12_params,
            "sign": m12_sign,
            "time": m12_ts
        }
        print('m12_data:\n', m12_data)


if __name__ == '__main__':
    M12Params().main()
