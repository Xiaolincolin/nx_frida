# -*- encoding: utf-8 -*-
# @ModuleName: m12_params
# @Function:
# @Author:
# @Time: 2025/7/2 14:12
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
    def create_params():
        m12_params = params_pb2.M12Params()
        app_info = params_pb2.AppInfo()
        device_info = params_pb2.DeviceInfo()
        default_info = params_pb2.DefaultInfo()

        # 组装app_info
        app_info.flag = 1
        app_info.ts_nonce = "1752560312003dc0f57a2b96f07be"
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
        device_info.qm_uin = '{"QmUin":"1752560312003dc0f57a2b96f07be"}'
        device_info.brand = "google"
        device_info.k_list = "k1:2025-06-06173101.558333356+0800;k2:2025-06-06173128.228336013+0800;k3:0000000000000000;k4:8a196b9a3e36b6db;k5:13106683;k6:12786688;k7:215040;k8:2800;k9:e7ce6953-761e-4864-a8f6-ccd87a76a7dc;k11:171;k12:4;k13:2025-06-06173128.228336013+0800;k14:2025-06-26153944.322408685+0800;k15:2954;k16:16;k17:2025-07-15141831.350423890+0800;k18:2025-07-15141831.350423890+0800;k19:605185;k20:4;k21:2025-07-15141831.350423890+0800;k22:2025-07-15141831.350423890+0800;k23:605186;k24:2;k25:2025-07-14141202.741778138+0800;k26:1970-02-19064925.840000631+0800;k27:22042;k28:15;k29:;k30:;k31:;k32:;k33:2025-06-06173128.785002735+0800;k34:2025-06-12191233.638222757+0800;k35:3773;k36:17;k37:2025-06-06173128.785002735+0800;k38:2025-06-06173128.785002735+0800;k39:3772;k40:5;k41:;k42:;k43:;k44:;k45:2025-06-06173123.808335573+0800;k46:2604;k47:2025-06-06173101.478333348+0800;k48:2025-06-06173103.768333576+0800;k49:2025-06-06173123.865002245+0800;k50:2606;k51:;k52:;k53:;k54:2025-06-06173101.478333348+0800;k55:99;k56:2593;k57:2605;k58:2025-06-06173113.881667917+0800;k59:2025-06-06173113.881667917+0800;k60:1990;k61:5582;k62:2025-06-06173124.188335610+0800;k63:2627;k64:2025-06-06173123.511668876+0800;k65:2599;k66:171;k67:2025-06-06173106.721667204+0800;k68:382;k69:;k70:113;k71:2025-06-06173101.478333348+0800;k72:114;k73:2025-06-06173101.481666682+0800;k74:2025-06-06173106.821667214+0800;k75:;k10:1"
        device_info.default_info_4.CopyFrom(default_info)
        device_info.unknow_3 = "b16d03d2f79152af377f756e7fafdfca954b3746db6df7db51aa37afdfdf5f46"
        device_info.default_info_5.CopyFrom(default_info)
        device_info.default_info_6.CopyFrom(default_info)
        device_info.default_info_7.CopyFrom(default_info)
        device_info.default_info_8.CopyFrom(default_info)
        device_info.system_info = '{"harmony":"0","clone":"0","containe":"","oz":"ZyjSxsx+BaNjy+w4fD1MC+4h9HkvETw+\/QhmVTHoSR0=","oz2":"","oo":"7FszTxhlP42TZPpH1M2Eyg==","kelong":"0","ip":"192.168.66.25","multiUser":"0","bod":"flame","brd":"google","dv":"flame","firstLevel":"29","manufact":"Google","name":"flame","host":"abfarm848","kernel":"Linux localhost 4.14.261-gdbc92b7a2b83-ab8577204 #1 SMP PREEMPT Thu May 12 09:07:20 UTC 2022 aarch64","pre":"0","av":"4.640.1510.219","ch":"","svr":"","fit":1749609461905,"jv":"2.1.2.17"}'
        device_info.default_info_9.CopyFrom(default_info)
        device_info.platform = "Phone"
        device_info.ts = "1752459011"
        device_info.default_info_10.CopyFrom(default_info)
        device_info.unknow_4 = "lLdF9dILb92dOPYBihkbhmiDUF63PIryW83PpKZ1u21q7RFssq6SBYUoJ0Qrj1xs06lFMbjk7DhC6luTb/dTLPRAmmu74ye2DeOT2nrjTCwS/RqfTx7pRZBIPj1yk5kUD5z5eDqLV7AhK7zb9BzIEzvZvRr9fnYhT8Z7O/he0T40JJrm97J5508vIqDjRwQszew6Z7rpc4WGZF424pD3GbXVVGhEKAfPb1AgFiodgMIJVpYwsa4Djich26SDCUMRtUGVvjVcuv6H3tziarhkwQ=="
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
    def test():
        data = {
            "crypt": "1",
            "extra": "{\"appKey\":\"0AND05YQXE52BNH0\",\"crypt\":\"1\"}",
            "key": "ni6scW3CcU8Uhzb0jjQZNKaXbSUwLZWHXMBWhA0YYDCrxfn32K13Y6zuNYDb3NEeza\/59XuE8GDyoxQ5HVI2PHV4tzpjgiyTL14t8qQl9qLOvjrNA3hMeVyEhRDzlHoz2RcQxDBr8HBJrArD7MqyJWCQ+cc+X\/BymEIuHNyhTVQgVxrJC\/NWtQw02PPZTMLCZhwHxKmhJv6v0EbUFfWURR9BS4e+K0BWpg63PmxTPwvOqDMjyilschyTvqVQ+l2SHJsgUNyknEwprQr3LKy5xaT+oJpCs3WQ4JQ3HRDjDEYry+RojsL3NOkQJGLC0uXKXIoL\/RNhdH341DuNii9Klg==",
            "nonce": "ac22249c91a09a12",
            "params": "iUlietJ+ryOsKucPw7TomWjtWEZWkhyuKPr4Efj3eWHq\/98Je+3tgHiCuRNxCYxGnDrBg78DQrxijQQOreR0bxAZiYtAyTAQLL28whS5K9Bivd6KrfrL\/6ukUF1IEORsJ1eInaS00m5BWxOwyRdGEHlh3+DzbLVMyXhFSsChLQcQ\/KKcOZTOwGml9vfbrAa\/LDRcwk3mH3MXFFh+9sqXjRVHDA+1njvFGhhWZOeuHWn6HG7hnUgSnwul7MtMe5115UNHKwFGusO3aZXrUJE0qjI7O7LLR79Yk2hUXQSZo+AEKvIvbva23Si17IY2uSlYxE8UyCVtaAQ4hsnQEudpMGyPQmlsSP6cJnyjakWFuPKFtRAUujEW74uPBD0yru4oYw5NueyoYYDgTznnsBPdWT6fndl7mdkJilcLWy+yzOeNgg+O8UVeWmY5tFAs8rnFxad+PMxS8lALOQBHNSj2yjYStVUearOnF1wmRI85dyj84sNvqwv\/T6Wvzw44YdRXVAKjj+sw9ZEsez1dRAVMVxzNUTX4HEi6ms\/i53Trs3jldAyhiNzDCqZsWWTyv3Od8pBdXssioZuWTOeSMMHxMtwfv\/HzkChnL8cLpbqh6+1Ly9\/hQvq4RfEvII6i0iN4iINPVK0ZmkdTUfa\/ZCdgxRkoyxvDISEZ3cFJqF3t0ndyBjYEP9tB\/PQYx2lb4\/acYxi0z96kyO4sil6uFRQ+zSrLCheSLTXcr5PeRSiRZ+PH3EORuSONZoxzuRZUqfiv8JLtNE\/Obx\/f+FB9MI4faa0QZrmfigtfh3itGWgcPQSWUC0Cy8APuNjIuwIFJDg5KzfLk8L60d0zeb2KxhuDbeJjMG5gHjHBtcyew6FVsnu81ACkuSfn1\/fRgMKuEy1HuogdcSIhPJsulNzHFXndUptrYKzfsqYtANd\/btXBcsiA8bRC4YSfDdqbjrYAeDq5IB5biP2jhOcqNuDewkZw9N4u56VGhZ\/YSBoZNNyeQxExKkWDao\/q6uI80tsERtfC\/+3qcJx8EnmYxh83tx+OQnmJi69Us6tPuz5s7bYYLf9et3\/bQd+URfSNdyCeL0FBTR621KHJjFl\/eJ8bi0EJdZETzbq7kxsXeflCnw2MSkWl+cu4Ny\/cIUrXar1AKP1+Z3Hj8xbfiuYQ4m9zCCaP0VFrPlaYLoTwflaBcFtbwEwra2lfO8o0acTL8f79XkhMyVY5yn8CJ2UsHdxJHleUL1YN0h308cOrfZ3TqhPR0B3Iw1C8GpU5XfkbOSRLM1fl7G1fluHkHGZTTfnE3J6X5RblRpsd1LN0WjAPwGccMOfbeNKpAWRiK9HTUMYNlx+KMnV7lH77ig64L\/wBnTjXshI7dzib4GgmA+qQX7PN5QfBAhScS2Fga3FlnXh16HTv2YcD4hZuNNPhkKh+VFR9FO9TcXsVkh9AzeLCmbq\/VnS5WIBDp3bBYwhyk3tjCC4bvHyWhF6CcuDfdVZlOn99ZPXbX0K5o4uhjCDs6T8TOtDWb02PJ\/Yxy5mu0DIRYG8HhMZoP8+SN4EWn43tnx3\/qDm4QwLZm2UZzzVeq+L6S6HMpvnYBPO35rYAm6qExChYPloL3X1M9xjb1nLQq4WJM8ZIlD5+dANf9TBQ6oHeAR6SxIghmvhn6npjH0uQCL+sTWM612Loo2elk9Xq6z005e70qoSkZsFoHUvOVKar8dRBnemsaANFtsLa\/vOwSr2gD9oDTmhtHgOOc0FQ2JgwfojH7KMNippMEije0GtAowadR8kBczPioMFqO0dUz+2QHProE1t7GI97aSoZP\/iduyGNvfkEpUKRDcZ\/HVMsNB5yiW7G0TYF6cxTOTvKmq+Hqb1Js3J9jpDxZ4DOOkCzdnb6eBVum6h5Q5lmxQDQ7uVdD9IIKoGpd6oFompD20plZw73ExCizPAE7FIezyrua2L+Wqr8OD1NGOKpCeujcEDc\/KnXRkoMGDRt2Gqo97IFC+X\/dRfavhVjKY8ZE6NC3teJhC7acFhSyVVsYgCcmHLn0Sc0ut2VVNKCS0nVmHyZWY2X7EfE46aOA1ZuyXUU6lunIn6QGRLzhCo+UROk05sVc7aFcDXw0xiBYqnx24iCm6iV6H4vmZ56izwn6GkMw0OROtQ+Dmt0w08guei0v0RE6Gzv8IyaNvBDpo9K1DAc2tufNW68SKTGIKlAXbS08f9ZxjHWiq6HjnBmh5VG62De243TTAtdgW9dJehRzVOGLX2azjti3280O4JTT47keWktEVnO4vooX7IcDOJtpmSKJTt0kfUCh2p47m6ibvHoWYc5oPbV4u2wBQ1KV1zVPqAmb22dgnKs7xHJQHKxEw6gVg+hDWKG2T5e\/YjWU7IrINiZmjfJ4P4vlL\/jEvcFIlxdNzjS5kaV3Musq1sJpXE1Oo1ozygCcb19mmpQd1HY\/WI689AK2lu29jBAarYUKX+oO0XCqfkNrdfNCZSitl8MlKPMGWhWN57zdGQ1h9NLA0XNQ8oarveanfrSzf0cJbb3TUBHwkJ3txqI6zTEPcEQAAzEL52EYlPBjX\/fZAIohN6WXXeaUFfbAl0yRvtJ5OUV481i4h4m\/xI3wdsjd+xTxhUiQNYo2B52+XY3TO0vRLxvIqblcsgP72bAat6Ahh12DDxlDtlegK9bQDuzHLkA7s\/2eufeItdcMSM9E6TiLDSweN+CHgaNJiMap9jx9Wy4SBMb1Mxrj3HE4L+AzVz34X\/3SAacy28CgEG4I3X81Ag\/3tO2lKbgsN19Ab4Vckm5Ptcs0HFbk5vfslnFNxyvltT41MEh74ECAboKcTs2G\/Q\/Kdijid0Q2JH41kjn26e1q9TFOIAsQll1sBQotzUkxFhx3Luxsn+33n2x\/fAEYZSkQLHEAwLkboK4KgmIxVptTfRJtK2lcAOyPK2TMvQQ0lvZLv6IKQItMz2M6gpN+CkW5F687y1h\/cjZpsaHwmnoerDk5o8Vw2kp37MmiH1Hh6SwcX71IWdPVED7+GQbZIvFMzXYupEEsXaF7qoQwuwR872ZkYTzM5lVS3fB6KamZePcXJRHqcsqMxp5Rc2gl34oUyhkxaJ2DUMipvRufq0Q8oE4GiN0UVaF+Um+eg8zzvYVLfbwx\/69V4PCUrcM+\/viCY4Wh3c6KLvE8s9Dyj5OY3LemkBwCuhGQh+tmhRah8dXJF\/3rTPOoct9il1GcZuy4vjbyxSF4rymuqo2yErnLlkwcvfQQZ8CBjp2mpmtQBIa64vj1WjROxlB026XF7vGaZ8gRCdp+9wuHM1kw0tbK4kLT0EW6aoFSJ0LGGdG52AYEeUfkNsxTzKqALbp\/MtF58qqlBKAtgvLC6B3fg==",
            "sign": "4c4385108ebb0cbc2270bc54088ea84ac729f7bffc73c7b44f0b0000000000000000",
            "time": "1752560312922"
        }
        return data

    def main(self):
        m12_crypt = '1'  # 前两次是1，后1次是2
        # key计算
        m12_key, m12_key_ori = self.get_m12_key()
        second_aes_key = bytes.fromhex(m12_key_ori[0:32])
        second_aes_iv = bytes.fromhex(m12_key_ori[32:])
        # 验证时固定 todo
        second_aes_key = bytes.fromhex("a3d2b3da6b978edd32fdab291b3508ce")
        second_aes_iv = bytes.fromhex("e1aaed6d622a8d00df94628270819f8d")
        # 验证时固定 todo
        print('key:\n', m12_key)

        # params计算
        m12_params_ori = self.create_params()
        m12_params_protobuf = m12_params_ori.SerializeToString()
        m12_params = self.get_m12_params(m12_params_protobuf, second_aes_key, second_aes_iv)
        print('m12_params:\n', m12_params)

        # nonce生成
        m12_nonce = self.get_m12_nonce()
        print('m12_nonce:\n', m12_nonce)

        # sign生成
        sign_ts = str(int(time.time() * 1000))
        # 验证时固定时间 todo
        sign_ts = '1752560312944'
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
