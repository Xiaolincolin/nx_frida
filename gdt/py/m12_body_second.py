# -*- encoding: utf-8 -*-
# @ModuleName: m12_params
# @Function:
# @Author:
# @Time: 2025/7/2 14:12
import base64
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
from gdt.py.modify_sha256 import modify_sha256


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
    def create_params(check_b64, params_begin):
        m12_params = params_pb2.M12Params()
        app_info = params_pb2.AppInfo()
        device_info = params_pb2.DeviceInfo()
        default_info = params_pb2.DefaultInfo()

        # 组装app_info
        qm_uin = params_begin.get('qm_uin', '')
        app_info.flag = 1
        app_info.ts_nonce = qm_uin
        app_info.status = 0
        app_info.unknow_1 = params_begin.get('app_key', '')
        app_info.js_version = params_begin.get('js_version', '')
        app_info.sdk_version = params_begin.get('sdk_version', '')
        app_info.os_version = params_begin.get('os_version', '')
        app_info.model = params_begin.get('model', '')
        app_info.default_info_1.CopyFrom(default_info)
        app_info.default_info_2.CopyFrom(default_info)
        app_info.package_name = params_begin.get('package_name', '')
        app_info.network = params_begin.get('network', '')
        app_info.network_type = params_begin.get('network_type', 0)
        # 组装device_info
        device_info.default_info_3.CopyFrom(default_info)
        device_info.unknow_2 = params_begin.get('unknow_2', '')
        device_info.qm_uin = '{"QmUin":"%s"}' % qm_uin
        device_info.brand = params_begin.get('brand', '')
        device_info.k_list = params_begin.get('k_list_str', '')
        device_info.default_info_4.CopyFrom(default_info)
        device_info.unknow_3 = params_begin.get('params_sign', '')
        device_info.default_info_5.CopyFrom(default_info)
        device_info.default_info_6.CopyFrom(default_info)
        device_info.default_info_7.CopyFrom(default_info)
        device_info.default_info_8.CopyFrom(default_info)
        device_info.system_info = params_begin.get('system_info', '')
        device_info.default_info_9.CopyFrom(default_info)
        device_info.platform = "Phone"
        device_info.ts = params_begin.get('d_ts', '')
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
    def get_check_info(params_begin):
        check_info_ori = {
            "0": params_begin.get('chck_ts', ''),
            "10": 0,
            "11": 0,
            "12": 0,
            "13": "",
            "15": 1,
            "16": 0,
            "17": params_begin.get('x509_hash', 0),
            "18": "guocao.tencent",
            "2": [{
                "2.1": ":\/memfd:frida-agent-64.so",
                "2.2": 0
            }],
            "20": 3,
            "21": 2,
            "22": params_begin.get('abi', ''),
            "23": [],
            "25": 1
        }
        return json.dumps(check_info_ori, separators=(',', ':')).replace('\\', '').replace('/', '\/').encode()

    @staticmethod
    def get_k_list_str():
        k_dict = {
            'k1': '2025-06-06173101.558333356+0800',
            'k2': '2025-06-06173128.228336013+0800',
            'k3': '0000000000000000',
            'k4': '8a196b9a3e36b6db',
            'k5': '13106683',
            'k6': '12786688',
            'k7': '215040',
            'k8': '2800',
            'k9': '189ca9e5-059c-4e76-afad-42be5509ba28',
            'k11': '171',
            'k12': '4',
            'k13': '2025-06-06173128.228336013+0800',
            'k14': '2025-06-26153944.322408685+0800',
            'k15': '2954',
            'k16': '16',
            'k17': '2025-07-23142407.348131734+0800',
            'k18': '2025-07-23142407.348131734+0800',
            'k19': '914397',
            'k20': '4',
            'k21': '2025-07-23142407.348131734+0800',
            'k22': '2025-07-23142407.348131734+0800',
            'k23': '914398',
            'k24': '2',
            'k25': '2025-07-23141949.838106081+0800',
            'k26': '1970-02-26064343.743333955+0800',
            'k27': '22982',
            'k28': '15',
            'k29': '',
            'k30': '',
            'k31': '',
            'k32': '',
            'k33': '2025-06-06173128.785002735+0800',
            'k34': '2025-07-23113020.897093066+0800',
            'k35': '3773',
            'k36': '20',
            'k37': '2025-06-06173128.785002735+0800',
            'k38': '2025-06-06173128.785002735+0800',
            'k39': '3772',
            'k40': '5',
            'k41': '',
            'k42': '',
            'k43': '',
            'k44': '',
            'k45': '2025-06-06173123.808335573+0800',
            'k46': '2604',
            'k47': '2025-06-06173101.478333348+0800',
            'k48': '2025-06-06173103.768333576+0800',
            'k49': '2025-06-06173123.865002245+0800',
            'k50': '2606',
            'k51': '',
            'k52': '',
            'k53': '',
            'k54': '2025-06-06173101.478333348+0800',
            'k55': '99',
            'k56': '2593',
            'k57': '2605',
            'k58': '2025-06-06173113.881667917+0800',
            'k59': '2025-06-06173113.881667917+0800',
            'k60': '1990',
            'k61': '5582',
            'k62': '2025-06-06173124.188335610+0800',
            'k63': '2627',
            'k64': '2025-06-06173123.511668876+0800',
            'k65': '2599',
            'k66': '171',
            'k67': '2025-06-06173106.721667204+0800',
            'k68': '382',
            'k69': '',
            'k70': '113',
            'k71': '2025-06-06173101.478333348+0800',
            'k72': '114',
            'k73': '2025-06-06173101.481666682+0800',
            'k74': '2025-06-06173106.821667214+0800',
            'k75': '',
            'k10': '1',
        }
        k_list_str = ''
        for k, v in k_dict.items():
            k_list_str += f'{k}:{v};'
        k_list_str = k_list_str[:-1]
        return k_list_str

    def get_system_info(self, params_begin):
        android_id = params_begin.get('android_id', '') or ''
        model = params_begin.get('model', '') or ''

        # 固定key,iv
        key = 'lvcwmSYVr2Axv1gn'
        iv = 'Zs0ntDqG2jyhKN0c'
        oz_bytes = self.aes_encrypt(android_id.encode(), key.encode(), iv.encode())
        oz = base64.b64encode(oz_bytes).decode()

        oo_bytes = self.aes_encrypt(model.encode(), key.encode(), iv.encode())
        oo = base64.b64encode(oo_bytes).decode()
        system_info = {
            "harmony": "0",
            "clone": "0",
            "containe": "",
            "oz": oz,
            "oz2": "",
            "oo": oo,
            "kelong": "0",
            "ip": params_begin.get('ip', ''),
            "multiUser": "0",
            "bod": params_begin.get('bod', ''),
            "brd": params_begin.get('brand', ''),
            "dv": params_begin.get('bod', ''),
            "firstLevel": params_begin.get('first_level', ''),
            "manufact": params_begin.get('manufact', ''),
            "name": params_begin.get('bod', ''),
            "host": params_begin.get('host', ''),
            "kernel": params_begin.get('kernel', ''),
            "pre": "0",
            "av": params_begin.get('sdk_version', ''),
            "ch": "",
            "svr": "",
            "fit": params_begin.get('fit', ''),
            "jv": params_begin.get('js_version', ''),
        }
        system_info_str = json.dumps(system_info, separators=(',', ':')).replace('/', '\/')
        return system_info_str

    @staticmethod
    def get_2_7_sign(params_begin):
        data_2_5 = params_begin.get('k_list_str', '')
        data_1_7 = params_begin.get('os_version', '')
        data_1_8 = params_begin.get('model', '')
        data_1_4 = params_begin.get('app_key', '')
        data_1_5 = params_begin.get('js_version', '')
        data_1_6 = params_begin.get('sdk_version', '')
        str_join = f'{data_2_5}{data_1_7}{data_1_8}{data_1_4}{data_1_5}{data_1_6}'
        even_chars = str_join[::2]
        even_chars = f'pzotrcm869{even_chars}'
        odd_chars = str_join[1::2]
        odd_chars = f'{odd_chars}pzotrcm869'
        index_sha_256_hex = modify_sha256(even_chars)
        value_sha_256_hex = modify_sha256(odd_chars)
        index_sha_256_bytes = bytes.fromhex(index_sha_256_hex)
        value_sha_256_bytes = bytes.fromhex(value_sha_256_hex)
        m12_2_7 = ''
        for item in index_sha_256_bytes:
            index = item & 0x1f
            value_bytes = value_sha_256_bytes[index]
            value = f"{value_bytes:02x}"
            m12_2_7 += value
        return m12_2_7

    def get_qm_uin(self):
        random_bytes = self.get_key()
        qm = int(time.time() * 1000)
        uin = random_bytes[0:16]
        return f'{qm}{uin}'

    @staticmethod
    def get_extra(params_begin):
        extra = {
            "appKey": params_begin.get('app_key', ''),
            "crypt": params_begin.get('crypt', ''),
        }
        return json.dumps(extra, separators=(',', ':'))

    def main(self, params_begin):
        params_begin['k_list_str'] = self.get_k_list_str()
        params_begin['system_info'] = self.get_system_info(params_begin)
        params_begin['params_sign'] = self.get_2_7_sign(params_begin)
        qm_uin_test = params_begin.get('qm_uin', '')  # 测试固定
        params_begin['qm_uin'] = qm_uin_test or self.get_qm_uin()

        m12_crypt = params_begin.get('crypt', '')  # 前两次是1，后1次是2
        # key计算
        m12_key, m12_key_ori = self.get_m12_key()
        second_aes_key = bytes.fromhex(m12_key_ori[0:32])
        second_aes_iv = bytes.fromhex(m12_key_ori[32:])
        # 验证时固定 todo
        second_aes_key = bytes.fromhex("5a930429773eed7f174388a91f2c51c3")
        second_aes_iv = bytes.fromhex("dcbefaac56fbabb5e59712066954fc15")
        # 验证时固定 todo
        print('key:\n', m12_key)

        # params计算
        check_info = self.get_check_info(params_begin)
        check_aes_key = bytes.fromhex("65626165636665346665343863393235")
        check_aes_iv = bytes.fromhex("62626633353932366533333231303632")
        check_bytes = self.aes_encrypt(check_info, check_aes_key, check_aes_iv)
        check_b64 = b64encode(check_bytes).decode()
        print('check_b64:\n', check_b64)

        m12_params_ori = self.create_params(check_b64, params_begin)
        m12_params_protobuf = m12_params_ori.SerializeToString()
        m12_params = self.get_m12_params(m12_params_protobuf, second_aes_key, second_aes_iv)
        print('m12_params:\n', m12_params)

        # nonce生成
        m12_nonce = self.get_m12_nonce()
        print('m12_nonce:\n', m12_nonce)

        # sign生成
        sign_ts = params_begin.get('sign_ts', '')

        # 都和params有关
        m12_ts = params_begin.get('params_time', '')

        m12_sign = self.get_m12_sign(m12_crypt, sign_ts, m12_key, m12_ts, m12_params, m12_nonce)
        print('m12_sign:\n', m12_sign)
        m12_data = {
            "crypt": m12_crypt,
            "extra": self.get_extra(params_begin),
            "key": m12_key,
            "nonce": m12_nonce,
            "params": m12_params,
            "sign": m12_sign,
            "time": m12_ts
        }
        print('m12_data:\n', m12_data)
        return m12_data

    @staticmethod
    def test():
        data = {
            "crypt": "1",
            "extra": "",
            "key": "TTKvPNbUq4SELQBGJwwFFNIiLGAXFPqnDIxlh9vM7jcfTevfDMMx0rcSIdpsLS1Acbq5PIlAAkzzIIcyyWB1IUXGS27f7fP1z1nq0Yc4bdoj9q1n8jVjfY\/UYW0hgDfY569CG9W0L1edoXEEZztA0IqbErvMI5B8XHHCUxLZoT4ubjVjIGSzNMtmx6Vrj07xQzd+EP73gm1ukTTMv1kELM52iYphFm2luuLzFZxS7Imyv55+HjNZzMUCrg7hA2ZKjCqb+4y0aughqb8jcEDJnpBG5YQKpZyL7m4jweVH4SLdOmJ+Q7rDuZLgDNHlTI5gE80j+wLFs8ta8vXYlSLUcg==",
            "nonce": "33f6a8ec5faa6e58",
            "params": "f3XoLOXOP1oQ95GEYAKrwAsNJsX4equRWOD6cTWbmbutqNc0nvA\/kcoMUDoMfcupeS94LGkp8roX8qNI5+IeLl682L4bPlGMFpRQdbRIcHuhnrobjKA30XbIEzFYmImJa1OTuQPCHlLCmfVY+yBaa5sPtDX4xDIWmMmi3vra\/8ufCLmAYK\/4Okd+IfcgDKuzNd2dr1bASd0ZXP3\/OjV2ypvhX9Dpdh13\/4GujKaPbkObfcSRAAkmek\/MJCn2fRN008XjhwOz\/w0+VjzhdVGiDdlgBCEV4khVXiaAzuhrniyt\/0B49x4CDEePG7ywPo3Xnby8SOH+QfIpI0Pd557NNawrt6aqlTyGVR7UZQkjXAxbazWM1Tt7y6crMYXz0TIrWpczYgpAgSQuasWAmPwieKnjsfwSvX6Ei43ZaAbcW\/cwal2Sb9Eja0ES7P6lPcE\/3k5A79JkTVNUfqctdnbT5fd998wcdzrJCu\/BorzNmG25aNL72B3dthhdmu15\/OMjwiFGl3r8XTwNryCQqfgvnGNxrA9CBYv5sRsjlyrdNv4LA89oY9vq1yfnbJCuOeoi5dAwUlGwNewPEDyCx8dXTPRiWA9ycRCHggwzmL7sqH0lP5HPY3DIlY8q3Txk2bZRzEFNTfnUe5HkNcVL1HFqIKYLIkuDavrqYSqFV2gnNoRO7Y4su3CUWOnaINZ62sjYTLXJwwMhGV0dIUTGX0J9kawDk3dpOkJzp5HvjrkL\/UF0fDnXE4Z2rWBbALl7Ne90DAPOS\/EZXkrIpOlOdifc2k7v8LOdXF0kD8yn2DMjeLhE9wiuJM2hEFXgOw78G25\/dIkQM0z+bIFdwEFotfTuY5aa7ZmRubPbWAKbgmYAwSap1MPoDNSHT3sbD9PgY0vNndacTviRjhcmVOPyo98uL8bXzBsbruzkLA6I\/KzBar4ckSlzh7G0A7VsZfY\/Vud\/81F7yBOQYdPpCkwErAaKqUtDVXIk7KXMCjzrUFW6gC7LxuFZgPxCbEXMBWqFPiJ3O9AUd36TCRlKNQENFMkXiAssiZZsMn\/gj87rNL5fULAEttKc5\/Vg0NHRNz0lzGmKZH37iYLul1F\/JTST3oVD4UEob5\/TYDzRQSk3VyzE14XRLQEHYVupPX55shft97Dh4TymjaRHTNEx7oNMrFUe\/wLtS1zJTqpoc1\/qm9XpkrNmLZPu+Jb5S2jsHGuOSwimAe3qLm+4OAGUBZhAq\/uctOHmX0kUyg90zVU82nsZFYK3BQlt+xKJG5E56eqWUvL1KVY7omVMe0skzpdY7XrxXiI6axU\/sFUcbvM5cFoUrFkSJSTIXoA37zTTCBSMu4N9huAERX9wJBnnT+R4hgONaYAWb5QqOHTctTebTD0oJctVcDDFeZBbFIUvUVPDO2RiKVLYUlg\/m7kT\/optaG8iwS3mRri1fHJQUm0U6hIf3BLRL0+0PC2dGUBgQPSEtq3K46\/DTxtig7G7r6O17Y5ikaOsXx9\/dtlvGZPjSCXJeDh7kQaa1uVlVG6j2cBGcZK7vfW2i2I4e\/ymqq\/wEc66wAMWrBdTOPUr6VEADzMvFQOLUi7UgTVxX\/vYlGvle90jZnTT8QWOlQHw1aCYKw0j3tjfiHRlxV0arT7CKp4XStQwAggepbZF6iPTC7d9qTGZe+q+rbseIDr9Ysk\/7PHUcwOpgf1Ca\/T+V5A6LYHRxlr06zhfd\/xIOyspv56XLkXzdRT53WQUPHwSABq8bg50M544GzPKOoFNZ9IuI7aIV66qmDxgzJJk5aKCSAWV2VIKF7umvSLa5Ig0FIC+\/HFz8NyQkqZBakA\/7K08R9G6KSWmhztRwUF6YoVFduPJSgpkFwRECJNf\/7YTzH3j7MDFYjrNvTgEVS4G8kRCtwdSWMyrb0gvWWjNE5vm9oOBE35nm20wKCLGD0pHUMxyNn3qm\/\/0UgbAplZshdNTFjQn0SsP48GH0NBIWBPKFCa8l2OckFqFb96mkKM5B\/UGx7WWPZMKTJLcyZasZuClprXS4DHiUORpuJqH\/YfJRuWYSFDm3hgaju\/sEkTtkU1As85np030nr\/+5z7QPBY03TOqkxgpgPIX\/peoniIk2pGyYyj73ER77Z68\/22cPznvzf5+Ag1IQWo5fyrhqCggInumhk0g59RFKFjN4qbTobh93G+hi1C59RvH9Dcb8Y6kc6TpG0sShyPmvEZETm+XRlDPBFHthij+4IbbSCCSvzoJjsNNshOWl9tlyLbd0yUIlYp+UMBV7JgDuW5sWYJW2h+i97Ozfq3GhdvsyQ3xdoxSO9BE7COWZv0Z70tVfXJivH71BTqGBROBkTnszUyf9TbsLYAogn1fOnLCtYqxqz4sqj0Vx4Ye8xSMu9L4iB3ZkBGac1nS9KfuOxWUESnP+uNtWOt5UBwsRTlcgj4zVhfyTnmwclCe0+VqwyaxEF2uiE8p1FlCbh5UQB23GLX6oEiBPV19EHUF5UTTOmNqsx1nhPyPkk1xy9aZaPeKthLnmZTNfnb4Q0Oao1uxa1MZkqRbls2wt\/x5j5EyLMXkTc9BGvUQh6zprPVhpnaW6XhvV7RTatqD+Ax0+wj5ZKoA9BAY42E4YZksFvfVHwSTK4CGV7r5yBZu44XDU44F0CTEeHveqqszKEXQC6xz4E439YtaUBN9MwRcIeAJ1eJk+14SYeYwH2JDVunYO326RqVKIqxCncbufgw6r2DeAKSvXEJsDnuO8At2BnN0SObMoOSkOG\/iQYX1E2BJTTbonuWanORy\/zgkq\/7yzJ1JylKNpWrnSZW7nnnm75xrf\/zoimsQzUOXTMpKqUyZFOwGUjpU8GBZ+cd024VRKhgLBwLLrWGMKz7YVTA+duVvJ40XLCWyyZ0tW5d5pQWp4gk5r5AbLjzLy0XTmdGoyMC2e\/RGHtA\/gW7K1u0v1mGncBtbEKFlqEhKGigh8SYJ4b\/fgqbDy6nxGEdqpAoyaapXKxiNshGp\/eIGeiZDbA6Ax8R0PT9jhpC8HiYOKpTPWFS+TkHnzM+2flX8cwGgMkcZzlwqmwv1zmNWAkJnvXpNy890C\/m358RWnwOpxu2kqDwlMCiPwUtftGaZVxYQHu1wd3vUTjqdjlayPRWj0YKx9UdNihqalwr4Wk8skCxkbCHNsbfe9Ngr0OFNbJB2Ea3MpUHgmWZy2lJa6vbHE1W\/vzFMcKrdZq1sCZRs2xiQ1gEFeGwN9XukbhRh7M2arRHfSEHxIqFdE1Pms210NpuJvNcps4H14KnQ1HoGE1CS4BMyQmcfDaCwtnW1LSWPTj72G+Tjj8BYIi2Fhp4k97hqjrbLtW0kwz2GV95tXrSHwF8xSyZZgH5Gbg==",
            "sign": "4c4385102ece35f426b626981c0852bf71759c75e4b1f41e52c40000000000000000",
            "time": "1753251849892"
        }
        return data

    def run(self):
        params_begin = {
            "crypt": "1",
            "fit": 1749609461905,
            "first_level": "29",
            "kernel": "Linux localhost 4.14.261-gdbc92b7a2b83-ab8577204 #1 SMP PREEMPT Thu May 12 09:07:20 UTC 2022 aarch64",
            "bod": "flame",
            "host": "abfarm848",
            "ip": "192.168.100.116",
            'android_id': 'b1349b36b6571cb0',
            'unknow_2': '35',
            'qm_uin': '1753251848782b9c968966a8cdcf7',  # 上线删除，测试固定
            'app_key': '0AND05YQXE52BNH0',
            'js_version': '2.1.2.17',
            'sdk_version': '4.640.1510.219',
            'os_version': 'Android 12,level 32',
            'brand': 'google',
            "manufact": "Google",
            'model': 'Pixel 4',
            'package_name': 'com.qq.e.union.demo.union',
            'network': 'wifi',
            'network_type': 3,
            'd_ts': '1753063271',
            'chck_ts': 1753251849,
            'sign_ts': '1753251849910',
            'params_time': '1753251849892',
            'x509_hash': 642918629,
            'abi': 'arm64-v8a',
        }
        self.main(params_begin)


if __name__ == '__main__':
    M12Params().run()
