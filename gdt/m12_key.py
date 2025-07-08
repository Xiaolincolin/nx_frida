import base64
import os
from base64 import b64decode, b64encode
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_v1_5
from hexdump import hexdump


class M12:
    @staticmethod
    def get_rsa_key():
        # 公钥（Base64 编码）
        # 可能就是app的证书
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
    def get_key():
        random_bytes = os.urandom(32)  # 生成 32 字节的随机字节
        return random_bytes.hex()

    def test_key(self):
        # 明文（hex）
        plaintext_hex = self.get_key()
        plaintext = bytes.fromhex(plaintext_hex)

        rsa_key = self.get_rsa_key()
        ciphertext = self.encrypt_rsa(rsa_key, plaintext)
        print(b64encode(ciphertext).decode())


if __name__ == '__main__':
    M12().test_key()
