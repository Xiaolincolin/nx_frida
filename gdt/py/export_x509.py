# -*- encoding: utf-8 -*-
# @ModuleName: export_x509
# @Function:
# @Author:
# @Time: 2025/7/18 10:15
import zipfile
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives import serialization


def java_string_hashcode(s: bytes) -> int:
    h = 0
    for b in s:
        h = (31 * h + b) & 0xFFFFFFFF  # 模拟 Java 的 int 溢出行为
    if h >= 0x80000000:  # 转为带符号
        h -= 0x100000000
    return h


def export_x509_certificate(apk_path):
    with zipfile.ZipFile(apk_path, "r") as apk:
        for name in apk.namelist():
            if name.startswith("META-INF/") and name.endswith(".RSA"):
                print(f"Found signature file: {name}")
                raw = apk.read(name)
                certs = pkcs7.load_der_pkcs7_certificates(raw)
                for idx, cert in enumerate(certs):
                    der_bytes = cert.public_bytes(encoding=serialization.Encoding.DER)
                    hex_string = der_bytes.hex()
                    print(f"\n--- Certificate {idx} hex---")
                    # 输出原始 hex，每行16字节
                    print(hex_string)
                    print('has_code: ', java_string_hashcode(der_bytes))


if __name__ == '__main__':
    path = "/Users/xuxiaolin/Desktop/gdt_android/gdt_demo.apk"
    export_x509_certificate(path)
