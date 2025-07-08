# -*- encoding: utf-8 -*-
# @ModuleName: jys
# @Function:
# @Author:
# @Time: 2025/6/24 16:07

import gzip
import io
import zlib


def decompress_bytes(gzipped_bytes):
    with gzip.GzipFile(fileobj=io.BytesIO(gzipped_bytes)) as f:
        return f.read()


def gzip_android_style(data: bytes) -> bytes:
    # deflate 数据（gzip压缩算法）
    compressed = zlib.compress(data)[2:-4]  # 去掉zlib头尾
    # 构造gzip header：1f 8b 08 00 00 00 00 00 00 00
    header = b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x00'
    # 构造gzip尾部：CRC32 + 输入长度（均为小端）
    crc32 = zlib.crc32(data) & 0xFFFFFFFF
    isize = len(data) & 0xFFFFFFFF
    trailer = crc32.to_bytes(4, 'little') + isize.to_bytes(4, 'little')
    return header + compressed + trailer


# 使用示例
hex_str = ' 1f8b08000000000000008d91cd6ec3201084dfc5e7d662c118e88d1fbb8f51b91827566de334491b29cabb77498d54f5d2debe1986d1c25e8bf5b3782a9862c543b1ee11255588c30e11107c442008c76983cbb8c1e8b7cc39c3d8e7f0bac1fa86e0e35c1e0e6528cfcb1897b20f73fcc6944c6d1268e31ce7b5b0dc81d3ce696b94239cd2e4a5eaee8839ca2a109ca559fd9fcdfebfd5fe77f7e9fe0c20206bd51acd8912b2a1b6b22d134283d4b5154630ab39080255dd568c4bc5b89512548d396e75d3981a1c31da02312d6b89e29209032df6c7d4ffa854fae8d777e45d8cbb29a09a0754cf59edd36a86a99bef47a11fbb977039a177bda59bc382c8ef1497fcf1735e4e76567fdca8cfab8ca9832284cb3afe9805e547379d43766e5f97c3e3da1e020000'
compressed_data = bytes.fromhex(hex_str)
decompressed = decompress_bytes(compressed_data)
print(decompressed.decode())

