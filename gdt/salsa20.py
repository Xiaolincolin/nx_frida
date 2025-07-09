# -*- encoding: utf-8 -*-
# @ModuleName: salsa20
# @Function:
# @Author:
# @Time: 2025/7/9 14:08
from Crypto.Cipher import Salsa20

key = bytes.fromhex("8a3632ed00000000000000000000000000000000000000000000000000000000")
nonce = bytes.fromhex("65a4e57fef44a2a3")
cipher = Salsa20.new(key=key, nonce=nonce)
keystream = cipher.encrypt(b"\x00" * 64)

print("[*] Python Keystream Block:")
for i in range(0, len(keystream), 16):
    chunk = keystream[i:i+16]
    hex_bytes = ' '.join(f"{b:02x}" for b in chunk)
    ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
    print(f"{i:08X}  {hex_bytes:<47}  {ascii_str}")
