#!/usr/bin/env python3
"""
Shellcode 多层加密 — XOR / RC4 / 自定义 S-Box
输出 C 数组，可直接 #include 进 Loader。
"""
import sys
import os
import hashlib


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def rc4_encrypt(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    result = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)


def custom_sbox_encrypt(data: bytes, sbox: bytes) -> bytes:
    result = bytearray()
    for i, b in enumerate(data):
        result.append(sbox[b] ^ sbox[i % len(sbox)])
    return bytes(result)


def generate_sbox(seed: bytes) -> bytes:
    sbox = list(range(256))
    import random as _random
    _random.Random(hashlib.sha256(seed).digest()).shuffle(sbox)
    return bytes(sbox)


def to_c_array(data: bytes, name: str = "shellcode") -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        lines.append('    ' + ', '.join(f'0x{b:02x}' for b in chunk) + ',')
    body = '\n'.join(lines)
    return (
        f'// {len(data)} bytes\n'
        f'unsigned char {name}[] = {{\n{body}\n}};\n'
        f'unsigned int {name}_len = {len(data)};\n'
    )


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <shellcode.bin> [key] [--layers xor,rc4,sbox]")
        sys.exit(1)

    in_file = sys.argv[1]
    key_str = sys.argv[2] if len(sys.argv) > 2 else os.urandom(16).hex()
    layers_str = 'xor,rc4'
    if '--layers' in sys.argv:
        idx = sys.argv.index('--layers')
        layers_str = sys.argv[idx + 1]

    key = key_str.encode() if not all(c in '0123456789abcdef' for c in key_str) else bytes.fromhex(key_str)
    layers = [l.strip() for l in layers_str.split(',')]

    with open(in_file, 'rb') as f:
        data = f.read()

    print(f"[*] Input:  {len(data)} bytes")
    print(f"[*] Key:    {key.hex() if isinstance(key, bytes) else key}")
    print(f"[*] Layers: {', '.join(layers)}")

    for layer in layers:
        if layer == 'xor':
            data = xor_encrypt(data, key)
            print(f"    XOR   → {len(data)} bytes")
        elif layer == 'rc4':
            data = rc4_encrypt(data, key)
            print(f"    RC4   → {len(data)} bytes")
        elif layer == 'sbox':
            sbox = generate_sbox(key)
            data = custom_sbox_encrypt(data, sbox)
            sbox_file = in_file.replace('.bin', '_sbox.bin')
            with open(sbox_file, 'wb') as f:
                f.write(sbox)
            print(f"    S-Box → {len(data)} bytes (sbox → {sbox_file})")
        else:
            print(f"    Unknown: {layer}")

    base = in_file.replace('.bin', '')
    with open(f'{base}_encrypted.c', 'w') as f:
        f.write(to_c_array(data, 'encrypted_shellcode'))
    with open(f'{base}_key.c', 'w') as f:
        f.write(to_c_array(key, 'decrypt_key'))
    print(f"[+] {base}_encrypted.c + {base}_key.c")


if __name__ == '__main__':
    main()
