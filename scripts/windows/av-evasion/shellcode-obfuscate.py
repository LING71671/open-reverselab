#!/usr/bin/env python3
"""
Shellcode 混淆 — 伪装成 UUID / IPv4 / IPv6 / MAC 地址数组。
"""
import sys
import uuid
import ipaddress


def to_uuid_array(data: bytes) -> list[str]:
    uuids = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        if len(chunk) < 16:
            chunk += b'\x00' * (16 - len(chunk))
        uuids.append(str(uuid.UUID(bytes_le=chunk)))
    return uuids


def to_ipv4_array(data: bytes) -> list[str]:
    ips = []
    for i in range(0, len(data), 4):
        chunk = data[i:i + 4]
        if len(chunk) < 4:
            chunk += b'\x00' * (4 - len(chunk))
        ips.append(str(ipaddress.IPv4Address(chunk)))
    return ips


def to_ipv6_array(data: bytes) -> list[str]:
    ips = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        if len(chunk) < 16:
            chunk += b'\x00' * (16 - len(chunk))
        ips.append(str(ipaddress.IPv6Address(chunk)))
    return ips


def to_mac_array(data: bytes) -> list[str]:
    macs = []
    for i in range(0, len(data), 6):
        chunk = data[i:i + 6]
        if len(chunk) < 6:
            chunk += b'\x00' * (6 - len(chunk))
        macs.append(':'.join(f'{b:02x}' for b in chunk).upper())
    return macs


FORMATS = {
    'uuid': to_uuid_array,
    'ipv4': to_ipv4_array,
    'ipv6': to_ipv6_array,
    'mac': to_mac_array,
}


def to_c_array(items: list[str], name: str = "obfuscated") -> str:
    body = '\n'.join(f'    "{item}",' for item in items)
    return (
        f'// {len(items)} items\n'
        f'char* {name}[] = {{\n{body}\n}};\n'
        f'unsigned int {name}_count = {len(items)};\n'
    )


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <shellcode.bin> [format=uuid|ipv4|ipv6|mac|combo]")
        sys.exit(1)

    in_file = sys.argv[1]
    fmt = sys.argv[2] if len(sys.argv) > 2 else 'uuid'

    with open(in_file, 'rb') as f:
        data = f.read()

    print(f"[*] Input:  {len(data)} bytes")
    print(f"[*] Format: {fmt}")

    if fmt == 'combo':
        import random
        combiners = {'uuid': (to_uuid_array, 16), 'ipv4': (to_ipv4_array, 4), 'mac': (to_mac_array, 6)}
        all_items = []
        pos = 0
        while pos < len(data):
            choice = random.choice(list(combiners.keys()))
            fn, size = combiners[choice]
            chunk = data[pos:pos + size]
            if len(chunk) < size:
                chunk += b'\x00' * (size - len(chunk))
            all_items.extend(fn(chunk))
            pos += size
        items = all_items
    else:
        fn = FORMATS.get(fmt, FORMATS['uuid'])
        items = fn(data)

    c_code = to_c_array(items, f'payload_{fmt}')
    out_file = in_file.replace('.bin', f'_obfuscated_{fmt}.c')
    with open(out_file, 'w') as f:
        f.write(c_code)
    print(f"[+] {out_file}")


if __name__ == '__main__':
    main()
