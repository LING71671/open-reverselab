# 游戏协议 Hook 与封包分析

## 场景

游戏使用自定义协议（Protobuf/FlatBuffers/私有二进制），需要 Hook 网络栈抓取请求/响应明文，或分析协议结构。

## 输入信号

- Wireshark/tcpdump 抓到 TCP/UDP 流非标准格式
- 应用使用了 OkHttp/Retrofit/自定义 Socket
- 数据经加密后发送，需在加密前/解密后下钩子
- 端口/封包层需要改造流量

## Java 层 HTTP Hook

### OkHttp (最常用)

```javascript
Java.perform(function() {
    // Hook OkHttp3 请求构造
    var Request = Java.use("okhttp3.Request")
    var RequestBody = Java.use("okhttp3.RequestBody")
    var HttpUrl = Java.use("okhttp3.HttpUrl")

    // Hook Call.execute (同步)
    var RealCall = Java.use("okhttp3.RealCall")
    RealCall.execute.implementation = function() {
        var req = this.request()
        var url = req.url().toString()
        console.log("[OkHttp] " + req.method() + " " + url)
        // headers
        var headers = req.headers()
        for (var i = 0; i < headers.size(); i++)
            console.log("  Header: " + headers.name(i) + "=" + headers.value(i))
        var resp = this.execute()
        console.log("[OkHttp] response code:", resp.code())
        return resp
    }

    // Hook Call.enqueue (异步) - 必需覆盖
    RealCall.enqueue.implementation = function(callback) {
        var req = this.request()
        console.log("[OkHttp ASYNC]", req.method(), req.url().toString())
        return this.enqueue(callback)
    }
})
```

### Retrofit 响应体抓取

```javascript
// Retrofit 底层也是 OkHttp, 加一个 ResponseBody Hook
var ResponseBody = Java.use("okhttp3.ResponseBody")
ResponseBody.string.implementation = function() {
    var body = this.string()
    console.log("[OkHttp Body]", body.substring(0, 500))
    return body
}
```

## Native 层 Socket Hook

```c
// 游戏常用 native socket 直接发包, 绕过 Java 层
// Frida 模板: hook send/sendto/recv/recvfrom
var sendto = Module.findExportByName("libc.so", "sendto")
Interceptor.attach(sendto, {
    onEnter: function(args) {
        var sockfd = args[0].toInt32()
        var buf = args[1]
        var len = args[2].toInt32()
        var flags = args[3].toInt32()
        var dest_addr = args[4]

        if (len > 4 && len < 4096) {  // 过滤噪声
            console.log("[sendto] fd=" + sockfd + " len=" + len)
            console.log(hexdump(buf, {length: Math.min(len, 256)}))
        }
    }
})

var recvfrom = Module.findExportByName("libc.so", "recvfrom")
Interceptor.attach(recvfrom, {
    onEnter: function(args) { this.buf = args[1]; this.len = args[2] },
    onLeave: function(ret) {
        if (ret.toInt32() > 0) {
            console.log("[recvfrom] len=" + ret.toInt32())
            console.log(hexdump(this.buf, {length: Math.min(ret.toInt32(), 256)}))
        }
    }
})
```

## 端口/封包转发

```bash
# 实战: redsocks + iptables 将指定流量转发到代理
# 1. 安装 redsocks
# 2. 配置 /etc/redsocks.conf 转发到 Burp/Charles
# 3. iptables 规则: 将 APP UID 的流量 DNAT 到 redsocks

# 或使用 ProxyDroid / Postern (Android 侧)
# 配合 Drony / SocksDroid 做全局或分应用代理
```

## Protobuf 协议逆向

```python
# 拿到封包二进制后的解析
# 方法1: 有 .proto 定义 → protoc 直接解析
# 方法2: 无 .proto → 用 protobuf-inspector 推断结构

# 安装: pip install protobuf-inspector
# 使用: protobuf_inspector < captured.bin
# 输出: 字段号、wire_type、值猜测
```

```bash
# protoc 命令行解码 (有 .proto 时)
cat captured_hex.bin | xxd -r -p > raw.bin
protoc --decode_raw < raw.bin          # 无 schema 尝试
protoc --decode=GameMsg msg.proto < raw.bin  # 有 schema
```

## 工具映射

```
tcpdump/Wireshark → 抓原始流
Frida + OkHttp Hook → Java 层明文
Frida + native socket Hook → Native 层明文
redsocks/iptables → 流量重定向
Burp/Charles → HTTP/HTTPS 代理审计
protobuf-inspector → 未知 Protobuf 推断
```

## 实战案例: 延迟发包绕过

```
已知: 封包包含时间戳签名, 有效期 5 秒
绕过: Hook sendto → 缓存封包 → 修改时间戳 → 延迟 4.9 秒再发送 → 复用有效封包
检测: 服务器侧非单调递增 nonce 检查
```

## 攻击链

```
确认通信方式 (HTTP/Socket/WebSocket) → 确定加密层次
→ Java: Hook OkHttp/Retrofit → Native: Hook socket send/recv
→ 非 HTTP: tcpdump + 逆向 socket 创建点 → 定位发包函数 → Frida hook
→ 拿明文: 确认序列化格式 (JSON/PB/FlatBuffers) → 解析协议字段
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| Frida Hook OkHttp/Retrofit + logcat HTTP 证据汇总 | `android_http_observation_recipe` | Frida Hook OkHttp/Retrofit + logcat HTTP 证据汇总 |
| 如协议层有加密，抓 Cipher key/iv | `android_crypto_unpack_recipe` | 如协议层有加密，抓 Cipher key/iv |

## 证据与验证闭环

- 记录 APK/SO 的 SHA256、包名、版本、ABI、设备/Android/Frida 版本及原始样本路径。
- 静态结论必须绑定类名、方法签名、RVA/文件偏移、字符串或 Xref；动态结论绑定 hook 点、参数、返回值和时间戳。
- 在未修改样本与实验副本上分别复现，保存 Frida 日志、dump 哈希和重放脚本到 `exports/android/`。
- Patch/重打包必须记录原始字节、修改字节、签名方式和安装启动结果，不能以“构建成功”代替行为验证。
