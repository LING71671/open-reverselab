# 在线验证系统分析与绕过

## 场景

APK 在启动时进行在线许可证验证（微验/频道验证/网络授权），未通过则闪退或锁功能。需要分析验证流程并绕过。

## 输入信号

- 应用启动后弹窗或闪退
- 抓包看到启动时向特定域名发 API 请求
- jadx 搜索 "verify"、"license"、"activate"、"check"
- native 中有 `httppost` / `curl_easy_perform` 调用

## 常见验证模式

### 模式 1: API 签名验证（微验）

```c
// 验证流程: 收集设备信息 → RC4 加密 → POST API → 解析响应
char *appkey = "YOUR_APPKEY_HERE";       // 应用密钥
char *rc4key = "YOUR_RC4_KEY_HERE";      // 加密密钥
char *host = "verify.example.com";       // 验证服务器

string verify() {
    int timestamp = time(NULL);
    // 签名: 时间戳 + appkey + 附加数据
    sprintf(payload, "%d%s%s", timestamp, appkey, extra);
    char *encrypted = Encrypt(payload, rc4key);  // RC4 加密
    
    // POST: api/?id=verify&app=12345&data=<encrypted>
    char *response = httppost(host, "api/?id=verify&app=12345", url_params);
    
    // 解密响应 → JSON 解析 → 检查 code 字段
    char *plain = Decrypt(response, rc4key);
    cJSON *json = cJSON_Parse(plain);
    int code = cJSON_GetObjectItem(json, "code")->valueint;
    return (code == 0) ? "ok" : "fail";
}
```

绕过点:
- 修改 hosts / DNS 劫持 verify.example.com → 自建验证服务器返回 `{"code":0}`
- Frida hook `httppost` 返回伪造响应
- Patch `appkey` + `rc4key` 为已知有效值

### 模式 2: Telegram 频道验证

```c
// 验证流程: 检测 Telegram 客户端 → 检查缓存文件 → 放行/跳转
int channel_verify() {
    // 1. 检查是否安装 Telegram
    char *tg_packages[] = {
        "org.telegram.messenger",
        "org.telegram.messenger.web",
        "tw.nekomimi.nekogram",
        // ... 8 个已知 TG 客户端包名
    };
    
    // 2. 检查频道缓存文件 (证明已加入频道)
    char *cache_files[] = {
        "cache/-6246562996528724687_99.jpg",  // 频道头像
        "cache/-6246854672052765681_97.jpg",
    };
    
    for (pkg in tg_packages) {
        if (package_installed(pkg)) {
            // 检测缓存文件
            char path[1024];
            sprintf(path, "/data/data/%s/%s", pkg, cache_file);
            if (access(path, F_OK) == 0) {
                return 1;  // 验证通过
            }
            // 未加入频道 → 自动跳转
            am_start(pkg, "https://t.me/joinchat/XXXXX");
        }
    }
    return 0;  // 验证失败
}
```

绕过点:
- 创建空缓存文件: `touch /data/data/org.telegram.messenger/cache/<channel_avatar_hash>.jpg`
- Frida hook `access` 返回 0（文件存在）
- Patch `checkFileExistence` 始终返回 1
- 直接 patch `频道验证()` 返回 1

### 模式 3: 网络连通性验证

```c
// 验证流程: curl_easy_perform 访问百度 → 检查连通性
int check_network() {
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, "http://www.baidu.com");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    return (res == CURLE_OK) ? 1 : 0;
}
```

## Frida 通用绕过模板

```javascript
// 1. Hook httppost (微验验证)
var httppost = Module.findExportByName(null, "httppost")
if (!httppost) {
    // 在 libmain.so 中搜索
    var mod = Process.findModuleByName("libmain.so")
    // 或枚举导出
    Module.enumerateExports("libmain.so").forEach(function(exp) {
        if (exp.name.indexOf("httppost") >= 0) httppost = exp.address
    })
}
Interceptor.attach(httppost, {
    onLeave: function(ret) {
        // 替换返回值为伪造的成功响应
        var fake = Memory.allocUtf8String('{"code":0,"msg":"ok"}')
        ret.replace(fake)
    }
})

// 2. Hook access (频道验证) 
var access = Module.findExportByName(null, "access")
Interceptor.attach(access, {
    onLeave: function(ret) {
        var path = Memory.readCString(this.context.x0 || this.context.rdi)
        if (path && path.indexOf("cache/") >= 0) {
            ret.replace(0)  // 伪造文件存在
        }
    }
})

// 3. Hook system (包名检查)
var system_ptr = Module.findExportByName(null, "system")
Interceptor.attach(system_ptr, {
    onEnter: function(args) {
        var cmd = Memory.readCString(args[0])
        if (cmd && cmd.indexOf("pm list packages") >= 0) {
            // 不执行, 直接返回
            args[0] = Memory.allocUtf8String("echo 'package:org.telegram.messenger'")
        }
    }
})
```

## 攻击链

```
启动闪退 → logcat 搜 error/verify/fail → jadx 定位验证类
→ 确认验证类型 (API/频道/网络) → Ghidra 分析 native 验证函数
→ Frida hook 验证函数入口 dump 参数 → 抓包确认 API 请求格式
→ 选择绕过方式: hook 返回/自建服务器/patch 二进制
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| Frida Hook 验证函数入口 + 签名校验 | `android_crypto_unpack_recipe` | Frida Hook 验证函数入口 + 签名校验 |
| 分析 native 验证函数 | `ghidra_headless_analyze` | 分析 native 验证函数 |
| 观察验证 HTTP 请求 | `android_http_observation_recipe` | 观察验证 HTTP 请求 |
