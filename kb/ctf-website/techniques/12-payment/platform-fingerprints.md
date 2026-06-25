# PHP 发卡/电商平台指纹库

> 从实战案例中积累的平台识别指纹。用于快速判断目标CMS，定向查找已知漏洞。

## 1. acg-faka (v3.4.x)

**案例**: beigpt, dimosky, tg5288

```
版本标记: v=3.4.8 / v=3.4.9 (URL query string)
前台路径: /user/authentication/login, /user/authentication/register
API路径:  /user/api/index/data, /user/api/index/commodity
          /user/api/index/valuation, /user/api/order/trade
          /user/api/index/query (IDOR关键!)
JS特征:   assets/common/js/ready.js (window._data_var, setVar, getVar)
          assets/common/js/_.js (jQuery 3.6.0 + util class)
          assets/user/js/_index.js (trade class)
框架:     layui
PHP版本:  8.x
支付插件: Epay(plugin/epay), Codepay, Kvmpay, 余额(pay_id=1)
插件路由: /plugin/{id}/
后台:     /admin/ (Cloudflare WAF保护)
安装:     /install/ (锁定后不可访问)
日志:     /runtime.log (可能泄露!)
```

### 已知漏洞模式
- `POST /user/api/index/query` 未认证IDOR暴订单+卡密
- Epay签名密钥在Config.php，无法远程读取
- 邮箱域名白名单（主流邮箱only）
- 余额支付直接返回secret（无需外部回调）

---

## 2. 独角数卡 (dujiaoka)

**案例**: 无直接案例，CTF常见

```
框架:     Laravel
前端:     layui / bootstrap / luna / hyper
路由:     RESTful API (/api/orders, /api/products)
支付:     Epay, Paypal, Stripe, 支付宝, 微信
特点:     Laravel框架，composer依赖，vendor目录
安装:     /install
后台:     /admin (laravel-admin)
GitHub:   assimon/dujiaoka (>7k stars)
```

---

## 3. Annie Mall (v1030)

**案例**: lo2o65

```
版本标记: v1030
关键路径: /ajax.php?act=query (IDOR!)
          /ajax.php?act=gettool (商品列表)
          /install/ (安装向导)
验证码:   极验(Geetest) - 公开订单
          数学验证码 - 供应商登录
```

### 已知漏洞模式
- `POST /ajax.php?act=query` type=qq → 返回全部订单+明文卡密
- `GET /ajax.php?act=gettool` → 返回所有商品

---

## 4. Xiangyun (XYCMS) V10.1

**案例**: ksjer

```
基础:     SeaCMS衍生
CMS标识:  Xiangyun Platform V10.1
框架:     PHP + MySQL
特点:     CDN/OSS架构, visitToken WAF
后台:     /admin (可识别CMS版本)
```

### 已知漏洞模式
- PHP数组参数注入绕过登录
- CAPTCHA验证可绕过

---

## 5. Emlog / Emlog Pro

**案例**: hanfolk-ai

```
CMS标识:  Emlog-style 1272
JS特征:   Layui 2.11.6, jQuery 3.5.1
服务器:   Nginx
CDN:      Cloudflare
支付:     Epay插件
```

---

## 6. 指纹速查表

| 特征 | acg-faka | dujiaoka | Annie Mall | XYCMS |
|------|----------|----------|------------|-------|
| URL版本标记 | `?v=3.4.x` | - | `v1030` | - |
| ready.js路径 | `/assets/common/js/ready.js` | - | - | - |
| jQuery封装 | `_.js` (jQ 3.6.0) | - | - | - |
| 前端框架 | layui | layui/bootstrap | - | - |
| API前缀 | `/user/api/` | `/api/` | `/ajax.php` | `/ajax/` |
| 关键IDOR端点 | `/user/api/index/query` | - | `/ajax.php?act=query` | - |
| 后台路径 | `/admin/` | `/admin/` | - | `/admin/` |
| 支付插件 | plugin/epay | plugin/epay | 内置 | - |
| PHP框架 | 自定义 | Laravel | 自定义 | SeaCMS |

## 7. 快速识别流程

```bash
# 1. 抓首页HTML
curl -s https://target | grep -E 'ready.js|_.js|layui|jquery|v=[0-9]'

# 2. 检查关键路径
curl -s -o /dev/null -w "%{http_code}" https://target/user/api/index/query
curl -s -o /dev/null -w "%{http_code}" https://target/ajax.php?act=query
curl -s -o /dev/null -w "%{http_code}" https://target/install/

# 3. 看HTTP头
curl -sI https://target | grep -iE 'server|x-powered-by|set-cookie'

# 4. 对照上表锁定平台 → 运行对应的 toolkit 脚本
```

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“响应差异”与服务端副作用分开记录；只有权限、状态、数据或 Flag 可重复变化才算确认。
- 从全新 session/重置状态最小化重放，记录依赖、并发参数、时间窗口及失败样本。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据只用 `REDACTED` 占位，自动检索 `flag{}`、`CTF{}`、`DASCTF{}`。

## MCP 工具映射

| 步骤 | MCP 工具 | 说明 |
|---|---|---|
| 运行时指纹与网络观察 | `jshook` | Hook 前端函数、XHR/fetch 与响应头 |
| 知识路由 | `kb_router` | 按平台、支付 SDK、框架版本选择技术文件 |
| 端点验证 | `http_probe` | 验证公开 API、版本头和状态码差异 |
