---
id: "ctf-website/06-file-attacks/file-upload-xxe-lfi-defense"
title: "文件上传隔离、XXE 禁用与路径穿越防御"
title_en: "File Upload Sandboxing, XXE Disabling & Path Traversal Defense"
summary: >
  防御文件上传扩展名/MIME/Polyglot/.htaccess 绕过、Zip Slip 与 Central Directory 错位、XML/SVG/Office 外部实体注入 (XXE) 及 LFI/路径穿越攻击，落地随机化对象存储、图片重编码、安全 XML 解析器配置、Zip 安全解压与规范化路径基准约束。
summary_en: >
  Comprehensive defense against file upload bypasses (.htaccess, double extensions, polyglots), Zip Slip and header mismatches, XXE across XML/SVG/Office parsers, and LFI/path traversal. Enforces randomized object-storage isolation, image re-encoding, hardened XML parser flags, safe archive extraction, and canonical base-directory confinement.
board: "ctf-website"
category: "06-file-attacks"
signals: ["file upload", "XXE", "LFI", "path traversal", "Zip Slip", "文件上传防御", "XXE防御", "路径穿越防御"]
mcp_tools: ["kb_router", "kb_read_file", "kb_catalog"]
keywords: ["文件上传安全", "XXE禁用", "路径穿越防御", "Zip Slip防御", "图片重编码", "defusedxml", "realpath校验", "blue-team"]
difficulty: "advanced"
tags: ["defense", "blue-team", "file-upload", "xxe", "lfi", "path-traversal", "web-security"]
language: "zh-CN"
last_updated: "2026-11-12"
related_articles: ["ctf-website/06-file-attacks/file-upload-xxe-lfi", "ctf-website/04-ssrf/ssrf-defense"]
track: "blue"
defends: "ctf-website/06-file-attacks/file-upload-xxe-lfi"
---
# 文件上传隔离、XXE 禁用与路径穿越防御

## 防御目标与威胁面

文件处理链路横跨上传保存、压缩包解包、XML/SVG/DOCX 解析与下载包含四个高危运行时环节：

1. **文件上传绕过**：仅校验前端 `Content-Type` 或黑名单扩展名，易被双写后缀（`a.php.jpg`）、分号/空字节/尾部空格（`a.asp;.jpg`、`a.php.`）、`.htaccess` 覆盖 Apache 执行规则及 EXIF/IDAT 图片马（Polyglot）击穿。
2. **Zip Slip 与头文件错位**：解压时直接拼接 `entry.filename` 导致 `../../` 任意路径覆盖；或校验器读取 Central Directory 名称而解压器读取 Local File Header 导致绕过。
3. **XXE 外部实体注入**：XML 解析器默认启用 `DOCTYPE`、外部通用实体或参数实体，SVG/Office 文档渲染引擎加载外部 `file://`/`http://`/`php://filter` 资源实现读文件与盲外带 SSRF。
4. **LFI / 路径穿越**：下载或包含接口允许 `../`、`....//`、`..%2f` 或 PHP `php://`/`phar://`/`zip://` 流包装器读取敏感配置与源码，或利用 `session.upload_progress` 竞态包含临时文件。

## 核心防御架构

| 攻击面 | 根治控制措施 | 实施要点 |
|---|---|---|
| 文件上传与执行 | 独立对象存储/无执行域名 + UUID 重命名 + 魔数校验与图片重编码 | 禁止使用客户端文件名落盘；上传目录配置不可脚本解析且关闭 `.htaccess` (`AllowOverride None`)；下载带 `Content-Disposition: attachment` 与 `X-Content-Type-Options: nosniff` |
| 归档解压 | 统一使用单一解析器先检验所有条目，严禁解包软链接 | 对每个 `entry` 先 `realpath` 校验必须严格位于目标解压根目录之内；过滤 `symlink`/设备节点 |
| XML / SVG / Office | 全面禁用 DTD 与外部实体解析 | Java 设 `disallow-doctype-decl=true`；PHP 禁用 `LIBXML_NOENT` 并启用安全加载；Python 使用 `defusedxml`；SVG 走静态光栅化或 DOMPurify 清洗 |
| 文件读取与 LFI | 资源 ID 映射替代路径传参 + `realpath` 根目录前缀强校验 | 禁止用户输入直接进入 `include`/`require`/`open`；PHP 关闭 `allow_url_include` 并拦截 `phar://` |

## 加固代码与离线核查示例

以下 Python 示例演示**上传文件名净化与 UUID 重命名、Zip 路径边界与双头一致性检验、安全 XML 解析（禁 DOCTYPE/实体）及 `realpath` 基目录锁定**，附带自检断言：

```python
import io
import os
import uuid
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Tuple

ALLOWED_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp"}


def safe_upload_filename(original_name: str, detected_ext: str) -> str:
    """忽略客户端文件名中的路径与后缀，基于服务端魔数检测类型生成随机名称。"""
    ext = detected_ext.lower()
    if ext not in ALLOWED_IMAGE_EXTS:
        raise ValueError(f"unsupported_detected_type:{ext}")
    return f"{uuid.uuid4().hex}{ext}"


def safe_resolve_under_base(base_dir: Path, user_rel_path: str) -> Path:
    """单次严格解析并验证目标路径严格处于 base_dir 之内。"""
    if "\x00" in user_rel_path or user_rel_path.startswith(("/", "\\")):
        raise ValueError("invalid_relative_path")
    base_resolved = base_dir.resolve()
    target = (base_resolved / user_rel_path).resolve()
    if target == base_resolved or base_resolved not in target.parents:
        raise ValueError(f"path_traversal_blocked:{user_rel_path}")
    return target


def validate_zip_archive(zip_bytes: bytes, extract_root: Path) -> int:
    """校验归档条目无 Zip Slip、无软链接且不包含路径控制字符。"""
    count = 0
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        for info in zf.infolist():
            # Unix symlink 属性位 (0o120000) 检测
            if ((info.external_attr >> 16) & 0o170000) == 0o120000:
                raise ValueError(f"symlink_forbidden:{info.filename}")
            if "\\" in info.filename or "\x00" in info.filename:
                raise ValueError(f"unsafe_zip_entry:{info.filename}")
            safe_resolve_under_base(extract_root, info.filename)
            count += 1
    return count


def reject_doctype_xml(xml_text: str) -> ET.Element:
    """在标准库解析前显式拒绝任何 DOCTYPE / ENTITY 声明（生产推荐直接用 defusedxml）。"""
    upper = xml_text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise ValueError("xxe_doctype_or_entity_forbidden")
    return ET.fromstring(xml_text)


if __name__ == "__main__":
    # 1. 上传重命名测试
    new_name = safe_upload_filename("../../shell.php;.jpg", ".jpg")
    assert new_name.endswith(".jpg") and "/" not in new_name and "php" not in new_name

    # 2. 路径穿越测试
    base = Path("sandbox_uploads").resolve()
    try:
        safe_resolve_under_base(base, "../../etc/passwd")
        assert False
    except ValueError:
        pass
    assert safe_resolve_under_base(base, "avatars/u1.png").parent == base / "avatars"

    # 3. Zip Slip 拦截测试
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../evil.php", "test")
    try:
        validate_zip_archive(buf.getvalue(), base)
        assert False
    except ValueError as e:
        assert "path_traversal_blocked" in str(e)

    # 4. XXE DOCTYPE 拦截测试
    try:
        reject_doctype_xml('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY f SYSTEM "file:///etc/passwd">]><r>&f;</r>')
        assert False
    except ValueError as e:
        assert str(e) == "xxe_doctype_or_entity_forbidden"
    print("File upload / XXE / LFI defense self-check passed.")
```

## 防御工作流

```text
1. 上传隔离：迁移用户文件至独立无脚本执行权限的对象存储域；服务端按内容魔数重编码图片并生成随机 UUID 文件名
2. 服务器加固：Apache 设置 AllowOverride None；Nginx 上传 location 禁解析 php/jsp/asp；响应强制 nosniff 与 attachment
3. 解压防御：使用先校验再落盘的单一安全解压库，逐条检验 realpath 越界并拒绝软链接条目
4. XML 安全：Java/PHP/.NET/Python 解析器全部关闭 DOCTYPE 与外部实体，SVG 经服务端清洗或转码输出
5. 读取收口：文件下载与模板包含改用白名单键值映射，彻底消除用户输入拼路径与流包装器调用
```

## 验证与判定标准

- **上传零执行与原名隔离**：上传 `shell.php.jpg`、`.htaccess` 或 EXIF 含脚本标签的图片后，存储路径为随机 UUID 且不保留可执行后缀；访问上传 URL 无法触发脚本解释执行。
- **Zip Slip 全拒**：包含 `../../`、反斜杠或软链接的恶意压缩包在解包前即报错中止，目标根目录之外无任何文件写入。
- **XXE 与 LFI 阻断**：提交外部实体 DTD、SVG `<image href="file://...">` 及 `....//etc/passwd`、`php://filter` 请求均返回解析错误或 `400`，无文件内容回显与 OOB 外联。

## MCP 工具映射

| 防御步骤 | MCP 工具 | 说明 |
|---|---|---|
| 检索文件与解析器防御 | `kb_router` | 搜索 `文件上传防御`、`XXE禁用`、`Zip Slip防御`、`LFI` |
| 对照攻击变体与测试矩阵 | `kb_read_file` | 读取 [file-upload-xxe-lfi.md](file-upload-xxe-lfi.md) 检查覆盖点 |
| 联动 SSRF OOB 阻断 | `kb_catalog` | 协同查阅 `ssrf-defense` 阻断盲 XXE 外带通道 |
