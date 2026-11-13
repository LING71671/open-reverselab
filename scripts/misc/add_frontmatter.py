#!/usr/bin/env python3
"""
为 KB 技术文章添加 YAML frontmatter 元数据。
读取文章内容，结合人工的 summary_csv 写入 frontmatter。
也支持从 kb-index.json 推断基础字段。

Usage:
    python scripts/misc/add_frontmatter.py --all          # 处理全部文章
    python scripts/misc/add_frontmatter.py --verify       # 验证已加 frontmatter
    python scripts/misc/add_frontmatter.py --dry-run      # 预览
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BOARDS = ("ctf-website", "apk-reverse", "pe-reverse", "general", "windows")
LAYERS = ("red", "blue", "shared")


REQUIRED_FIELDS = [
    "id", "title", "title_en", "summary", "summary_en",
    "board", "category", "signals", "keywords", "difficulty", "tags",
    "language", "last_updated",
]


def technique_files() -> list[tuple[str, Path]]:
    result = []
    for layer, board in ((layer, board) for layer in LAYERS for board in BOARDS):
        root = ROOT / "kb" / layer / board / "techniques"
        if not root.exists():
            continue
        for p in root.rglob("*.md"):
            if p.name.lower() == "readme.md" or p.name in ("attack-network.md", "defense-network.md"):
                continue
            result.append((board, p))
    return sorted(result, key=lambda x: str(x[1]))


def has_frontmatter(text: str) -> bool:
    return text.lstrip().startswith("---")


def strip_frontmatter(text: str) -> str:
    """剥离 YAML frontmatter，返回正文。"""
    t = text.lstrip()
    if t.startswith("---"):
        end = t.find("---", 3)
        if end != -1:
            return t[end + 3:].lstrip()
    return text


def infer_frontmatter(board: str, path: Path) -> dict:
    """从文章内容和路径推断基础元数据。"""
    text = path.read_text(encoding="utf-8", errors="replace")
    body = strip_frontmatter(text) if has_frontmatter(text) else text

    # 取 H1 为 title
    title = ""
    title_en = ""
    for line in body.splitlines():
        if line.startswith("# ") and not title:
            title = line[2:].strip()
            break

    # 取首段非空非标题行作为原始摘要线索
    lines = body.splitlines()
    first_para_lines = []
    in_first_para = False
    for line in lines:
        if line.startswith("# "):
            if in_first_para:
                break
            in_first_para = True
            continue
        if in_first_para:
            if not line.strip():
                if first_para_lines:
                    break
                continue
            first_para_lines.append(line.strip())
    first_para = " ".join(first_para_lines)[:300]

    # 从路径推断 category
    rel = Path(*path.parts[path.parts.index("techniques") + 1:])
    parts = rel.parts
    category = parts[0] if parts else ""

    # 从文本提取信号
    signals = _extract_signals(text)
    mcp_tools = _extract_mcp_tools(text)
    keywords = signals[:10]

    # 难度
    difficulty = "intermediate"
    if len(text) < 2000:
        difficulty = "beginner"
    elif len(text) > 8000:
        difficulty = "advanced"

    return {
        "id": f"{board}/{rel.with_suffix('').as_posix()}",
        "title": title,
        "title_en": title_en,
        "summary": first_para,
        "summary_en": "",
        "board": board,
        "category": category,
        "signals": signals,
        "mcp_tools": mcp_tools,
        "keywords": keywords,
        "difficulty": difficulty,
        "tags": [],
        "language": "zh-CN",
        "last_updated": "2026-06-25",
        "related_articles": [],
    }


def _extract_signals(text: str) -> list:
    """从文本中提取信号关键词。"""
    patterns = [
        r"\b(JWT|jwt)\b", r"\b(SQLi?|sql)\b", r"\b(SSRF|ssrf)\b",
        r"\b(XSS|xss)\b", r"\b(CSRF|csrf)\b", r"\b(CORS|cors)\b",
        r"\b(OAuth|oauth)\b", r"\b(SAML|saml)\b", r"\b(LDAP|ldap)\b",
        r"\b(GraphQL|graphql)\b", r"\b(gRPC|grpc|Protobuf|protobuf)\b",
        r"\b(Frida|frida)\b", r"\b(Ghidra|ghidra)\b", r"\b(x64dbg)\b",
        r"\b(YARA|yara)\b", r"\b(Sigma|sigma)\b", r"\b(IOC|ioc)\b",
        r"\b(DEX|dex)\b", r"\b(IL2CPP|il2cpp)\b", r"\b(UE4|ue4)\b",
        r"\b(APK|apk)\b", r"\b(PE|pe)\b", r"\b(malware)\b",
        r"\b(加密|解密|encrypt|crypto|AES|DES|RSA|RC4|TEA|XOR)\b",
        r"\b(壳|packer|混淆|obfuscat)\b", r"\b(反调试|anti-debug)\b",
        r"\b(DoS|dos|拒绝服务)\b", r"\b(支付|payment)\b",
        r"\b(签名|signature)\b", r"\b(绕过|bypass)\b",
        r"\b(注入|injection)\b", r"\b(逃逸|escape)\b",
        r"\b(CVE-\d{4}-\d+)\b",
    ]
    found = set()
    for pattern in patterns:
        matches = re.findall(pattern, text, re.I)
        for m in matches:
            if isinstance(m, tuple):
                m = m[0]
            found.add(m.lower())
    return sorted(found)[:20]


def _extract_mcp_tools(text: str) -> list:
    """从文本中提取 MCP 工具引用。"""
    tool_patterns = [
        "http_probe", "run_ctf_tool", "kb_router", "kb_read_file", "kb_catalog",
        "android_app_baseline", "android_crypto_unpack_recipe", "android_frida",
        "android_http_observation_recipe", "android_adb",
        "triage_pe", "ghidra_headless_analyze", "ghidra_summary",
        "make_x64dbg_breakpoint_script", "make_pe_crypto_unpack_plan",
        "sample_full_workup", "sample_autopilot_round",
        "make_yara_stub", "make_sigma_stub", "make_procmon_filters",
        "extract_iocs_from_summary", "refine_ioc_sources",
        "procmon_start_capture", "procmon_stop_capture", "procmon_export_csv",
        "patch_bytes", "patch_pattern", "patch_pe_bytes", "generate_patch_report",
        "die_scan", "rizin_", "solve_crypto_from_evidence", "make_crypto_replay_scaffold",
        "python_re_tool", "hash_file", "search_pattern",
        "carve_payloads_from_dump", "extract_frida_buffers",
        "parse_android_crypto_unpack_result", "postprocess_frida_crypto_result",
        "project_skills_status", "toolbox_launch", "toolbox_list",
        "import_sample", "copy_sample", "quarantine_sample",
    ]
    found = set()
    text_lower = text.lower()
    for tool in tool_patterns:
        if tool.lower() in text_lower:
            found.add(tool)
    return sorted(found)


def format_frontmatter(meta: dict) -> str:
    """将元数据字典格式化为 YAML frontmatter 字符串。"""
    lines = ["---"]
    # 核心字段
    for field in ["id", "title", "title_en", "summary", "summary_en",
                   "board", "category", "difficulty", "language", "last_updated"]:
        val = meta.get(field, "")
        if field in ("summary", "summary_en") and val:
            lines.append(f'{field}: >')
            for para_line in val.replace('\n', ' ').split('。'):
                para_line = para_line.strip()
                if para_line:
                    lines.append(f'  {para_line}。')
        else:
            lines.append(f'{field}: "{val}"')

    # 列表字段
    for field in ["signals", "mcp_tools", "keywords", "tags", "related_articles"]:
        val = meta.get(field, [])
        if val:
            items = ", ".join(f'"{v}"' for v in val)
            lines.append(f"{field}: [{items}]")
        else:
            lines.append(f"{field}: []")

    lines.append("---")
    return "\n".join(lines) + "\n"


def apply_frontmatter(path: Path, frontmatter: str, dry_run: bool = False) -> bool:
    """将 frontmatter 写入文件（如果尚不存在）。"""
    text = path.read_text(encoding="utf-8", errors="replace")
    if has_frontmatter(text):
        return False  # 已有 frontmatter，跳过
    new_text = frontmatter + "\n" + text
    if not dry_run:
        path.write_text(new_text, encoding="utf-8")
    return True


def verify() -> list[str]:
    """验证所有文章都有完整的 frontmatter。"""
    failures = []
    for board, path in technique_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        if not has_frontmatter(text):
            failures.append(f"missing-frontmatter: {path.relative_to(ROOT)}")
            continue
        # 解析 YAML
        t = text.lstrip()
        end = t.find("---", 3)
        if end == -1:
            failures.append(f"malformed-frontmatter: {path.relative_to(ROOT)}")
            continue
        fm_text = t[3:end]
        for field in REQUIRED_FIELDS:
            if f"{field}:" not in fm_text:
                failures.append(f"missing-field:{field} in {path.relative_to(ROOT)}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", help="处理全部文章")
    parser.add_argument("--verify", action="store_true", help="验证 frontmatter 完整性")
    parser.add_argument("--dry-run", action="store_true", help="预览模式")
    parser.add_argument("--board", help="仅处理指定板块")
    parser.add_argument("--file", help="仅处理指定文件路径（相对于 techniques/）")
    args = parser.parse_args()

    if args.verify:
        failures = verify()
        print(json.dumps({"overall": "PASS" if not failures else "FAIL",
                          "failures": failures}, ensure_ascii=False, indent=2))
        return 1 if failures else 0

    if not args.all and not args.file:
        parser.print_help()
        return 0

    files = technique_files()
    if args.board:
        files = [(b, p) for b, p in files if b == args.board]
    if args.file:
        files = [(b, p) for b, p in files if args.file in p.as_posix()]

    count = 0
    for board, path in files:
        meta = infer_frontmatter(board, path)
        fm = format_frontmatter(meta)
        if apply_frontmatter(path, fm, dry_run=args.dry_run):
            count += 1
            print(f"  + {path.relative_to(ROOT)}")
    print(f"\n{count} files processed (dry_run={args.dry_run})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
