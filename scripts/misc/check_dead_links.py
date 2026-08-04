"""扫描仓库内所有 tracked markdown 文件的相对链接，找出死链（目标不存在）。
只检查相对路径链接；外部 URL、页内锚点、协议相对链接跳过。
"""
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

def tracked_files():
    out = subprocess.check_output(["git", "-C", str(ROOT), "ls-files"], text=True)
    files = {p.replace("/", os.sep) for p in out.splitlines() if p}
    return files

def strip_code(text):
    """移除 fenced code block 和 inline code，避免正则/代码被误判为链接。"""
    text = re.sub(r"```.*?```", "\n", text, flags=re.S)
    text = re.sub(r"~~~.*?~~~", "\n", text, flags=re.S)
    # 行内代码 `...`（粗鲁但有效：把内容替换成占位符）
    text = re.sub(r"`[^`]*`", "`code`", text)
    return text

def collect_links(md_path, files, dead):
    text = md_path.read_text(encoding="utf-8", errors="replace")
    text = strip_code(text)
    # 内联链接 [text](url) 和参考式定义 [ref]: url
    inline = re.findall(r"\[[^\]]*\]\(([^)]+)\)", text)
    refdef = re.findall(r"^\[[^\]]+\]:\s*(\S+)", text, re.MULTILINE)
    links = inline + refdef
    base_dir = md_path.parent
    for raw in links:
        url = raw.strip().strip("<>")
        if not url:
            continue
        if re.match(r"^(https?|ftp|mailto|tel|file):", url, re.I):
            continue
        if url.startswith("//"):
            continue
        if url.startswith("#"):
            continue  # 页内锚点
        # 去掉 query/fragment
        target = url.split("#")[0].split("?")[0].strip()
        if not target:
            continue
        # 反引号或空白处理
        if " " in target and "(" not in target:
            target = target.split()[0]
        resolved = os.path.normpath(os.path.join(str(base_dir), target.replace("/", os.sep)))
        rel = os.path.relpath(resolved, str(ROOT))
        exists = False
        if rel in files or rel.lower() in {f.lower() for f in files}:
            exists = True
        elif os.path.isdir(resolved):
            exists = True  # 目录链接（如 boards/）
        elif os.path.exists(resolved) and os.path.isfile(resolved):
            exists = True  # 未 tracked 但存在于工作区
        if not exists:
            dead.append((md_path, raw, target))

def github_slug(header):
    """近似 GitHub 锚点 slug：小写、去标点（保留连字符/空格/下划线/冒号/点）、空格转连字符。"""
    h = header.strip()
    h = re.sub(r"<[^>]+>", "", h)  # 去 HTML 标签
    h = re.sub(r"`([^`]*)`", r"\1", h)  # 去反引号
    h = re.sub(r"^#+\s*", "", h)  # 去掉标题标记前缀
    h = h.lower()
    h = re.sub(r"[^\w\s\-:.]", "", h, flags=re.UNICODE)
    h = re.sub(r"\s+", " ", h)  # 合并连续空白
    h = h.replace(" ", "-")
    h = h.strip("-")
    return h

def collect_anchors(md_path, files, dead):
    text = md_path.read_text(encoding="utf-8", errors="replace")
    text = strip_code(text)
    base_dir = md_path.parent
    # 页内锚点 [text](#foo)
    for m in re.finditer(r"\[[^\]]*\]\(#([^)\s]+)\)", text):
        anchor = m.group(1)
        if not any(github_slug(line) == anchor
                   for line in text.splitlines() if line.strip().startswith("#")):
            dead.append((md_path, f"#{anchor}", f"<same-file> 缺少标题锚点 #{anchor}"))
    # 跨文件锚点 [text](file.md#foo)
    for m in re.finditer(r"\[[^\]]*\]\(([^)\s]+\.md)#([^)\s]+)\)", text):
        target, anchor = m.group(1), m.group(2)
        resolved = os.path.normpath(os.path.join(str(base_dir), target.replace("/", os.sep)))
        rel = os.path.relpath(resolved, str(ROOT))
        exists = (rel in files or rel.lower() in {f.lower() for f in files})
        if not exists:
            continue  # 文件本身不存在已由主流程报告
        tpath = Path(resolved)
        if not tpath.exists():
            continue
        ttext = tpath.read_text(encoding="utf-8", errors="replace")
        if not any(github_slug(line) == anchor
                   for line in ttext.splitlines() if line.strip().startswith("#")):
            dead.append((md_path, f"{target}#{anchor}", f"{target} 缺少标题锚点 #{anchor}"))

def collect_refs(md_path, files, dead):
    """检查 [text][ref] 是否在文件内有 [ref]: 定义。"""
    text = md_path.read_text(encoding="utf-8", errors="replace")
    text = strip_code(text)
    defined = set(re.findall(r"^\[([^\]]+)\]:\s*\S+", text, re.MULTILINE))
    used = set(re.findall(r"\[[^\]]*\]\[([^\]]+)\]", text))
    for ref in used - defined:
        dead.append((md_path, f"[ref:{ref}]", f"引用式链接未定义 [{ref}]"))

def main():
    files = tracked_files()
    md_files = sorted(
        Path(ROOT) / f for f in files
        if f.lower().endswith(".md") and not f.startswith(".git")
    )
    # 补充工作区实际存在的 untracked md（排除本地工具/生成目录）
    skip_dirs = {".git", ".reasonix", ".serena", ".claude", ".codex",
                 "tmp", "logs", "exports", "samples", "patches", "projects",
                 "reports", "notes", "cases", "dist", ".reverselab-local", ".pytest_cache",
                 ".venv", "node_modules", "__pycache__"}
    for p in ROOT.rglob("*.md"):
        rel = p.relative_to(ROOT)
        if any(part in skip_dirs for part in rel.parts):
            continue
        if p not in md_files:
            md_files.append(p)
    md_files = sorted(set(md_files))
    dead = []
    for f in md_files:
        if not f.exists():
            continue  # sparse checkout 缺失，跳过
        try:
            collect_links(f, files, dead)
            collect_anchors(f, files, dead)
            collect_refs(f, files, dead)
        except Exception as e:
            print(f"[ERR] {f}: {e}")
    print(f"扫描 {len(md_files)} 个 markdown 文件，发现 {len(dead)} 个死链\n")
    for md, raw, target in dead:
        rel = os.path.relpath(md, ROOT).replace(os.sep, "/")
        print(f"{rel}  ->  [{raw}]  (解析目标: {target})")

if __name__ == "__main__":
    main()
