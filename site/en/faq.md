# Frequently Asked Questions

Answers to common questions about the ReverseLab project, its MCP tools, the knowledge base, and contributing.

## 1. What is ReverseLab?

ReverseLab is an open-source reverse engineering lab that combines a knowledge base of **183 in-depth technical articles**, **100+ MCP (Model Context Protocol) automation tools**, and end-to-end automated workflows for CTF / APK / PE analysis. The project follows a "conventions as contracts" design and is built for AI-agent-assisted analysis.

## 2. Which areas does the ReverseLab knowledge base cover?

- **CTF Website** (26 categories, 118 articles): JWT / SQLi / SSRF / XSS / CVE / DoS / Payment / Paywall / Signature attacks / API / OAuth / Cloud-native / IAM
- **APK Reverse** (8 categories, 23 articles): DEX / Native / JNI / IL2CPP / Frida / Pinning / Unpacking / VMP / Repackaging
- **PE Reverse** (9 categories, 24 articles): Ghidra static analysis / x64dbg dynamic debugging / TLS Callbacks / API Resolvers / VMP virtualization / IOC / YARA / Sigma / Patch / AV evasion
- **General** (5 categories, 17 articles): Linux kernel exploitation / crypto algorithm identification / PRNG cracking / game cheating and anti-cheat / protocol reversing / firmware / hardware
- **Windows** (1 article): Windows platform configuration-injection deep dive

## 3. What are MCP tools, and why do they matter?

MCP (Model Context Protocol) is the **standard protocol** for AI models to interact with external tools. ReverseLab's MCP tools let an AI agent **directly invoke** reverse engineering tooling without manual intervention. For example: the AI spots a JWT token → automatically calls `kb_router` to look up the technique → `kb_read_file` to read the attack method → `http_probe` to send a probe request → decides whether a vulnerability exists. This is rare in the open-source ecosystem and is ReverseLab's core differentiator.

## 4. How does an AI agent use ReverseLab for automated analysis?

After loading the project, the agent walks the context chain (`CLAUDE.md` → `AGENTS.md` → `AI-USAGE.md` → `boards/<board>/AI-USAGE.md`) to learn the conventions. When a signal is detected:

1. Call `kb_router` to find relevant technique articles
2. Call `kb_read_file` to read the article and its runnable code
3. Follow the **MCP tool mapping table** in each article to invoke the matching tools automatically
4. Collect evidence, record notes, and generate reports

## 5. How do I install and use ReverseLab?

```powershell
git clone https://github.com/LING71671/open-reverselab.git
cd open-reverselab
.\scripts\misc\bootstrap.ps1
.\scripts\misc\install_tools.ps1 -CTF       # Web tools
.\scripts\misc\install_tools.ps1 -Android   # APK tools
.\scripts\misc\install_tools.ps1 -Windows   # PE tools
.\scripts\misc\install_tools.ps1 -Common    # Ghidra + Maven

# Verify
python scripts/misc/lab_healthcheck.py
python scripts/misc/ai_toolcheck.py
```

## 6. Does ReverseLab execute requests on its own?

No. ReverseLab provides technical documentation, directory conventions, and an automated toolchain; whether a given request is executed is handled by the AI model provider, hosting platform, or organizational policy you connect to.

## 7. How does ReverseLab relate to Ghidra / x64dbg / Frida and similar tools?

ReverseLab is a **knowledge base and automation orchestration layer** — it integrates, but does not bundle, these external tools. Supported tooling includes Ghidra (decompiler), x64dbg (Windows debugger), Frida (dynamic instrumentation), JADX (APK decompiler), sqlmap, Burp Suite, nmap, DirSearch, Cheat Engine, PE-bear, DiE, Procmon, HxD, Cutter/Rizin, and various Python CTF libraries.

## 8. How can I contribute to ReverseLab?

See [CONTRIBUTING.md](https://github.com/LING71671/open-reverselab/blob/main/CONTRIBUTING.md). After adding or changing content, run `public_release_check.py`, `lab_healthcheck.py`, and `kb_doc_audit.py` to keep the directory structure, indexes, and documentation consistent.
