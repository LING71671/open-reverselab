# P4nda0s/reverse-skills provenance and local mapping

## Review record

- Upstream: <https://github.com/P4nda0s/reverse-skills>
- Reviewed revision: `a2baa31c58a3567977188414da68c8c842057152`
- Review date: 2026-07-31
- Relevant upstream paths reviewed:
  - `skills/rev-frida/SKILL.md`
  - `skills/rev-symbol/SKILL.md`
  - `skills/rev-struct/SKILL.md`

The upstream README states MIT, but the reviewed repository tree does not contain a committed `LICENSE` file. Under this repository's public migration boundary (`PUBLICATION.md`), the upstream is therefore treated as **reference-only**. This project does not vendor its prompt text, source snippets, templates, binaries, submodules, or package dependencies. The implementation below is independently written and uses existing ReverseLab interfaces.

## Capability mapping

| Upstream workflow idea | Open-ReverseLab implementation | Primary execution/evidence surface |
|---|---|---|
| `rev-frida` loader-aware instrumentation | Android native Frida templates and JNI tracing guidance | `android_frida_template_library`, `android_frida_render_template`, `android_frida_run_script`, `android_crypto_unpack_recipe` |
| `rev-symbol` function-name inference | Ghidra summary evidence plus conservative Function Map suggestions | `ghidra_headless_analyze`, `ghidra_summary_functions`, `ghidra_summary_function_detail`, `ghidra_summary_call_focus`, generated analysis notes |
| `rev-struct` layout inference | Existing PE struct/ReClass techniques plus a symbol/field evidence ledger | `kb/pe-reverse/techniques/03-static-analysis/01-struct-reconstruction.md`, `04-reclass-reconstruction.md` |

## Tool baseline

For the supported Ghidra-first workflow, install or provide:

- Ghidra and the compatible Java runtime; `analyzeHeadless` is the primary automated path.
- Android SDK platform-tools (`adb`) for Android work.
- Host Frida tooling plus an Android `frida-server` version compatible with the host client.
- JADX and Apktool for Android static preparation.

IDA Pro/Hex-Rays may be used as an analyst-provided optional second opinion. It is not required by this integration, is not added to `.mcp.json`, and is not a CI dependency. Ghidra summary evidence remains the portable project contract.

## Update policy

Before using a newer upstream revision as inspiration, review its tree and license metadata again, update the pinned revision and date in this file, and check that no unconfirmed third-party source or binary crosses the public migration boundary.
