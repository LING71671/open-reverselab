# Changelog

[简体中文](CHANGELOG.zh-CN.md)

Notable changes to Open ReverseLab.

## [2.0.0-beta.1] - 2026-11-13

### Desktop and Agent execution

- Windows x64 desktop installer and portable ZIP, with a live flow canvas, readable analysis progress, expandable evidence, and full-page Settings.
- Independent red and blue strategies. Both can plan multiple actions, run independent work concurrently, exchange evidence across branches, and verify the combined Goal.
- Generated action DAGs with dependency validation, parallel execution, joins, cancellation, and recorded input bindings. The canvas uses actual dependencies and evidence links.
- Concurrent Goals and ready actions without a default count cap. Time and token budgets are optional. Running Goals accept revised requirements while retaining their identity, history, and evidence.
- Independent verification separates process success from Goal completion. Failed routes, repeated actions, and missing evidence feed into further planning.
- Triage and Python execution have no default timeout or 4 MiB output cutoff. Configured remaining time budgets propagate to execution; stopping or expiry terminates the Python process tree.
- Workspaces retain samples, original and working copies, Goals, reports, and observation scripts. Background execution remains bound to its originating workspace.

### Configuration and knowledge

- Model selection uses saved configuration or an explicit environment model ID. Provider credentials stay associated with their configured provider.
- Native streaming model transport and independent model/Python proxy routing, with proxy pools, connection checks, cancellation, and failure classification.
- Separate `kb/red/`, `kb/blue/`, and `kb/shared/` collections, attack and defense networks, related-document navigation, and indexed knowledge access.
- Optional sustained performance warnings and optional Sentry diagnostics, both off by default. Diagnostics sanitize errors and timings, exclude restored history, and cancel in-flight submissions when disabled.
- Stable and Beta update channels use actual GitHub Release assets and SemVer ordering. Installer updates verify the package signature and wait for all workspaces' tasks and writes.
- English and Chinese architecture, Agent runtime, workspace, network, diagnostic, update, development, and error-code guides.
- Project-owned code uses Apache-2.0. Third-party components retain their original licenses; earlier published versions retain their original terms.

### Fixes and validation scope

- Improved canvas layout, expansion stability, cursor behavior, viewport following, and transitions; raw plans and scripts are available in details instead of filling the transcript.
- Regression coverage includes Goal revisions and isolation, DAG dependencies and cancellation, evidence provenance, update-channel selection, proxy behavior, diagnostics, and workspace persistence.
- Windows process cancellation and large-output handling were checked with real subprocesses. Synthetic model and release records cover orchestration and update state transitions.
- This beta targets Windows x64 and requires Python 3.11+ and WebView2. External analysis tools are installed separately. User task evaluation and full installed-version upgrade acceptance remain separate from the regression checks. BLA/REA evaluation is not included in this release's validation.

## [2.0.0] - 2026-11-13 (withdrawn)

### Added

- Windows x64 desktop with independent red/blue strategies, parallel both branches, target-bound Goals, a queue, workspaces, and original/working sample copies.
- Live flow canvas, execution evidence, verification, repeat detection, error codes, and health monitoring. This withdrawn revision used time-bounded Python observations.
- Application updates with optional daily checks, release notes, skipped versions, download progress, and signature/version checks. Installation waited for all workspace tasks and persistence, with single-instance protection.
- Windows installer, portable ZIP, signatures, and update manifest. This revision did not include Authenticode signing.

### Changed

- Unified light/dark desktop and website styling, typography, spacing, controls, and transitions, with retained drafts, filters, and reading positions.
- Website desktop screenshots, bilingual installation/update instructions, tool search, and removal of obsolete counts and development links.
- Reworked README and product/developer documentation, with Agent, workspace, health, release, and update contracts. Knowledge documents used domain organization and `track`/`defends` relationships.
- Fixed indexed article links, standardized website builds on pnpm, and retained migration entries for old documentation pages.

### Scope

The binary target was Windows x64. Python and external reverse-engineering tools were separate dependencies. Model-assisted analysis sent context and evidence to the configured endpoint. BLA/REA acceptance and native debugger adapters remained outstanding.

## [1.2.1] - 2026-09-07

A single `v1.2.1` release tag. Documentation and branding changes did not alter platform artifacts or require reinstalling the toolchain.

### Changed

- Redesigned the README with a centered introduction, Docs/Discord/DeepWiki/License/Sponsor badges, project purpose, audience guidance, and separate human/AI-agent quick starts with collapsible commands.
- Added the Sponsored by Sentry placement and light/dark wordmarks, a dedicated Sponsors section, and links to `SPONSORS.md`.
- Used the “180+ articles” knowledge-base description and linked the generated documentation site as the catalog reference.
- Added `assets/sponsors/sentry-wordmark-light.svg` and `sentry-wordmark-dark.svg`.
- Made Chinese the README default for that revision, moved English to `README.en.md`, removed the then-redundant `README.zh.md`, and added language links.
- Replaced sponsor Markdown tables with full-width HTML tables and logos. Updated the public sponsor contact to **belloshehubz@gmail.com**.

### Fixed

- Checked README references against tracked entry points, contribution documents, code of conduct, and sponsor files.

## [1.2.0] - 2026-09-06

A single `v1.2.0` tag with no platform-specific artifact differences.

### Added

- VitePress documentation on Cloudflare Pages, tool pages, FAQ, custom 404, social preview images, and automated `deploy-site.yml` deployment.
- Cross-platform social-preview generation with committed PNG output; board badges used color dots.
- VMP virtualization/devirtualization coverage, a license/keygen section with 10 categories and 31 articles, and reverse-skills workflows.
- English-default and separate Chinese README versions for that revision; DeepWiki badge, Sentry acknowledgments, Contributor Covenant, and the then-current noncommercial statement.
- The local `env.md` environment-snapshot protocol and 22 gradient themes.
- Replaced the QQ group link with Discord, repaired links, restored the upstream JSHookLocal reference, and added platform-aware installation prompts.

### Fixed

- Set `PYTHONIOENCODING=utf-8` and UTF-8 output for `ai_context` and `ai_toolcheck` to repair CJK JSON output.
- Returned POSIX-style paths from `kb_router` and repaired POSIX command fallback.
- Increased tool-check failure details to 1,500 characters.
- Addressed Windows first-run issue #13 and ignored local `.reasonix` data and generated preview files.

### Notes

The English website was still in progress and was not included in that release.

## [1.1.0] - 2026-07-08

Platform tags: `v1.1.0-macos-linux` for the POSIX core and `v1.1.0-windows` for the Windows toolchain.

### Added

- `START_HERE.sh`, `scripts/misc/bootstrap.sh`, and extensionless POSIX `ai_context`, `ai_tool`, `ai_finding`, and `ai_toolcheck` wrappers.
- Platform-aware registry paths, `.bat/.cmd` fallbacks, current-interpreter fallback, and MCP routing for Ghidra, Rizin, adb, and CTF tools.
- Cross-platform quick-start documentation and explicit handling of Windows-only tools.

### Release notes

- **macOS/Linux:** run `./START_HERE.sh`, then `./scripts/misc/bootstrap.sh`, and add `tools/bin` and `tools/ctf-website/bin` to PATH. The release focused on Python/MCP, wrappers, and installed native CLI tools.
- **Windows:** use `START_HERE.bat`, `scripts/misc/bootstrap.ps1`, and `scripts/misc/install_tools.ps1` for the full GUI/PE toolchain.

## [1.0.0] - 2026-06-25

### Initial public release

- 197 technical articles across Web/CTF, APK, PE, General, and Windows. Articles linked scenarios, signals, methods, paths, and MCP tools.
- Four Mermaid attack-network maps and a Web/CTF checklist covering test matrices and evidence collection.
- More than 100 MCP tools for Web/CTF, Android, PE/Windows, general analysis, and sample operations.
- CTF and sample-analysis workflows, including discovery, static/dynamic analysis, verification, reporting, IOC/rule generation, and patch workflows.
- Release checks for publication privacy, environment health, tool availability, knowledge documents, and pytest.
- Folder conventions for local artifacts, five-board routing, and the AI context chain `CLAUDE.md → AGENTS.md → AI-USAGE.md → boards/<board>/AI-USAGE.md`.
- Publication rules, contribution guidance, security policy, and the GPL-3.0-only license used by that initial version.
