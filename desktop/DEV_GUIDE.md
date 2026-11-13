# Desktop development guide

[简体中文](DEV_GUIDE.zh-CN.md) · [Desktop guide](README.md)

## Local setup

Use pnpm and the versions supported by `package.json` and the lockfile. The current Windows checks use Node 22, Rust 1.93, and Python 3.13. Python 3.11+ must be available as `python` to both Vite and the native process; sample import uses `hashlib.file_digest`. Native builds require the [platform Tauri prerequisites](https://v2.tauri.app/start/prerequisites/). Windows builds need MSVC C++ build tools; runtime users need WebView2.

From `desktop/`:

```sh
pnpm install --frozen-lockfile
pnpm dev
pnpm tauri dev
pnpm build
```

`pnpm dev` starts the browser preview; `pnpm tauri dev` starts the native application and its development server. Browser preview and native desktop use the same workspace and KB Python services. The browser endpoints are local development middleware.

## Adding a tool or strategy

1. Define the request/result contract in `src/core/contracts`.
2. Add a tool adapter behind `NativeBridge` or an injected runner. Propagate cancellation and any explicitly configured remaining time budget. Preserve output, result provenance, and classified failures. An omitted timeout must remain unlimited through the adapter and subprocess.
3. Add or update the strategy in `src/engine/tracks`; keep red/blue independent.
4. Use `DagScheduler` for dependent parallel actions. When exclusive resources are needed, connect resource keys and an injected shared `DagResourcePool`. An abort request must not release a resource before its runner settles.
5. Emit structured steps, tool records, health events, and evidence through callbacks. Engine code must use its bound Goal and workspace instead of reading the currently visible session.
6. Keep acceptance criteria bound to the objective and assess actual outputs through the independent verifier. A successful process exit alone must not complete the Goal.
7. Update the relevant Markdown contract and test an actual failure, cancellation, or isolation case for the new capability.

Current built-in adapters support Python execution and target triage. Python scripts can invoke installed libraries and CLI tools with the current user account. KB MCP tool names identify related capabilities; invoking them from the desktop requires a connected adapter. Debugger, device, and hardening integrations must implement the same execution and cancellation contracts.

## Verification commands

From `desktop/`:

```sh
pnpm build
node --test src/services/goals/goalManager.test.mjs src/engine/tests/pipeline.test.mjs src/engine/tests/dagScheduler.test.mjs tests/*.test.mjs
node --experimental-strip-types --test tests/*.test.ts
cargo check --manifest-path src-tauri/Cargo.toml
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib
```

From the repository root:

```sh
python -m pytest tests/test_desktop_kb.py tests/test_desktop_workspace.py tests/test_desktop_triage.py
python scripts/misc/public_release_check.py
```

Engine tests use synthetic targets and mocked model responses. Live provider behavior and BLA/REA acceptance require their own recorded runs. Keep private end-to-end targets, logs, and screenshots outside the public change set.

`tests/test_desktop_triage.py` covers missing targets, unknown file metadata, empty directories, and ZIP/APK identity. Target discovery must stop on missing files. Architecture, compiler, imports, and packing status must come from observed metadata.

## Configuration

| Setting | Purpose |
| --- | --- |
| `REVERSELAB_ROOT` | Locate repository knowledge and scripts |
| `REVERSELAB_DATA_DIR` | Set the local workspace registry root |
| `REVERSELAB_WORKSPACE_DIR` | Set the default workspace directory |
| `VITE_LLM_BASE_URL` | Initialize the development model endpoint |
| `VITE_LLM_API_KEY` | Initialize the development model credential |
| `VITE_LLM_MODEL` | Explicitly select the development model ID |
| `VITE_SENTRY_DSN` | Supply a public diagnostic ingestion DSN |

Saved model settings take precedence. A manually configured provider keeps its own credential; it does not inherit another provider's environment key. Model selection uses a saved model or an explicit environment model ID. Configure the endpoint, key, and model before starting model-assisted work.

Vite embeds `VITE_*` values in the frontend build. Runtime credentials belong in local Settings and must stay out of tracked files and distribution builds. Supplying a Sentry DSN does not enable collection; the diagnostic switch defaults to off.

See [workspace storage](WORKSPACES.md), [Agent execution](AGENT_SYSTEM.md), [error codes](ERROR_CODES.md), [proxy routing](NETWORK.md), and [diagnostics](DIAGNOSTICS.md) for their contracts.

## Release

Keep `package.json`, `src-tauri/Cargo.toml`, `src-tauri/Cargo.lock`, and `src-tauri/tauri.conf.json` aligned with the release version. For a local executable, use `pnpm tauri build --no-bundle`. For signed installation and update releases, stage the committed runtime sources and build with `pnpm tauri build --bundles nsis --config src-tauri/tauri.release.conf.json`.

Follow [RELEASING.md](../RELEASING.md) for packaging and publication, and [UPDATES.md](UPDATES.md) for update channels and installation behavior. A source version change alone does not publish an installer.
