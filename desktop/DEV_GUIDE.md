# Desktop development guide

## Local setup

Use the versions supported by `package.json` and the lockfile, with pnpm as the package manager. The current Windows checks use Node 22, Rust 1.93 and Python 3.13. Python 3.10+ must be available as `python` to both Vite and the native process. Native builds require the [platform Tauri prerequisites](https://v2.tauri.app/start/prerequisites/). Windows builds need MSVC C++ build tools; runtime users need WebView2.

```sh
pnpm install --frozen-lockfile
pnpm dev
pnpm tauri dev
pnpm build
```

Browser preview and native desktop use the same workspace and KB Python services. The browser endpoints are local development middleware, not a remotely deployable service.

## Adding a tool or strategy

1. Define the request/result contract in `src/core/contracts`.
2. Add a tool adapter behind `NativeBridge` or an injected runner. Include real timeouts, cancellation, output bounds, result provenance and classified failures.
3. Add or update the strategy in `src/engine/tracks`; keep red/blue independent.
4. Use `DagScheduler` for dependent parallel actions and an injected shared `DagResourcePool` for exclusive resources. An abort request must not release a resource before its runner settles.
5. Emit structured steps, tool records, health events and evidence through callbacks. Do not update React or read the currently visible session from engine code.
6. Extend the fixed acceptance criteria and independent verifier. A successful process exit alone must not complete the Goal.
7. Update the relevant Markdown contract and test an actual failure, cancellation or isolation case for the new capability.

Current built-in adapters support Python execution and target triage. Python scripts can invoke installed libraries and CLI tools with the current user account; the model selects actions using the user objective and its own safety policy. KB MCP tool names are references, not automatically registered executable adapters. Adding debugger/device/hardening execution requires the corresponding adapter.

## Verification commands

From `desktop`:

```sh
pnpm build
node --test src/services/goals/goalManager.test.mjs src/engine/tests/pipeline.test.mjs tests/*.test.mjs
node --experimental-strip-types --test tests/*.test.ts
cargo check --manifest-path src-tauri/Cargo.toml
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib
```

From repository root:

```sh
python -m pytest tests/test_desktop_kb.py tests/test_desktop_workspace.py
python scripts/misc/public_release_check.py
```

The tests use synthetic targets and mocked model responses. They do not prove a specific provider's live quality or BLA/REA resistance. Save private end-to-end runs and screenshots outside the public change set.

`tests/test_desktop_triage.py` also covers nonexistent targets, unknown file metadata, empty directories and ZIP/APK identity. Target discovery must stop on missing files; architecture, compiler, imports and packing status must never be filled with demo defaults.

## Configuration

`REVERSELAB_ROOT` locates the repository knowledge/scripts. `REVERSELAB_DATA_DIR` changes the local registry root, and `REVERSELAB_WORKSPACE_DIR` changes the default data workspace. Runtime credentials belong in local Settings, never in tracked configuration.

See [WORKSPACES.md](WORKSPACES.md), [AGENT_SYSTEM.md](AGENT_SYSTEM.md) and [ERROR_CODES.md](ERROR_CODES.md) for storage, execution and failure contracts.

## Release

Keep `package.json`, `src-tauri/Cargo.toml`, `src-tauri/Cargo.lock` and `src-tauri/tauri.conf.json` aligned with the release version. For a local executable, use `pnpm tauri build --no-bundle`. For signed installation and update releases, stage the committed runtime sources and build with `pnpm tauri build --bundles nsis --config src-tauri/tauri.release.conf.json`; see [RELEASING.md](../RELEASING.md).
