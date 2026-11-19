# Static analysis: IDA first, Ghidra fallback

The existing `reverse_lab_tools` MCP server now includes a native IDAPython
adapter. No separate third-party IDA MCP server is required for this workflow.
It performs static analysis only: it does not launch the sample or a debugger.

## Default policy

- `static_headless_analyze(path=..., backend="auto")` tries IDA first, then
  Ghidra if IDA cannot launch, times out, fails, or does not export a valid summary.
- `backend="ida"` and `backend="ghidra"` are explicit choices and do not silently
  switch tools. An empty backend uses `REVERSELAB_STATIC_BACKEND`, default `auto`.
- A failed attempt is recorded in `attempts`, including available log paths;
  success identifies `backend` and `fallback_used`. Two failures return an error,
  not a stale or invented summary.
- `sample_full_workup(sample_path=...)` now performs static analysis by default.
  A supplied `summary_path` is reused instead of rerunning static analysis.
- Set `run_static=False` for the previous no-analysis behavior.
  Legacy `run_ghidra=True` deliberately forces Ghidra; it overrides backend selection.
- The autopilot uses this same policy and retains the chosen backend in its manifest.

## Discovery and configuration

`static_backend_status()` reports discovered executables without launching them.
Discovery checks `REVERSELAB_IDA_EXE`, PATH, `IDA_HOME`, and supported local
installation locations (including the Windows IDA Professional registry entry).
Prefer the text-mode `idat` executable. An explicit invalid executable override
is reported rather than silently replaced by another IDA installation.

Optional process environment settings:

    REVERSELAB_STATIC_BACKEND=auto
    REVERSELAB_IDA_EXE=<absolute path to idat executable>
    IDA_HOME=<IDA installation directory>

Set these in the MCP server's environment or its parent process. A repository
`.env` file is not implicitly loaded by this adapter. Do not put machine-specific
paths or license material in public configuration files.

IDA Professional 9.4 with IDAPython is the locally validated configuration.
Hex-Rays provides pseudocode. Without a matching decompiler, basic static
metadata can still be exported; each function explicitly reports an unavailable
or failed decompilation rather than fabricated pseudocode. This alone does not
discard otherwise usable IDA metadata or force a Ghidra run.

IDA runs in autonomous mode with the shipped exporter. Both timeouts bound the
IDA process; the smaller positive analysis/process timeout applies. Automatic
fallback gives Ghidra its own configured budget.

## MCP tools

- `static_backend_status`: executable discovery and configured preference.
- `static_headless_analyze`: preferred entry point with backend selection.
- `ida_headless_analyze` / `ghidra_headless_analyze`: direct explicit backends.
- `static_summary_list` / `static_summary_overview` / `static_summary_functions`.
- `static_summary_function_detail` / `static_summary_imports` / `static_summary_strings`.
- Existing `ghidra_summary_*` readers default to the newest Ghidra export.
  Explicit summary paths can point to either backend. The `static_summary_*`
  readers default to the newest export across both backends. Function references, strings, imports and decompilation previews
  retain the existing field contract used by notes, breakpoints and IOC reports.

Reload/reconnect the `reverse_lab_tools` MCP server after updating its source
so the client discovers the added tools and revised workflow arguments.

## Artifact isolation

- Each IDA call gets a new database directory under `projects/windows/ida-headless/`.
- Inputs are copied into that directory before analysis; original samples and
  existing databases are not overwritten, regardless of the legacy `overwrite` flag.
- IDA summaries and logs go under `exports/windows/ida/` with unique run identifiers.
- Ghidra retains its existing paths. Both summary roots are accepted, with path
  traversal rejected. Ghidra output from a previous run is not accepted as fresh.
- Existing `cases/` and project contents are not migrated or deleted.
- Generated evidence stays in local artifact directories and is not a public source artifact.

## Verification

    python -B -m pytest -q tests/test_static_analysis.py

Tests mock the commercial tools: IDA preference, missing executable, timeout,
nonzero exit, malformed/missing summary, forced backend, environment preference,
failure reporting, input preservation, isolated databases, compatible readers,
path containment, stale-summary rejection, workflow defaults and autopilot policy.
Runtime readiness must additionally be checked with a locally generated benign
fixture; executable discovery alone is not license or decompiler validation.
