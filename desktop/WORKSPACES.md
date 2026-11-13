# Workspaces and samples

[简体中文](WORKSPACES.zh-CN.md) · [Desktop guide](README.md)

Open ReverseLab creates a default workspace on first use and lets the user create or open other workspaces. Each workspace owns its samples, Goals, execution records, and analysis artifacts.

## Directories

The default location is `.open-reverselab/workspaces/Default` beneath the user's home directory. `REVERSELAB_WORKSPACE_DIR` overrides this location. The workspace registry is `.open-reverselab/workspaces.json`; `REVERSELAB_DATA_DIR` overrides the local data root. Tests use temporary directories.

Creating a workspace in an existing directory adds the managed `.reverselab` directory. Opening an existing workspace requires a valid manifest.

```text
<workspace>/
  .reverselab/
    workspace.json           # version, id, name, createdAt
    goals.json               # Goal snapshots and execution records
    samples/<sample-id>/
      sample.json            # file list, sizes, and SHA256
      original/              # imported original copies
      working/               # analysis copies
    reports/<goal-id>/<track-attempt>/analysis.md
    exports/<goal-id>/<track-attempt>/observation.py
```

## Sample import and targets

Import copies the source without moving or deleting it. Files receive a SHA256 identity; a directory's manifest records each file's relative path, size, and hash. The importer currently accepts up to 2 GiB and 10,000 entries and rejects linked entries. These are import limits, independent of Goal budgets.

Original and working copies are separate. An imported sample's default target points to its working copy. Execution uses the selected target with the current account's permissions.

A URL can be used directly as a Goal target. External files and directories can also be referenced directly; managed copies are created through sample import.

## Lifecycle and service API

[workspaceRuntime](src/services/goals/workspaceRuntime.ts) holds a separate GoalManager for each loaded workspace. Switching views keeps its runners alive. A runtime passes its bound report path to the pipeline and storage adapter. Reports for the same target remain separate by Goal ID, strategy, and attempt.

The Tauri `workspace_operation` command and development `POST /api/workspace` endpoint use the same [Python implementation](../scripts/misc/desktop_workspace.py). JSON requests select an `action`:

| Action | Input | Result |
| --- | --- | --- |
| `default` | None | Create or open the default workspace |
| `list` | None | Registered workspaces |
| `create` | `root`, optional `name` | Initialize the manifest and managed directories |
| `open` | `root` | Validate and open the manifest |
| `samples` | `root` | Sample records |
| `import` | `root`, `source` | Original and working copies with a manifest |
| `load` | `root` | Goal snapshot, or `null` before the first save |
| `save` | `root`, `snapshot` | Atomically replace the Goal snapshot |
| `report` | `root`, `report` | Save a report and observation script |

JSON persistence writes a temporary file, flushes it, and atomically replaces the destination. Shared registry and snapshot writes use a local file lock; the frontend also serializes writes per workspace. Locks prevent overlapping writes but do not merge competing records from multiple instances. Use one writing application instance per workspace.

Reports and scripts are saved separately from Goal snapshots. A failure to save them is surfaced as a storage failure. Before installing an application update, the runtime waits for loaded workspace writes to finish; see [UPDATES.md](UPDATES.md).

## Recovery and moving workspaces

When loading history, previous `running` or `queued` Goals become `cancelled`, with interrupted progress and steps marked accordingly. Loading does not restart external processes. Create a new Goal to continue analysis. Normal operations save records asynchronously, so writes still pending when a process terminates can be lost.

Workspaces contain private samples, targets, logs, and reports and stay outside the public repository. Back up the complete `.reverselab` directory. Current snapshots contain absolute target and report paths. After moving a workspace, select the target again; automatic path relocation is not implemented.

Model credentials and application preferences are stored separately in local WebView storage. Copying a workspace does not copy those settings. See [Agent lifecycle](AGENT_SYSTEM.md) and [health events](ERROR_CODES.md) for execution and failure contracts.
