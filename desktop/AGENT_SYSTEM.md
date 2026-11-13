# Desktop Agent runtime

[简体中文](AGENT_SYSTEM.zh-CN.md) · [Architecture](ARCHITECTURE.md)

Open ReverseLab runs a Goal against a target using `red`, `blue`, or `both`. The runtime selects observations, executes actions, retains evidence, and independently checks the requested result. Time and token budgets are optional. The user can add requirements during execution or stop the Goal.

This document describes current contracts and implementation boundaries. A successful tool call, a saved report, and a verified Goal are recorded separately.

## Strategy contracts

| Strategy | Owns | Shares |
| --- | --- | --- |
| `red` | Analysis hypotheses, acceptance criteria, action selection, and assessment rules | Tool adapters, indexed knowledge access, event contracts, and runtime services |
| `blue` | Defensive questions, required observations, detection or remediation assessment | The same runtime services |
| `both` | Strategy startup, budget allocation, evidence exchange, and combined verification | One overall Goal budget |

[red.ts](src/engine/tracks/red.ts) and [blue.ts](src/engine/tracks/blue.ts) implement [TrackPolicy](src/engine/tracks/contract.ts) independently. [both.ts](src/engine/tracks/both.ts) composes their runners, retaining separate context, route history, action output, and verdicts.

Both strategies can create action forks and joins. They exchange observations while executing, and later actions can depend on evidence produced by the other strategy. Passing both scoped assessments is followed by [verification of the original combined objective](src/engine/tracks/verifyBothGoal.ts).

Knowledge selection uses indexed track metadata: red reads `kb/red/` and `kb/shared/`; blue reads `kb/blue/` and `kb/shared/`. Each strategy in both retrieves its own references. A paired-document link helps locate related material without changing the receiving strategy.

## Goal ownership and revisions

[GoalManager](src/services/goals/goalManager.ts) copies the target, objective, strategy, and optional budget on submission. Callback closures bind to the Goal ID; changing the visible Goal, workspace, or top-level strategy does not retarget execution. Managers remain alive in their original [workspace runtime](src/services/goals/workspaceRuntime.ts).

Model and provider settings are captured when each pipeline execution starts. A queued Goal therefore uses the settings present when its runner begins. Both strategies inherit the same snapshot. Settings changes do not replace a running model request.

A running or queued Goal accepts additional requirements through `steer`:

1. Append a numbered revision to the objective and retain the user's message with `pending` status.
2. Let the current stage settle. An action DAG checks for revisions before starting further actions.
3. Reject completion and obsolete deliverables from the superseded objective.
4. Queue the revision under the same Goal ID, retaining transcript and selected earlier tool evidence.
5. Start with the remaining total budget and mark the applicable revision `applied`. New graph nodes and report namespaces distinguish revisions.

Stopping cancels pending revisions as well as the active execution. Late callbacks from cancelled or settled executions cannot change the final record. Cancelling a queued Goal removes it without starting its runner; cancelling a running Goal signals the runner and keeps its execution slot until it settles.

## Planning and action DAGs

[HarnessPipeline](src/engine/pipeline/HarnessPipeline.ts) orchestrates discovery, triage, knowledge lookup, model planning, and execution with verification. A failed assessment can return to knowledge lookup and planning with its failure reason and next hypothesis. Exhausting new KB matches alone does not exhaust possible observations.

Planning may return an acceptance plan and an `action-plan` containing:

| Field | Meaning |
| --- | --- |
| `id` | Unique action identifier within the round |
| `title` | Human-readable action title |
| `dependsOn` | IDs of prerequisite actions |
| `script` | Python source for this action |

[actionPlan.ts](src/engine/pipeline/actionPlan.ts) validates the entire graph before executing tools. Duplicate IDs, missing dependencies, cycles, and malformed explicit plans are rejected. An invalid explicit DAG is not silently treated as a single-script plan. Older single Python script responses remain supported when no explicit action plan is present.

Ready actions run concurrently. At action start, the script receives `REVERSELAB_INPUTS` containing its parent results and `REVERSELAB_PEER_EVIDENCE` containing available peer messages. The runtime records the actual bindings and script for later verification. Successful stdout is registered under evidence keys such as `actions.read.stdout`; tool records retain outputs and elapsed times.

A scheduler's DAG is immutable after construction. Subsequent planning creates a new DAG with new graph-node IDs, preserving previous attempts. Graph width follows actual independent actions and dependencies.

### Scheduling and cancellation

[DagScheduler](src/engine/runtime/dagScheduler.ts) supports any finite acyclic graph. GoalManager and the scheduler have no default concurrency cap; an embedding application may explicitly inject one. A node executes at most once within a scheduler run.

| Dependency policy | Ready when | Typical use |
| --- | --- | --- |
| `allSucceeded` | Every parent succeeded | Actions requiring parent artifacts |
| `allSettled` | Every parent reached a terminal state | Joins that inspect successes, failures, and cancellations |

A failed prerequisite cancels its dependent ordinary actions while unrelated actions continue. An `allSettled` join receives all direct parent results. Branch cancellation propagates through ordinary descendants and stops at such joins; global cancellation covers the entire DAG.

Node states are `queued`, `running`, `succeeded`, `failed`, and `cancelled`. An abort request does not itself prove that a process has stopped: the runner keeps its slot and resource ownership until it resolves or rejects. Observer exceptions are reported separately from tool failures.

The scheduler supports exclusive `resourceKeys` and an injected `DagResourcePool`. The same pool can serialize access across schedulers. The generated action schema currently supplies neither resource keys nor a shared workspace pool; device and debugger integrations must connect these facilities when needed. These locks are in-process, not cross-process locks.

## Evidence exchange and repeat detection

[AgentMessageBus](src/engine/runtime/agentMessages.ts) routes messages between registered agents of one Goal. Messages carry sender, recipient, type, optional correlation ID, and evidence references. Supported types are `evidence`, `question`, `answer`, `blocked`, and `result`. Accepted payloads are copied and frozen; duplicate IDs are not redelivered.

Both publishes action observations, KB references, blocking reasons, and branch results. Planning reads peer messages, and actions read available peer observations at execution time. Evidence-node references become cross-links in the canvas. Matching action fingerprints can share one execution Promise within the both run; each strategy still evaluates the output independently.

Action fingerprints include target, script, parent observations, and peer observations. [Observation identity](src/engine/pipeline/observationIdentity.ts) normalizes JSON key order and excludes transport receipt IDs, graph-node IDs, and runner durations from peer-observation identity. The same script and inputs are not re-executed merely because another KB document was selected. Single-script plans also normalize comments and blank lines for duplicate detection.

The route ledger compares failure category, observation fingerprint, and selected references. A repeated unchanged failure on the same route stops that loop. A similar symptom on a different candidate route remains visible while other candidates can still be attempted. A new document, timestamp, or rewritten summary alone is not evidence of progress.

This is input-based repeat detection, not semantic equivalence analysis. Changed but equivalent programs can still evade exact comparison; general target-version and evidence-freshness tracking remains incomplete.

## Independent Goal verification

| Result | What it records |
| --- | --- |
| Tool execution succeeded | The process or adapter completed successfully |
| Evidence accepted | The observation satisfies the strategy's evidence checks |
| Goal verified | The fixed acceptance criteria passed independent assessment |

[goalVerifier.ts](src/engine/pipeline/goalVerifier.ts) binds the first valid acceptance plan to the current target and objective before execution. Checks contain `id`, `criterion`, and `expected`; later route attempts retain that plan. A user revision starts a new plan for the revised objective.

Explicit SHA256 objectives have a deterministic path that compares the observed result with independently obtained triage data. Other objectives use a separate model request with the original objective, fixed checks, actual execution program and input bindings, and tool evidence. It returns `verified` or `continue`, plus per-check observations and evidence quotations. Model assessment is recorded as `model_assessed`.

The runtime requires exactly the planned check IDs. A passing check must cite a supplied evidence key and quote text present in its source. Missing checks, invented references, absent quotations, or incomplete coverage keep the Goal unverified and provide feedback for further work. A script's own `passed: true` value is not a completion signal.

Quoted evidence and the collection program are assessed together; model instructions treat target content, KB text, and stdout as data. These inputs do not change the bound objective or acceptance plan. Valid quotation checks establish provenance within the supplied output; the model's semantic assessment still requires appropriate live acceptance tests.

For both, scoped verdicts retain separate responsibilities. Combined verification prefixes each strategy's check and evidence IDs and assesses full-objective coverage. One branch's success cannot stand in for the other branch.

## Budgets and terminal states

`maxDurationMs` and `maxTokens` are independent optional fields. Omitted fields mean no total limit and are omitted from persisted request budgets. Model calls omit output-token and request-time limits when no finite remaining budget exists.

Pipeline deadlines use monotonic time. Requests and actions receive the remaining duration when a total deadline exists. Goal revisions deduct earlier elapsed time and token use; changing routes does not reset consumption.

Triage and Python execution have no default tool deadline. The bridge passes a finite remaining Goal duration when configured; otherwise it omits the timeout. An exhausted duration is rejected before dispatch. Cancellation or expiry terminates the Python process tree in native and browser development execution. Tool transports preserve output without a default 4 MiB truncation or buffer-stop limit.

Token accounting includes planning and independent verification. Provider usage replaces estimates when available; otherwise the runtime marks usage as estimated. Without complete provider usage and exact input counting, a user-supplied token budget is an estimated control.

For a finite both token budget, the coordinator reserves up to one third, capped at 8,192 tokens, for combined verification. The remaining allocation is divided between red and blue, with the odd remainder going to blue. After one strategy finishes, the other can use its unspent allocation through the coordinator. The final check includes both branches' consumption. No reserve is taken for an unlimited budget or the built-in hash path.

`RunProgress` uses these actual statuses:

| Status | Meaning |
| --- | --- |
| `running` | Executing, including a handoff to a pending revision |
| `completed` | The current objective passed its required verification |
| `exhausted` | A configured time or token budget was consumed |
| `blocked` | Required capability, evidence, viable route, or valid output is unavailable |
| `cancelled` | The user stopped the run |

The reason and health code distinguish budget exhaustion, unavailable services, repeated failures, and other blockers. A summary checkpoint retains target, objective, track, visited references, action fingerprints, and blocking reasons. It does not serialize live processes or provide automatic execution resumption after application restart.

## Events, presentation, and diagnostics

Callbacks emit steps, tool records, stage diagnostics, deliverables, run progress, and [health events](src/core/contracts/health.ts). Health events identify the Goal, branch, agent, node, status, code, and optional duration. [HealthMonitor](src/services/health/healthMonitor.ts) summarizes retained observations; recovery on one trace does not erase failure on another. Unobserved layers remain `unknown`.

The transcript renders analysis progress and expandable plans, scripts, output, and verification details. The canvas uses actual dependency and evidence edges, preserving failed attempts and subsequent routes. These views do not infer success from node count or report existence.

Workspace runtime connects new accepted health events to the optional diagnostic receiver. Historical restoration and view rendering remain local. Sentry sends sanitized errors and sampled operation timings only after the user enables it; disabling cancels in-flight submissions. Native performance warnings use a separate background sampler. See [DIAGNOSTICS.md](DIAGNOSTICS.md).

## Current implementation boundaries

- The direct execution adapters provide target triage and Python processes. Scripts can invoke installed libraries and CLI tools with the current user's permissions. Dedicated debugger sessions, device control, and hardening adapters require integration with the same execution and cancellation contracts.
- Agent mailboxes currently retain 128 history entries and 64 entries per inbox, accept up to 512 messages per bus, and allow 8 correlated hops. The limits are configurable in the bus API; they are not Goal or action concurrency caps.
- Model evidence input uses excerpts: independent verification currently divides 16,000 characters among available stdout sources. Full tool records and saved scripts have a separate role from the verifier's selected input.
- Dynamic planning occurs between DAG executions. The UI does not edit arbitrary active graphs or create arbitrary Agent roles.
- Runtime snapshots restore history and interruption status, not live execution. Universal evidence freshness, semantic action deduplication, and cross-tool hypothesis search are still incomplete.
- BLA / REA profiles define acceptance work; completed upstream adversarial validation is not claimed. See [ADVERSARIAL_PROFILES.md](ADVERSARIAL_PROFILES.md).

## Verification when changing the runtime

Use the existing [development checks](DEV_GUIDE.md), and cover the behavior affected by a change:

- Concurrent Goals and action forks remain isolated; cancelling one leaves unrelated work running.
- Invalid DAGs never start tools; joins receive all parent outcomes; resource locks remain held until cancellation settles.
- Both preserves scoped verdicts, cross-strategy evidence, and one shared budget.
- Revisions retain history and budget use; an obsolete result cannot complete the revised objective.
- Duplicate actions, unchanged failures, malformed plans, false success output, and unsupported evidence cannot silently pass.
- Model, KB, tool, and storage failures remain identifiable; missing usage is marked estimated.
- Reports retain their workspace ownership; restored interrupted runs remain interrupted.
- Proxy cancellation and failover preserve request semantics; optional diagnostics do not send historical data or continue after being disabled.

The [Goal tests](src/services/goals/goalManager.test.mjs), [pipeline tests](src/engine/tests/pipeline.test.mjs), [scheduler tests](src/engine/tests/dagScheduler.test.mjs), and [message tests](tests/agentMessages.test.ts) exercise synthetic cases. Live model behavior and adversarial targets require their own evidence.
