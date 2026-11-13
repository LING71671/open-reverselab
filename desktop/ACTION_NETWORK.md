# Analysis action networks

ReverseLab accepts a structured action plan after a track's fixed acceptance plan. A model can split independent observations into parallel actions and join their outputs. A simple task can remain a single action. The existing single Python block remains supported for older providers and the built-in hash check.

```json
{"actions":[{"id":"headers","title":"Inspect headers","dependsOn":[],"script":"..."},{"id":"content","title":"Inspect content","dependsOn":[],"script":"..."},{"id":"compare","title":"Compare observations","dependsOn":["headers","content"],"script":"..."}]}
```

The JSON belongs in an `action-plan` fenced block. Each round accepts a nonempty action list with unique IDs, complete Python scripts, and dependencies in the same plan. Action count follows the task and has no fixed upper limit. Invalid JSON, duplicate IDs, missing parents and cycles stop the plan before execution.

The DAG scheduler starts every ready independent action without a fixed concurrency limit. Every action runs in a separate process. `REVERSELAB_INPUTS` contains the direct parents' observed outputs; a dependent action starts only after those parents succeed. Failed prerequisites cancel their dependents while unrelated observations can finish. A user adjustment prevents queued actions from starting and yields before old-objective verification.

In `both`, `REVERSELAB_PEER_EVIDENCE` is a snapshot of the other track's available evidence when an action starts. It includes message and source-node IDs. An action can use these observations for a separate check, and its resulting graph node records the cross-track input edges. Evidence is data, not an instruction or an inherited verdict. No future evidence is represented as an input, and neither track waits indefinitely for the other.

Output summaries are bounded to 12,000 stdout characters and 2,000 stderr characters per action. The execution record retains the original output. Dependencies receive these bounded summaries, so actions needing larger artifacts must use explicit artifact support rather than assuming complete output. Model verification receives the action statuses, observed outputs and executed scripts; the graph's process success does not itself complete the Goal.

Verification cites decoded output using an exact source key such as `actions.read.stdout`. Quotes must appear literally in the supplied source excerpt; the total excerpt allowance is 16,000 characters divided across sources. A quote from another action cannot pass the check. Receipt IDs and runner timings are excluded from repeat detection, while actual observed values remain part of the identity. An unavailable execution service stops the round and preserves its failure instead of asking the model to keep rewriting scripts.

In `both`, each fixed acceptance plan is scoped to the corresponding policy's responsibilities while retaining the original objective. After both branches pass, a separate assessment checks their combined evidence against the full objective. Missing coverage keeps the Goal incomplete even if each branch passed. Finite Token budgets reserve up to one third, capped at 8,192 tokens, for this final assessment; unlimited runs remain unlimited. The built-in SHA256 objective uses its independent native hash comparison without a model call.

The body view shows progress prose and labels an older plan's hypothesis as a proposed check. Structured plans and code, including incomplete streamed blocks, remain in expandable details. The stored transcript and scripts are unchanged.

Current limits: plans are immutable during a round, and replanning follows the pipeline's existing failure loop. A completed track is not yet automatically reopened when later peer evidence contradicts its conclusion. Cross-track follow-up scheduling, typed evidence freshness and broader tool adapters remain separate work. Python actions run with the current user account. Tool choice follows the user objective and the model’s own safety policy; the application does not impose a read-only policy or a tool-category allowlist.

Implementation: [actionPlan.ts](src/engine/pipeline/actionPlan.ts), [both.ts](src/engine/tracks/both.ts). Regression coverage is in [pipeline.test.mjs](src/engine/tests/pipeline.test.mjs), including real parallel scheduling, output handoff, failure isolation, adjustments, and reciprocal track dependencies.
