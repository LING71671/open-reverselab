# Goal execution

[简体中文](GOALS.zh-CN.md)

A Goal keeps its target, objective, execution history, evidence, and reports together. The body and canvas show the same record. Time and token limits are optional; leaving both blank adds no Goal-wide quota. Individual tools and network operations retain their own timeouts.

## Titles and manual names

The planning model summarizes the task into a short title in its existing response. No separate title request is made. The full objective stays in the first user message. A user name set by double-clicking a task or pressing F2 takes priority over generated titles. Local hash-only tasks use their operation name without calling a model.

## Instructions during execution

Submitting an instruction while a Goal is running adds a pending user message. The current pipeline stage finishes before the scheduler applies the instruction. Newer instructions take precedence where they conflict with older requirements. The target and red/blue/both track remain fixed; another target uses another Goal.

The next revision receives the earlier conversation and tool evidence as context, creates a new acceptance plan for the updated objective, and runs under the same Goal identity. Old callbacks cannot publish completion for the new revision. Graph nodes and saved reports distinguish revisions, preserving earlier evidence. Several instructions received during one stage are applied together.

Time and tokens already spent count toward any configured limits. Adjusting a Goal does not reset those limits. Stop cancels pending continuation. Reopening the application marks interrupted work as stopped instead of silently restarting it.

## Evidence and route changes

Knowledge retrieval supplies references. Finding no new matches does not mean that all analysis routes have been exhausted: the agent can repair an action or examine new evidence. Repeated failures with unchanged evidence on the same route stop the loop.

Plans accept a `goal-plan` block, a JSON block, or a leading JSON object with the same validated check schema. The target and objective come from the Goal, not from model-authored JSON. Completion requires tool output and an independent assessment against the fixed checks; a generated script alone is not a completed result.

## Checks

Run from the repository root:

```sh
node --test desktop/src/services/goals/goalManager.test.mjs desktop/src/engine/tests/pipeline.test.mjs
pnpm --dir desktop build
```

These checks cover isolation, queuing, cancellation, optional quotas, adjustment boundaries, evidence preservation, title ownership, and failed-route recovery. Provider and desktop integration still require an actual model and tool run.
