# Desktop development standards

The current visual specification is [DESIGN_BRIEF.md](DESIGN_BRIEF.md). It replaces the previous dark-only palette and decorative result overlays.

Keep React views separate from task scheduling, strategies, tool adapters and persistence. New behavior belongs in the narrow module that owns it. Red and blue policies must remain independent; both composes them through explicit callbacks and scoped messages.

Use TypeScript contracts from `src/core/contracts`. Engine code must not depend on UI components. Goal callbacks carry their original task identity. Never select a destination from the currently visible workspace during a background write.

Show actual states and evidence. Do not seed tool readiness, model connections, counts, task results, sample paths or progress. Keep the user's target and objective fixed during execution. Record limits and current adapter support in Markdown.

Add focused tests for queue isolation, dependency ordering, cancellation, persistence boundaries, budget behavior and verification. Avoid tests that merely repeat reversible styling changes. Run the relevant checks and the repository publication check before submission.

Private samples, logs, reports, workspace records, credentials and machine-specific paths stay outside public changes. Follow [PUBLICATION.md](../PUBLICATION.md).
