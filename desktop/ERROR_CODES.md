# Health events and error codes

[简体中文](ERROR_CODES.zh-CN.md) · [Agent runtime](AGENT_SYSTEM.md)

Execution emits [HealthEvent](src/core/contracts/health.ts) records, aggregated by [HealthMonitor](src/services/health/healthMonitor.ts). The view groups observations into Goal, Agent, model, knowledge, tool, and storage layers. A layer without observations remains `unknown`.

Events contain `eventId`, `goalId`, `layer`, `status`, and a timestamp. Optional fields identify a branch, agent, node, or correlation, and record duration, error code, recovery advice, and details. Each monitor accepts events for its own Goal. Its default retained history is 256 events, configurable through `maxHistory`; total observation counts remain separate from the retained window.

Snapshots combine the latest event of each branch/agent/node trace within the retained window. A recovered trace does not hide another trace's failure. If a layer has no remaining events in that window, the snapshot uses its last recorded event.

## Error codes

| Code | Layer | Meaning | Recovery advice |
| --- | --- | --- | --- |
| INPUT_INVALID | goal | Input does not meet execution requirements | Revise the input |
| MODEL_AUTH | model | Model authentication or access failed | Check provider configuration |
| MODEL_QUOTA | model | Account quota is exhausted | Check account balance or quota |
| MODEL_RATE_LIMIT | model | Provider rate limit reached | Retry after the rate limit clears |
| MODEL_TIMEOUT | model | Model response timed out | Check the connection and retry |
| MODEL_UNAVAILABLE | model | Model or its connection is unavailable | Use another service or route |
| PROXY_CONFIG | model / tool | Proxy configuration is invalid | Correct the proxy pool configuration |
| PROXY_CONNECT | model / tool | Connection to the proxy failed | Select another node |
| PROXY_AUTH | model / tool | Proxy authentication failed | Correct the node credentials |
| PROXY_UNAVAILABLE | model / tool | No enabled proxy node is available | Check nodes or wait for cooldown |
| NETWORK_TIMEOUT | model / tool | Network request timed out | Check the connection and retry |
| NETWORK_FAILED | model / tool | An established request was interrupted | Inspect the result before resending |
| KB_UNAVAILABLE | kb | Knowledge service is unavailable | Check the knowledge configuration |
| KB_DOC_MISSING | kb | An indexed document is missing | Select another reference |
| TOOL_MISSING | tool | An execution dependency is missing | Check local tool configuration |
| TOOL_TIMEOUT | tool | Tool execution timed out | Reconsider the budget or route |
| TOOL_FAILED | tool | Tool execution failed | Try another route |
| TOOL_UNAVAILABLE | tool | Execution service cannot be reached or refuses the request | Restore the service before retrying |
| EVIDENCE_INVALID | agent | Evidence is insufficient or fails acceptance checks | Collect further independent observations |
| LOOP_DETECTED | agent | An action or unchanged failure is repeating | Choose a different route |
| BUDGET_TIME | goal | A configured time budget is exhausted | Stop and retain records |
| BUDGET_TOKENS | goal | A configured token budget is exhausted | Stop and retain records |
| USER_CANCELLED | goal | The user stopped execution | Cancel execution |
| STORAGE_FAILED | storage | Report or Goal persistence failed | Check the disk and permissions |
| UNKNOWN | Original layer | Failure has not been classified | Inspect the details |

`retryable` and `recovery` describe scheduling advice; they do not record an executed retry. Recovery values are `retry`, `alternate`, `configure`, `revise`, `stop`, and `inspect`. Authentication failures and exhausted account quota are not classified as retryable rate limits.

Sources can raise `HealthFault` with an explicit code. Classification prefers an explicit code, then uses HTTP status and known error text. Proxy and network codes retain the originating layer. Goal budgets are optional; the presence of a budget error code does not imply a default limit.

## Status and results

| Status | Meaning |
| --- | --- |
| `unknown` | No observation is available; this is a snapshot state |
| `running` | The observed operation has started |
| `healthy` | The observed operation succeeded |
| `degraded` | The observation reports a warning or impediment |
| `failed` | The observation reports a failure |
| `cancelled` | The observed operation was cancelled |

Tool execution, evidence acceptance, and Goal completion are recorded separately. Model stages, knowledge reads, Python execution, report writes, and Goal stop reasons emit their own events. Local tool detection invokes Python to inspect the runtime, modules, and PATH. Asynchronous workspace persistence failures appear separately in the health view; in-memory records remain available.

Restored events describe the earlier run. The health monitor does not periodically probe external service readiness. Optional native performance sampling and Sentry reporting have their own switches and lifecycle, described in [DIAGNOSTICS.md](DIAGNOSTICS.md). Storage and recovery behavior is described in [WORKSPACES.md](WORKSPACES.md).
