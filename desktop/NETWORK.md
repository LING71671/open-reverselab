# Proxy pools

[简体中文](NETWORK.zh-CN.md)

## Configure a proxy pool

Open **Settings → Proxy pool**. Add named HTTP, HTTPS, SOCKS5 or SOCKS5h nodes, enter authentication in the separate username/password fields, and enable the nodes to use. Save the configuration. Test one node or all enabled nodes against an HTTP(S) URL you choose; a test sends a GET through that node and reports response-header latency. Bulk tests use two workers.

Model requests and Python target access have independent policies. Both default to the system route.

| Policy | Model requests | Python target access |
| --- | --- | --- |
| System | Native system/environment proxy selection | Inherit the child process environment |
| Direct | Explicitly bypass proxies | Clear proxy variables and configure urllib for direct access |
| Fixed node | One enabled node | One enabled HTTP(S) node |
| Failover | Try enabled nodes in order on connection failure or proxy authentication rejection | Unavailable: scripts are not replayed |
| Round robin | Rotate the first node for each request; try remaining candidates on connection failure | Rotate enabled HTTP(S) nodes for each execution |

Every model request snapshots its route candidates. Failed nodes cool down for 30 seconds, except an explicitly fixed node can be retried immediately. An empty or failed pool returns an error; it never silently sends traffic directly. The transport does not switch proxies after a response starts streaming. The Goal runtime handles interrupted model inference and HTTP failures as described below.

Python receives proxy variables only in its own child environment, plus an explicit urllib opener. This covers clients that honor these variables and the built-in URL triage. Scripts that create their own transport or raw sockets can bypass that setting; it is not a network sandbox. SOCKS nodes are supported for model transport; Python target routing currently requires HTTP(S). The updater, optional Sentry diagnostics, and independently launched MCP clients retain their own network configuration.

Changes apply to subsequent requests and executions. Existing streams and child processes retain the route they started with. Browser preview allows editing; proxy testing and enforced routing require the desktop app. The browser uses its own network settings in system mode.

The node editor validates addresses and credentials when you select **Done**. Saving validates both routing policies together. Before disabling or removing a fixed node, select another enabled node or change that policy explicitly. A failed save retains the previously active route. Tests that finish after a node's address or credentials change do not overwrite its new health state.

## Model reconnection

While the application remains open, planning and independent verification retain their Goal context during temporary connection failures. The current card shows a reconnect message and stays active. Requests retry after 2, 4, 8, 16, then 30 seconds, with no retry-count limit; a provider's `Retry-After` is respected. An offline event interrupts a stalled request, and an online event wakes the connection wait. Known offline periods do not send model requests.

An interrupted response is regenerated from the same request context. Partial plans are replaced, and only a completed response can proceed to execution. Verification retries retain the existing tool evidence and do not execute Python or MCP actions again. Authentication, quota, invalid-input, and proxy-configuration failures stop with their actual error.

Stopping cancels the active request or wait. Revised requirements end the wait and return control to the existing Goal revision flow. Explicit time and token budgets still apply; repeated requests retain their usage, estimated when the provider did not report it. Reconnection does not restore live execution after closing the application.

## Data and failure handling

Nodes and credentials are saved in local WebView storage, without OS-keychain encryption. They are not included in Goal prompts, reports, or workspace records. Child process output redacts configured proxy credentials; avoid printing sensitive environment variables from custom scripts. Node tests report only status and latency. Network errors use stable `PROXY_*` / `NETWORK_*` codes; see [error codes](ERROR_CODES.md).

Background performance warnings and optional remote diagnostics are configured separately in **Settings → Diagnostics**. See [Diagnostics](DIAGNOSTICS.md), or return to the [desktop guide](README.md).

## Verification

From `desktop/`:

```sh
node --experimental-strip-types --test tests/proxyPool.test.ts
node --test tests/networkTransport.test.mjs src/engine/tests/pipeline.test.mjs
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib network::tests
```

The tests cover add/edit/enable/disable/remove persistence, invalid saves, independent routing policies, failover without direct fallback, cancellation, credential redaction, and stale probe results. Native loopback fixtures exercise HTTP proxy authentication and streaming, SOCKS5h authentication and remote DNS, and a real Python urllib request using only its child-process proxy environment. They do not contact a model provider or a target service.
