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

Every model request snapshots its route candidates. Failed nodes cool down for 30 seconds, except an explicitly fixed node can be retried immediately. An empty or failed pool returns an error; it never silently sends traffic directly. Responses that have begun streaming are not replayed. HTTP errors returned by the model are handled by the Goal runtime, not by changing proxies. Timeouts after sending a request do not automatically retry its body.

Python receives proxy variables only in its own child environment, plus an explicit urllib opener. This covers clients that honor these variables and the built-in URL triage. Scripts that create their own transport or raw sockets can bypass that setting; it is not a network sandbox. SOCKS nodes are supported for model transport; Python target routing currently requires HTTP(S). The updater, optional Sentry diagnostics, and independently launched MCP clients retain their own network configuration.

Changes apply to subsequent requests and executions. Existing streams and child processes retain the route they started with. Browser preview allows editing; proxy testing and enforced routing require the desktop app. The browser uses its own network settings in system mode.

## Data and failure handling

Nodes and credentials are saved in local WebView storage, without OS-keychain encryption. They are not included in Goal prompts, reports, or workspace records. Child process output redacts configured proxy credentials; avoid printing sensitive environment variables from custom scripts. Node tests report only status and latency. Network errors use stable `PROXY_*` / `NETWORK_*` codes; see [error codes](ERROR_CODES.md).

Background performance warnings and optional remote diagnostics are configured separately in **Settings → Diagnostics**. See [Diagnostics](DIAGNOSTICS.md), or return to the [desktop guide](README.md).
