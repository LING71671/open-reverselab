# Knowledge and MCP extensions

[简体中文](EXTENSIONS.zh-CN.md)

Status: design proposal for [issue #24](https://github.com/LING71671/open-reverselab/issues/24). The desktop does not yet implement the marketplace, GitHub/ZIP importer, or the contract described here. The authoring skill and its offline packaging helper are available for preparing draft packages.

## Distribution and ownership

Open ReverseLab will install knowledge and tools independently of the desktop. A knowledge update, new domain, attack network, defense network, or MCP connection should not require rebuilding the application.

| Component | Owns | Updates independently |
| --- | --- | --- |
| Desktop runtime | Workspaces, Goals, scheduling, evidence, package manager, MCP client | Application |
| Knowledge pack | Documents, methods, signals, prerequisites, attack/defense networks, relationships, tool bindings | Pack |
| MCP extension | Server connection or installation descriptor, configuration inputs | Server/preset |
| Repository catalog | Searchable metadata and references to knowledge and MCP extensions | Catalog |

KnowledgeStore and ToolRegistry are separate services. Packs can be read and searched without a connected MCP server. MCP tools can be used without a corresponding knowledge pack. Bindings can associate several servers with a method or several packs with a server.

`red` and `blue` retain separate methods and network entrypoints; `shared` contains reusable facts and techniques. `both` composes the installed networks and exchanges evidence across them. It is a runtime strategy, not another copy of the knowledge base or a fixed pair of lanes.

## Import through GitHub or ZIP

The application will expose an **Extensions** page with **Knowledge**, **MCP**, **Installed**, and **Sources** views. Its primary actions are **Add GitHub link** and **Import ZIP**. A source may contain one extension or a catalog of many extensions.

| Input | Resolution |
| --- | --- |
| GitHub repository URL | Inspect `reverselab.registry.json`; otherwise inspect a root extension manifest |
| GitHub tree/folder or manifest URL | Resolve the selected path at its ref and inspect that extension/catalog |
| GitHub release ZIP URL | Download that artifact and inspect its manifest |
| Local ZIP | Accept a package root or a single enclosing directory, as in GitHub source archives |

Inspection displays the source, kind, version, content summary, dependencies, and configuration required before installation. If a repository contains multiple candidates without a catalog, show the candidates instead of silently choosing the first one. Resolve branch/tag names using GitHub metadata, including refs containing slashes; record the resulting commit and subdirectory. Private repository credentials belong to local source settings.

Catalog browsing fetches metadata first. Installing an entry fetches only its selected artifact or pack contents. GitHub URLs and ZIPs converge on the same validation and activation path. Missing manifests produce an actionable result: select a contained manifest, or convert ordinary Markdown to a document collection. Conversion preserves the text and does not invent method relations or execution prerequisites.

Repository catalogs are static JSON and can be hosted in an ordinary GitHub repository. The initial product does not require a centralized marketplace service. Official and user-added sources use the same format; an entry's publisher field alone does not establish ownership of a namespace.

## Contract and identity

The [authoring contract](tools/skills/create-reverselab-extension/references/contract.md) defines draft manifests, catalog entries, method/network records, and ZIP contents. Its draft identifier is `open-reverselab.extension/v1-draft`; a production importer must not silently treat that identifier as a stable v1 contract.

Use independent versions for the extension contract, catalog contract, pack content, application, and negotiated MCP protocol. A pack owns a namespace and stable method/document/network IDs. IDs survive translations, renamed files, and title edits. References resolve against a lock containing source identity, pack ID, exact version, and digest. Two sources claiming the same pack ID do not silently replace each other.

Methods describe signals, prerequisites, required evidence, expected outputs, tool capabilities, and supporting documents. Networks refer to those methods and express typed relations: `depends_on`, `enables`, `composes_with`, `defends`, `detects`, `verifies`, and `conflicts`. Domains and entrypoints come from package data rather than a built-in list of four boards.

Conditions use declarative `all`, `any`, `not`, and evidence predicates. Missing evidence evaluates to unknown, not success or failure. The planner resolves unknown prerequisites before selecting an executable action. Documentation may include scripts and code examples; importing or reading a pack does not execute them.

Knowledge graphs may have feedback cycles. An execution round materializes a dependency DAG using the current evidence and selected methods; that DAG must be acyclic. A feedback edge becomes a later round after the prerequisite evidence changes. Parallel branches, joins, cross-domain routes, conflicting results, and defense coverage gaps remain explicit.

## Updates, export, and runtime evidence

Import stages files, validates the supported contract and references, resolves dependencies, builds an index, then activates the new version atomically. Failure or cancellation leaves the previous active version available. Archive paths must stay inside the staging directory; reject absolute paths, traversal, links, duplicate entries, and names that collide on supported filesystems. Expose progress and cancellation rather than silently truncating large packs.

Each Goal pins the resolved pack versions and tool inventory/schema fingerprints. Updating a pack affects new Goals; switching an active Goal requires a recorded replan at an execution boundary. Retain versions referenced by unfinished or replayable runs. Disabled packs leave the selected search catalog; removing one reports dependent packages and retained run references.

Support both complete-pack export and selected-subgraph export. The latter carries its documents, prerequisites, relations, and dependency closure, and receives a derived pack ID with original IDs recorded as provenance. It must not claim to be the original complete pack. Include redistributable dependencies or exact locked references; missing required dependencies prevent activation. Optional unresolved links remain visible as unavailable.

Knowledge exports contain authored knowledge. Workspace evidence, task histories, targets, and model credentials remain workspace data. MCP configuration exports contain input names and credential references, not resolved credential values.

Execution evidence records the Goal/target revision, method ID, pack digest, invocation ID, observation source, and result status. Expected outputs are distinct from observed results. Reports preserve verified, unverified, unobservable, and conflicting evidence. Replanning compares method, inputs, evidence revision, tool version, and previous failure before repeating an unchanged action. There is no protocol-level cap on concurrent branches or Goal duration.

Unknown optional extension fields survive round trips; unknown required capabilities or unsupported contract versions prevent activation. Production schemas will use [JSON Schema 2020-12](https://json-schema.org/draft/2020-12), supplemented by reference and semantic checks. The current helper checks a documented authoring subset; it is not the future desktop validator.

## MCP integration

MCP retains its standard wire protocol. Open ReverseLab adds package metadata and knowledge semantics around it. Clients use the server's advertised capabilities, paginated [tool discovery](https://modelcontextprotocol.io/specification/2025-11-25/server/tools), input/output schemas, cancellation, and change notifications. Connections use standard [stdio or Streamable HTTP transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports). A catalog can later adapt the official registry's [`server.json` metadata](https://modelcontextprotocol.io/registry/about), without copying its wire protocol or promising that every package manager is already supported.

There are two independent directions:

1. **Desktop as MCP client.** Add a server, collect its configuration, connect, and discover its tools/resources. Resolve tools as `connection_id/tool_name`; the same tool name on two servers must not collide. Refresh changed schemas before invocation. A lost connection with an unknown action outcome must not trigger an automatic replay of that action. Adding a repository or knowledge pack never starts an MCP process; connecting/installing a selected MCP entry is a distinct user action.
2. **KnowledgeStore as MCP server.** Proposed `kb_search`, `kb_get`, `kb_neighbors`, `kb_resolve`, and `kb_list_packs` return the same IDs, version locks, and provenance as the desktop and CLI. Existing `kb_router` and `kb_read_file` remain compatibility adapters. Versioned [resources](https://modelcontextprotocol.io/specification/2025-11-25/server/resources) expose documents and networks. Import/export management uses explicit operations and cancellable jobs, separate from search and reading.

Knowledge bindings describe capability requirements and schema-compatible argument/evidence mappings. A missing binding does not prohibit generic MCP use. A missing tool marks the associated method unavailable and allows the planner to choose another route. Packages supply task data; they do not replace the user's Goal or the host's runtime instructions.

## Authoring skill

Use [create-reverselab-extension](tools/skills/create-reverselab-extension/SKILL.md) to create or extend a knowledge pack, an MCP descriptor, or a repository catalog. It includes a working synthetic knowledge template, contract reference, and a standard-library Python helper for checking and packaging explicit files.

The skill should produce both a reviewable source directory and a ZIP from the same manifest. GitHub publishing is a separate action under the user's requested repository and ref. The helper is usable now; an application import test must wait for the importer implementation and must not be reported as passed from an offline package check.

## Migration and delivery batches

| Batch | Work and completion evidence |
| --- | --- |
| 1. Contract and compatibility | Schemas, stable IDs, legacy Markdown/index adapter, source-qualified references, migration round trip; a new third-party domain needs no application edit |
| 2. Knowledge package manager | GitHub and ZIP import, dependency resolution, atomic updates, full/subgraph export, source catalog UI; cancellation and malformed archive cases preserve installed data |
| 3. MCP extensions | Independent server manager, stdio/HTTP adapters, configuration inputs, tool/resource discovery, mappings, reconnect/cancel behavior; knowledge usable without MCP and MCP usable without a pack |
| 4. Network composition | Move complete attack/defense networks and routing metadata into packs; synthetic cross-domain parallel/join/conflict/replan and blue coverage-gap examples drive both planner and canvas |
| 5. Independent releases | Desktop runtime allowlist for both NSIS and portable ZIP; separately versioned knowledge artifacts, import/export instructions, source catalogs, and a new desktop release tag |

Current migration points are `scripts/misc/kb_layout.py`, `desktop_kb.py`, `kb_router.py`, `kb/catalog/`, `desktop/src/engine/pipeline/kbSelection.ts`, `KbRoutingStage.ts`, and `harnessGraph.ts`. Current document IDs depend on board/filename, and routing still contains fixed board/path assumptions. Preserve legacy aliases while migrating to stable source-qualified IDs.

`scripts/misc/package_desktop_release.py` currently includes `kb` in installer resources and copies the tracked source into the portable archive. Both paths must change to an explicit runtime manifest; removing Markdown from only one archive is insufficient. Packs can initially remain in this monorepo with independent artifacts/tags, then move to separate repositories without changing their IDs or contract.

Issue #24 stays open until the corresponding runtime, migration, and acceptance cases exist. This proposal and authoring helper do not complete those implementation items.
