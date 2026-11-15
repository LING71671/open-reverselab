---
name: create-reverselab-extension
description: Create or extend Open ReverseLab knowledge packs, attack and defense networks, MCP connection descriptors, and GitHub extension catalogs. Prepare reviewable source and ZIP artifacts against the stable v1 contract.
---

# Create Open ReverseLab extensions

[简体中文](SKILL.zh-CN.md)

Build the requested extension, preserving existing knowledge and stable IDs. Use the **stable v1 contract** accepted by the desktop Extensions page. Report structural checks, actual import/export checks, and live MCP checks separately.

## Choose the output

- **Knowledge:** documents, methods, attack/defense networks, evidence conditions, and optional tool bindings.
- **MCP:** a connection descriptor for an existing server and the inputs it needs. Implement a new MCP server only when the user requests one.
- **Catalog:** a `reverselab.registry.json` listing knowledge and MCP entries in a GitHub repository. A repository may contain either kind or both.

Read [the contract](references/contract.md) for the selected output. Use [assets/integrity-pack](assets/integrity-pack/) as a working knowledge example, replacing its synthetic content with the requested material. The example demonstrates format, not an attack/defense coverage target.

[assets/http-mcp](assets/http-mcp/) is a connection preset requiring the user's endpoint. [assets/reverselab.registry.json](assets/reverselab.registry.json) lists both examples using repository-relative paths; copy that directory's contents to a new catalog repository root when needed.

## Author the extension

Infer the namespace, domain, language, and intended audience from the repository and request. Ask only for material missing information. Keep a working copy when converting an existing knowledge base; map its legacy paths to stable IDs. Use a new derived pack identity when exporting only part of another pack.

For knowledge, keep readable articles separate from structured methods. Record actual prerequisites, required evidence, expected outputs, failure conditions, tool requirements, and provenance. Preserve useful runnable examples and clearly state their environment. Do not invent execution results, tool names, defense coverage, or verification status. Shared methods can be reused by both tracks; red and blue have independent network entrypoints and can cross-reference each other. Do not force every graph into two lanes or mirror every red article into a shallow blue duplicate.

For MCP, inspect the server's documented transport, installation/version requirements, and real input schemas before describing bindings. Use standard MCP, with an independently configured connection. Store configuration input names and credential references, never a working credential. Importing a descriptor is not starting a server. If only the descriptor was checked, report that connection and tool invocation remain untested.

For a catalog, list actual pack paths or versioned artifact URLs. Keep source/ref/digest information consistent with the delivered package. Do not publish fabricated release URLs or checksums. A GitHub repository URL and its downloaded ZIP must resolve to the same manifest and authored content.

## Check and package

The helper is relative to this skill directory and requires Python 3.11+ with no third-party packages:

```sh
python scripts/package_extension.py check path/to/pack
python scripts/package_extension.py build path/to/pack path/to/extension.zip
python scripts/package_extension.py check path/to/extension.zip
python scripts/package_extension.py migrate path/to/draft.zip path/to/v1.zip
```

The helper copies the desktop's canonical `scripts/misc/extension_protocol.py`. It validates the stable structure, explicit file list, IDs, references, conditions, required features, MCP descriptors, and archive hashes. Dependencies use exact versions. It also provides three-valued `evaluate_condition` for local checks. Dependency activation and live MCP behavior belong to the runtime services. Fix the affected artifact when checks fail; do not weaken validation. A v1-draft package requires explicit migration, including validation of any existing lock before conversion.

Review domain semantics separately: referenced evidence must support the method, relationship direction must be correct, and a detection method must not be described as prevention. Test runnable examples only within the task's requested environment. Keep real task evidence and histories outside the reusable package. For catalogs, parse JSON, resolve relative paths at the selected commit, and check entry identity/version/digest against the referenced package.

Deliver the source directory, ZIP, computed SHA256, and the checks performed. Use an existing publisher license where applicable. Publishing a repository, release, or external message requires the user's corresponding instruction; authoring alone does not imply it. Test the desktop importer through local source/ZIP and export/reimport; test GitHub import when a real requested source exists. Do not invent a published URL to claim that check. The importer can read a local package directory, including a source checkout's `kb` package; merely cloning a repository does not install its knowledge in the desktop.
