---
name: create-reverselab-extension
description: Create or extend Open ReverseLab knowledge packs, attack and defense networks, MCP connection descriptors, and GitHub extension catalogs. Prepare reviewable source and ZIP artifacts against the bundled draft contract.
---

# Create Open ReverseLab extensions

[简体中文](SKILL.zh-CN.md)

Build the extension the user requested, preserving existing knowledge and stable IDs. The bundled format is a **draft authoring contract**. The current desktop does not yet import these packages. Report offline validation separately from application compatibility.

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
```

It validates the local draft structure, explicit file list, IDs, local references, network entries, MCP descriptor shape, and archive digests. It does not resolve remote dependencies, validate a live MCP server, evaluate method conditions, or prove compatibility with a desktop importer. Read the helper's errors and fix the affected artifact; do not weaken its checks to make a malformed pack pass.

Review domain semantics separately: referenced evidence must support the method, relationship direction must be correct, and a detection method must not be described as prevention. Test runnable examples only within the task's requested environment. Keep real task evidence and histories outside the reusable package. For catalogs, parse JSON, resolve relative paths at the selected commit, and check entry identity/version/digest against the referenced package.

Deliver the source directory, ZIP, computed SHA256, and an accurate account of checks performed. Use an existing publisher license where applicable. Publishing a repository, release, or external message requires the user's corresponding instruction; authoring alone does not imply it. If the importer exists in the target checkout, additionally test GitHub and ZIP import plus export/reimport against that actual implementation.
