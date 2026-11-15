# Knowledge and MCP extensions

[简体中文](EXTENSIONS.zh-CN.md)

The desktop includes an **Extensions** page for installing knowledge packs and MCP descriptors independently. Desktop installer and portable resources use a runtime allowlist that excludes knowledge content and MCP servers.

## Install and manage

Open **Extensions** in the sidebar. **Knowledge** and **MCP** show installed entries; **Sources** stores catalogs to browse later.

From v2.0.0-beta2, the application includes **Open ReverseLab official knowledge** under **Sources**, pointing to `https://github.com/LING71671/open-reverselab-knowledge`. Choose **Browse**, then **Install**. The address is available offline and is also added to existing profiles; knowledge is downloaded only when requested. Removing the source is remembered, and it can be added again. In the published `v2.0.0-beta1`, add the same address manually.

1. Paste a GitHub repository, tree/folder, manifest, or release ZIP link and choose **Read**, or choose **Import ZIP**. Local package directories and ZIP paths also work.
2. Select an inspected entry and install it. Reading a source or installing an MCP descriptor does not start its server.
3. Enable, disable, remove, or export installed entries. Complete ZIP export can be imported again. Knowledge entries also support selecting networks for a derived ZIP containing their local method/document closure and dependency references.
4. For MCP, open **Configure**, fill the descriptor's inputs, save, and **Verify connection** to discover tools/resources. **Add connection** accepts a standalone stdio command/argument array or Streamable HTTP endpoint without a preset.

Browser development and the native application call the same Python services. Browser ZIP imports upload file bytes; native imports use a file picker. Exports use a native save dialog or browser download. Long operations expose cancellation and have no default overall job deadline; individual network/protocol exchanges retain bounded connection/read waits.

A source can contain one extension or a static `reverselab.registry.json` catalog containing both kinds. Add it under **Sources**, then **Browse**. Refreshing metadata does not replace an installed version. There is no centralized marketplace account or private-repository credential editor.

The importer resolves GitHub branch/tag paths, including slash-containing refs, records the commit and subdirectory, and validates selected files. Catalog entries reference a directory at the same commit, a separate GitHub package repository through `repository`, or an HTTPS artifact with SHA256. Repository entries resolve to the target repository identity and commit; installing through a catalog or directly uses the same identity. Ordinary Markdown must first be authored into a declared document collection; importing does not invent methods or relationships.

## Stable v1 contract

The [authoring contract](tools/skills/create-reverselab-extension/references/contract.md) and [canonical validator](scripts/misc/extension_protocol.py) define:

| File | Protocol | Purpose |
| --- | --- | --- |
| `reverselab.extension.json` | `open-reverselab.extension/v1` | Knowledge/MCP metadata and explicit payload files |
| `reverselab.registry.json` | `open-reverselab.registry/v1` | Repository catalog entries |
| `reverselab.lock.json` | `open-reverselab.lock/v1` | Exact manifest and payload hashes |

Content versions use SemVer. Dependencies name a source identity, package ID, and **exact version**; install required dependencies first. Missing required dependencies/entities, unsupported `requiredFeatures`, and unsupported versions block activation. Unknown optional metadata survives export. Draft packages need the explicit `migrate` command, which checks old hashes before conversion.

Installations are identified by source, package ID, version, and digest. Stable entity IDs resolve to `reverselab://<installationId>/<entityId>`. Two sources with the same declared package ID coexist without silently replacing each other. Legacy paths can remain aliases; ambiguous aliases require a source-qualified URI.

Knowledge contains documents, methods, domains, networks, and optional tool bindings. `red` and `blue` retain independent entrypoints; `shared` is available to either. `both` selects across installed tracks. Domains come from installed data.

Typed relations include `depends_on`, `enables`, `composes_with`, `defends`, `detects`, `verifies`, and `conflicts`. Conditions use `all`, `any`, `not`, and evidence predicates. The validator provides three-valued evaluation where missing evidence is unknown. These records are available to routing and Goal context; this does not promise that every graph is compiled into a complete condition-driven execution plan. Legacy document-network mappings record their provenance and preserve original articles.

## Storage, updates, and export

For knowledge installed from GitHub, choose **Check for updates** on its installed entry, then **Update to …**. Discovery checks the original repository's default branch and package path, including installations reached through a pinned catalog. Only a higher SemVer content version is offered; the update installs the exact commit inspected. Checking does not replace content. A failed update leaves the installed version active, and a disabled pack stays disabled after updating. Local folders and ZIPs use manual import of the new content.

The store uses `REVERSELAB_EXTENSIONS_DIR`, otherwise `REVERSELAB_DATA_DIR/extensions`, otherwise the user's `.open-reverselab/extensions`. MCP connection values are local application data, separate from package payloads. Python and third-party tools are installed separately.

Import validates paths, archive members, hashes, references, features, and dependencies before atomic registry activation. It rejects traversal/absolute paths, links, duplicate names, and case collisions. Installing a newer version from the same source disables the old version and retains its bytes. Goals use pinned IDs/digests. Removing an extension excludes it from new selections, retains pinned content, and disables required dependents. Disabling a package needed by enabled dependents is rejected with their IDs.

Complete export preserves the manifest and declared files. Selected-network export uses a derived package ID and records original IDs, digest, and source in provenance; external dependencies retain exact references. Export excludes workspace targets, histories, evidence, and saved MCP credentials. The output does not overwrite existing files. Preserve licenses when redistributing content.

## MCP runtime

The independent client supports stdio and Streamable HTTP, initialization, paginated tools/resources, qualified `connectionId/toolName` tools, and explicit tool/resource requests. **Verified** means discovery succeeded. That session closes; each later request opens a fresh session.

The client rediscovers schemas before invocation and can reject an expected-schema mismatch before dispatch. It does not automatically replay a call with unknown outcome. Cancellation and an explicit caller budget terminate the subprocess tree. Installing a preset does not install external executables or run hooks; prepare its documented prerequisites separately.

Knowledge stays readable without MCP, and generic MCP connections work without a knowledge pack. Bindings associate methods with capabilities and discovered tools. Package metadata and articles remain task data, not host instructions.

## Author and verify

Use [create-reverselab-extension](tools/skills/create-reverselab-extension/SKILL.md) for packs, MCP descriptors, and catalogs. Its portable helper copies the runtime validator and uses Python 3.11+ without external dependencies:

```sh
python scripts/misc/extension_protocol.py check path/to/source
python scripts/misc/extension_protocol.py build path/to/source path/to/extension.zip
python scripts/misc/extension_protocol.py check path/to/extension.zip
python scripts/misc/extension_protocol.py migrate path/to/draft.zip path/to/v1.zip
```

`desktop_extensions.py` accepts one stdin JSON request with `operation`: `list`, `inspect`, `install`, `updates/check`, `updates/install`, `enable`, `remove`, `export`, `sources/list`, `sources/add`, `sources/remove`, `sources/refresh`, `pin`, `catalog`, `graph`, `get`, `read`, `resolve`, or `neighbors`. Selected-network export adds `networkIds` to `export`. `desktop_mcp.py` supports `list`, `configure`, `remove`, `connect`, `disconnect`, `call`, and `read`. Each returns one JSON result.

Check structure, then test actual import/export/reimport and relevant MCP behavior separately. A descriptor check does not demonstrate server reachability or successful tool execution. Publishing a package, desktop release, or source catalog remains a separate action.
