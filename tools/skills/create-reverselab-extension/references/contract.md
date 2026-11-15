# Extension authoring contract: v1

[简体中文](contract.zh-CN.md)

This stable contract is accepted by the desktop Extensions importer. The bundled helper copies the runtime validator. Its `check` validates local structure and semantics; installed dependency resolution and MCP tool execution are runtime operations. Existing v1-draft packages need explicit `migrate` conversion.

## Common manifest

The root file is `reverselab.extension.json`:

```json
{
  "protocol": "open-reverselab.extension/v1",
  "kind": "knowledge",
  "id": "example.integrity",
  "version": "0.1.0",
  "title": "File integrity methods",
  "description": "Read a file and compare its digest with a declared value.",
  "license": "Apache-2.0",
  "files": ["knowledge.json", "docs/read.md", "docs/compare.md"],
  "requires": [],
  "knowledge": "knowledge.json"
}
```

`kind` is `knowledge` or `mcp`. Use a lowercase dotted pack namespace and a SemVer content version. `files` explicitly lists every payload file, excluding the manifest and generated `reverselab.lock.json`. Paths are relative POSIX paths. Only listed files are packaged; do not glob an entire workspace. The manifest and all payload files must be UTF-8 when textual. Optional extension metadata uses `extensions`; unknown optional values remain intact.

`requires` entries contain `id`, `version` (exact SemVer), `source` (source identity or repository URL), and `optional` (boolean). Version ranges are rejected. Install required dependencies before activation; the store resolves their installation IDs and digests and validates external references. The helper checks dependency shape without fetching content. Supported `requiredFeatures` are `knowledge`, `mcp`, `conditions/v1`, `typed-relations/v1`, and `source-qualified-ids/v1`; unknown required features prevent activation.

## Knowledge records

The `knowledge` file is an object with `domains`, `documents`, `methods`, `networks`, and optional `bindings` arrays. A domain is a nonempty string; a new domain does not require desktop code. Entity IDs have the form `pack.namespace/local-name`. Local names can contain slash-separated segments and do not depend on file paths or language. `track` is `red`, `blue`, or `shared`; `both` is a runtime composition mode.

| Record | Fields |
| --- | --- |
| Document | `id`, `title`, `path` (listed Markdown file), `track`, `domain`; optional `locale`, `aliases`, `provenance` |
| Method | `id`, `title`, `document` (document ID), `track`, `domain`, `signals` (strings), `requiresEvidence` (evidence keys), `produces` (expected evidence keys), `toolRequirements` (capability names), optional `when`, `provenance`, `validation` |
| Network | `id`, `title`, `track`, `entrypoints` (method IDs), `nodes` (method IDs), `relations` |
| Binding | `method` (method ID), `capability`, `server` (connection/preset reference), `tool`, `inputMapping`, optional `outputMapping`; mappings are declarative, not executable expressions |

Methods may reference documents from required packs. Network nodes may reference methods from required packs. Every external reference resolves through an explicit dependency source, not a globally guessed package name. External relationships are checked during activation; the helper only verifies that the dependency is declared.

Relations contain `from`, `to`, `type`, and optional `when`. Direction matters:

| Relation | Meaning of `from → to` |
| --- | --- |
| `depends_on` | The source method requires the target method's result |
| `enables` | The source method produces a condition used by the target |
| `composes_with` | The methods can be combined under the recorded conditions |
| `defends` / `detects` | The source method prevents / observes the target technique |
| `verifies` | The source method checks a claim/result associated with the target |
| `conflicts` | The methods or their results cannot jointly support the same claim under the recorded conditions |

Optional `when` is one of `{"all": [condition]}`, `{"any": [condition]}`, `{"not": condition}`, or `{"evidence": "key", "state": "observed|absent|unobservable"}`. Unknown is distinct from recorded absence. An empty `all` is true; an empty `any` is false. Unknown propagates through `not`; for `all`/`any`, a decisive false/true wins, otherwise unknown propagates. `evaluate_condition(condition, evidence)` returns `True`, `False`, or `None`. Conditions and relation ordering are data, not a claim that the desktop automatically schedules every declared graph.

`provenance` names sources and versions; `validation` describes what was actually tested and in which environment. `produces` describes expected evidence only. Record observations in the workspace with method/pack IDs, invocation and evidence references; never label an expected output as an observed result in a reusable pack.

Knowledge feedback cycles are allowed. A planner must resolve selected methods into an acyclic execution round; relation order in JSON is not an execution schedule. Subgraph exports include required local entities/documents and use a new derived pack ID with `origin` references. Required external dependency locks travel with the export; dependencies that cannot be redistributed remain references.

## MCP descriptors

An MCP extension uses the same manifest with `kind: "mcp"`, `mcp: "connection.json"`, and that file in `files`. It describes how the user can connect an existing server; it does not redefine JSON-RPC, MCP negotiation, or tool schemas.

`connection.json` has `transport`, `inputs`, and either `command`/`args` for `stdio`, or `url` for `streamable-http`. `inputs` is an array of `{name, type, required}` where `type` is `string`, `url`, `path`, or `secret`. Input `value` and `default` fields are rejected. `${inputs.name}` references resolve locally. Optional `env` and `headers` values must be input references; credentials are never bundled. `args` is an argument array. Server prerequisites and pinned installation instructions belong in a listed document; the desktop does not execute install hooks or package-manager commands. It saves configuration and explicitly verifies the selected connection, with a fresh session for later calls.

For example, an HTTP preset can require a user-supplied endpoint without pretending a sample server exists:

```json
{
  "transport": "streamable-http",
  "url": "${inputs.endpoint}",
  "inputs": [{"name": "endpoint", "type": "url", "required": true}]
}
```

Tool bindings use real discovered names and input/output schemas. Full connection behavior uses the upstream MCP specification; a passing descriptor check does not demonstrate that a server is reachable or a tool works.

## ZIP and lock contents

Use a standard ZIP. Recommended artifact names are `pack-id-version.kbpack.zip` or `pack-id-version.mcp.zip`. These are naming conventions, not separate compression formats. A ZIP contains its manifest and explicit payload, optionally under one enclosing folder. `reverselab.lock.json` lists the SHA256 of the manifest and every payload file; it does not include itself. The outer ZIP SHA256 is recorded alongside the artifact/catalog entry, avoiding a self-referential checksum.

Local source checks do not require a lock; building generates one from the exact packaged bytes. ZIP checks require it. The helper rejects unexpected files, ambiguous roots, path traversal, links, duplicate/case-colliding paths, and changed content. A checksum detects byte changes; it does not authenticate a publisher.

## GitHub repository catalog

A root `reverselab.registry.json` uses `protocol: "open-reverselab.registry/v1"`, `id`, `title`, and `entries`. Each entry has `id`, `kind`, `title`, `version`, and exactly one location:

- `path`: relative path to an extension directory in the same resolved commit, or
- `artifact`: HTTPS ZIP URL plus `sha256` computed from the actual artifact.
- `repository`: GitHub URL pointing directly to a package directory in another repository. Use a commit URL to pin a catalog release. The importer resolves the destination commit during inspection, validates the package identity/version during installation, and uses the destination repository as its source identity. This field does not recursively follow another catalog.

Optional entry metadata includes `description`, `domains`, `tracks`, and `license`. One repository can list knowledge and MCP entries together. Entry identity and version must match the referenced manifest. Catalog resolution records source repository, commit, and path. Refreshing a catalog discovers versions; it does not update installed extensions without an installation/update action.

The pack helper does not package a marketplace catalog. Validate its JSON and resolve each entry separately. Do not embed machine-specific configuration or secrets in the catalog. Preparing a local catalog is distinct from publishing a GitHub repository or release.
