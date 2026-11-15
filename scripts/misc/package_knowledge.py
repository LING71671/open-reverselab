#!/usr/bin/env python3
"""Build the independently versioned official knowledge pack from source articles.

Existing entity IDs survive rebuilds and path changes through declared aliases.
Legacy prose/Mermaid networks remain complete documents. Only explicit paired
defense links become typed relations; prose is not guessed into prerequisites.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from desktop_kb import build_legacy_catalog
from extension_protocol import PROTOCOL, REGISTRY_PROTOCOL, json_bytes, load, validate, pack

ROOT = Path(__file__).resolve().parents[2]
NAMESPACE = "org.open-reverselab.knowledge"


def generate(root: Path = ROOT, version: str = "1.0.0") -> dict:
    kb = root / "kb"
    previous = json.loads((kb / "knowledge.json").read_text(encoding="utf-8")) if (kb / "knowledge.json").exists() else {}
    existing = {alias: doc for doc in previous.get("documents", []) for alias in ["kb/" + doc["path"], *doc.get("aliases", [])]}
    old_methods = {item["document"]: item for item in previous.get("methods", [])}
    path_aliases = json.loads((kb / "path-aliases.json").read_text(encoding="utf-8")) if (kb / "path-aliases.json").exists() else {}
    path_aliases = path_aliases.get("aliases", path_aliases)
    catalog = build_legacy_catalog("both", root)
    documents, methods, networks = [], [], []
    by_path = {}
    for item in catalog:
        path = item["path"]
        aliases = [path, *[old for old, new in path_aliases.items() if new == path]]
        prior = next((existing[a] for a in aliases if a in existing), {})
        # The generated ID is written to knowledge.json and subsequently reused.
        local = hashlib.sha256(path.encode()).hexdigest()[:20]
        doc_id = prior.get("id", f"{NAMESPACE}/docs/{local}")
        method_id = old_methods.get(doc_id, {}).get("id", f"{NAMESPACE}/methods/{local}")
        track = "shared" if item["track"] == "both" else item["track"]
        common = {"title": item["title"], "track": track, "domain": item["board"]}
        documents.append({**prior, **common, "id": doc_id, "path": path.removeprefix("kb/"),
                          "aliases": list(dict.fromkeys([*prior.get("aliases", []), *aliases])),
                          "category": item["category"], "signals": item["signals"], "mcp_tools": item["mcp_tools"]})
        methods.append({"id": method_id, **common, "document": doc_id, "signals": item["signals"],
                        "requiresEvidence": [], "produces": [], "toolRequirements": [],
                        "provenance": {"kind": "legacy-document", "source": path},
                        "validation": {"prerequisites": "unspecified", "toolMappings": "documented-in-source"}})
        by_path[path] = method_id
    for board in sorted({item["board"] for item in catalog}):
        for track, filename in (("red", "attack-network.md"), ("blue", "defense-network.md")):
            members = [item for item in catalog if item["board"] == board and item["track"] in (track, "both")]
            if not members:
                continue
            entry = next((item for item in members if item["path"].endswith("/" + filename)), None)
            nodes = [by_path[item["path"]] for item in members]
            relations = []
            if track == "blue":
                for item in members:
                    for paired in item["related_paths"]:
                        if paired in by_path and "/red/" in paired and item["track"] == "blue":
                            other = by_path[paired]
                            if other not in nodes:
                                nodes.append(other)
                            relations.append({"from": by_path[item["path"]], "to": other, "type": "defends",
                                              "provenance": {"kind": "legacy-paired-document"}})
            networks.append({"id": f"{NAMESPACE}/networks/{track}/{board}", "title": f"{board} · {track}",
                             "track": track, "domain": board, "nodes": nodes,
                             "entrypoints": [by_path[entry["path"]]] if entry else [], "relations": relations,
                             "provenance": {"kind": "document-network", "source": entry["path"] if entry else "",
                                            "semantics": "See source document for the complete branching network."}})
    # Guides are readable entities too: relative Markdown links must survive
    # installation outside the source tree without inventing method semantics.
    documented = {item["path"] for item in documents}
    for guide in sorted(kb.rglob("*.md")):
        relative = guide.relative_to(kb).as_posix()
        if relative in documented:
            continue
        path = "kb/" + relative
        prior = existing.get(path, {})
        parts = relative.split("/")
        track = parts[0] if parts[0] in {"red", "blue", "shared"} else "shared"
        domain = parts[1] if len(parts) > 2 and parts[0] in {"red", "blue", "shared"} else "general"
        heading = re.search(r"^#\s+(.+)$", guide.read_text(encoding="utf-8-sig"), re.M)
        documents.append({**prior, "id": prior.get("id", f"{NAMESPACE}/docs/{hashlib.sha256(path.encode()).hexdigest()[:20]}"),
                          "title": heading.group(1) if heading else guide.stem, "path": relative,
                          "track": track, "domain": domain, "aliases": list(dict.fromkeys([*prior.get("aliases", []), path])),
                          "category": "guide", "signals": [], "mcp_tools": []})
    knowledge = {"domains": sorted({d["domain"] for d in documents}), "documents": documents,
                 "methods": methods, "networks": networks, "bindings": []}
    (kb / "knowledge.json").write_bytes(json_bytes(knowledge))
    # Include linked source guides and catalogs, so exporting the pack preserves
    # the complete collection rather than a desktop-only selection of articles.
    files = sorted(p.relative_to(kb).as_posix() for p in kb.rglob("*") if p.is_file()
                   and p.suffix in {".md", ".json"} and p.name not in {"reverselab.extension.json", "reverselab.lock.json"})
    manifest = {"protocol": PROTOCOL, "kind": "knowledge", "id": NAMESPACE, "version": version,
                "title": "Open ReverseLab knowledge", "description": "Red, blue and shared analysis documents and networks.",
                "license": "Apache-2.0", "knowledge": "knowledge.json", "files": files, "requires": []}
    (kb / "reverselab.extension.json").write_bytes(json_bytes(manifest))
    (root / "reverselab.registry.json").write_bytes(json_bytes({"protocol": REGISTRY_PROTOCOL,
        "id": "org.open-reverselab.registry", "title": "Open ReverseLab extensions",
        "entries": [{"id": NAMESPACE, "kind": "knowledge", "version": version, "title": manifest["title"], "path": "kb"}]}))
    validate(*load(kb))
    return {"documents": len(documents), "methods": len(methods), "networks": len(networks), "files": len(files)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default="1.0.0")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = generate(version=args.version)
    if args.output:
        pack(ROOT / "kb", args.output)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
