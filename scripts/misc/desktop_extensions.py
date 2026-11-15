#!/usr/bin/env python3
"""One JSON request on stdin, one JSON result on stdout for extension operations."""

from __future__ import annotations

import json
import sys
import zipfile

from extension_store import ExtensionStore


def dispatch(request: dict, store: ExtensionStore | None = None) -> dict:
    store = store or ExtensionStore()
    operation = request.get("operation", request.get("op"))
    if operation == "list":
        return {"entries": store.list()}
    if operation == "inspect":
        return store.inspect(request.get("source", ""), migrate_draft=request.get("migrateDraft", False), archive_base64=request.get("archiveBase64"), filename=request.get("filename", "package.zip"))
    if operation == "install":
        return {"entry": store.install(request["inspectionId"], request["entryId"])}
    if operation == "updates/check":
        return store.check_update(request["installationId"])
    if operation == "updates/install":
        return {"entry": store.update(request["installationId"], request["inspectionId"])}
    if operation == "enable":
        return {"entry": store.enable(request["installationId"], request.get("enabled", True))}
    if operation == "remove":
        return store.remove(request["installationId"])
    if operation == "export":
        return store.export(request["installationId"], request.get("outputPath"), request.get("networkIds"))
    if operation == "sources/list":
        return {"sources": store.sources_list()}
    if operation == "sources/add":
        return {"source": store.sources_add(request["source"])}
    if operation == "sources/remove":
        return store.sources_remove(request["sourceId"])
    if operation == "sources/refresh":
        return store.sources_refresh(request["sourceId"])
    if operation == "pin":
        return {"pins": store.pin()}
    if operation == "catalog":
        documents = store.catalog(request.get("track", "both"), request.get("pinned"))
        return {"entries": documents, "documents": documents}
    if operation == "graph":
        return store.graph(request.get("track", "both"), request.get("pinned"))
    if operation == "read":
        return {"content": store.read_document(request.get("uri", request.get("path", "")))}
    if operation == "get":
        if "installationId" in request:
            return {"entry": store.get(request["installationId"])}
        return {"entity": store.resolve(request.get("id", request.get("uri", "")), request.get("pinned"))}
    if operation == "resolve":
        return {"path": store.resolve_link(request["uri"], request["href"])}
    if operation == "neighbors":
        return store.neighbors(request.get("id", request.get("uri", "")), request.get("pinned"))
    raise ValueError("Unknown extension operation: " + str(operation))


def main() -> int:
    try:
        request = json.load(sys.stdin)
        if not isinstance(request, dict):
            raise ValueError("Expected a JSON request object")
        result = {"ok": True, **dispatch(request)}
    except (ValueError, OSError, KeyError, TypeError, RuntimeError, zipfile.BadZipFile) as error:
        result = {"ok": False, "error": str(error)}
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
