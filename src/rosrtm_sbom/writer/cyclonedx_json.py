from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path

from ..config import ScanConfig
from ..model import Component, DependencyGraph


def _component_to_cdx(c: Component) -> dict:
    item = {
        "bom-ref": c.bom_ref,
        "type": c.type,
        "name": c.name,
    }
    if c.version:
        item["version"] = c.version
    if c.purl:
        item["purl"] = c.purl
    if c.licenses:
        item["licenses"] = [{"license": {"name": x}} for x in c.licenses]
    if c.hashes:
        item["hashes"] = [{"alg": k, "content": v} for k, v in c.hashes.items()]
    if c.properties:
        item["properties"] = [{"name": k, "value": v} for k, v in sorted(c.properties.items())]
    return item


def _dependencies_to_cdx(graph: DependencyGraph) -> list[dict]:
    depmap: dict[str, set[str]] = defaultdict(set)
    for e in graph.edges:
        depmap[e.src_ref].add(e.dst_ref)

    result: list[dict] = []
    for src, dsts in sorted(depmap.items()):
        result.append({
            "ref": src,
            "dependsOn": sorted(dsts),
        })
    return result


def _metadata(config: ScanConfig, primary: Component | None) -> dict:
    tool = {
        "vendor": "OpenAI prototype",
        "name": "rosrtm-sbom",
        "version": "0.1.0",
    }

    md = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tools": {"components": [tool]},
        "properties": [
            {"name": "scan.profile", "value": config.profile},
            {"name": "scan.source", "value": str(config.source) if config.source else ""},
            {"name": "scan.build", "value": str(config.build) if config.build else ""},
            {"name": "scan.install", "value": str(config.install) if config.install else ""},
            {"name": "scan.target", "value": config.target or ""},
        ],
    }
    if primary is not None:
        md["component"] = _component_to_cdx(primary)
    return md


def write_cyclonedx_json(graph: DependencyGraph, config: ScanConfig, primary: Component | None) -> None:
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": _metadata(config, primary),
        "components": [_component_to_cdx(c) for _, c in sorted(graph.components.items())],
        "dependencies": _dependencies_to_cdx(graph),
    }

    config.output.parent.mkdir(parents=True, exist_ok=True)
    config.output.write_text(json.dumps(bom, indent=2, ensure_ascii=False), encoding="utf-8")
    