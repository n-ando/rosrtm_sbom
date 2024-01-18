from __future__ import annotations

import ast
from pathlib import Path

from ..model import Component, DependencyEdge, Evidence


def _extract_imports(pyfile: Path) -> set[str]:
    tree = ast.parse(pyfile.read_text(encoding="utf-8", errors="ignore"))
    mods: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mods.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                mods.add(node.module.split(".")[0])

    return mods


def analyze_python_file(path: Path) -> tuple[Component, list[Component], list[DependencyEdge]]:
    imports = sorted(_extract_imports(path))

    primary = Component(
        bom_ref=f"file:{path}",
        name=path.name,
        type="application",
        properties={
            "file.path": str(path),
            "language": "python",
        },
        evidence=[Evidence("python_import", str(path), {})],
    )

    components: list[Component] = []
    edges: list[DependencyEdge] = []

    for mod in imports:
        dep_ref = f"python-module:{mod}"
        comp = Component(
            bom_ref=dep_ref,
            name=mod,
            type="library",
            properties={"ecosystem": "python"},
            evidence=[Evidence("python_import", str(path), {"module": mod})],
        )
        components.append(comp)
        edges.append(
            DependencyEdge(
                src_ref=primary.bom_ref,
                dst_ref=dep_ref,
                scope="runtime",
                evidence=[Evidence("python_import", str(path), {"module": mod})],
            )
        )

    return primary, components, edges
