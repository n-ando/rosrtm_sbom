from __future__ import annotations

from pathlib import Path
import shlex

from ..model import Component, DependencyEdge, Evidence


def analyze_link_txt(path: Path, owner_ref: str) -> tuple[list[Component], list[DependencyEdge]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    argv = shlex.split(text)

    components: list[Component] = []
    edges: list[DependencyEdge] = []
    seen: set[str] = set()

    for tok in argv:
        dep_name = None
        dep_ref = None
        props = {"origin": "link.txt", "linktxt.path": str(path)}

        if tok.startswith("-l") and len(tok) > 2:
            dep_name = f"lib{tok[2:]}.so"
            dep_ref = f"native-lib:{dep_name}"
        elif tok.endswith(".so") or tok.endswith(".a"):
            dep_name = Path(tok).name
            dep_ref = f"native-lib:{dep_name}"
            props["resolved.path"] = tok

        if dep_ref and dep_ref not in seen:
            seen.add(dep_ref)
            comp = Component(
                bom_ref=dep_ref,
                name=dep_name or dep_ref,
                type="library",
                properties=props,
                evidence=[Evidence("link_txt", str(path), {"token": tok})],
            )
            components.append(comp)
            edges.append(
                DependencyEdge(
                    src_ref=owner_ref,
                    dst_ref=dep_ref,
                    scope="build",
                    evidence=[Evidence("link_txt", str(path), {"token": tok})],
                )
            )

    return components, edges
