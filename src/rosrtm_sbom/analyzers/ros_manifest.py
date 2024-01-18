from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET

from ..model import Component, DependencyEdge, Evidence

DEP_TAG_SCOPE = {
    "depend": "runtime",
    "exec_depend": "runtime",
    "build_depend": "build",
    "buildtool_depend": "build",
    "test_depend": "test",
}


def analyze_package_xml(path: Path) -> tuple[Component, list[DependencyEdge]]:
    tree = ET.parse(path)
    root = tree.getroot()

    pkg_name = root.findtext("name", default=path.parent.name)
    pkg_version = root.findtext("version")
    licenses = [e.text.strip() for e in root.findall("license") if e.text]

    component = Component(
        bom_ref=f"ros-pkg:{pkg_name}" + (f"@{pkg_version}" if pkg_version else ""),
        name=pkg_name,
        version=pkg_version,
        type="framework",
        licenses=licenses,
        properties={
            "ecosystem": "ros",
            "manifest.path": str(path),
        },
        evidence=[Evidence("package_xml", str(path), {})],
    )

    edges: list[DependencyEdge] = []

    for child in root:
        tag = child.tag.split("}")[-1]
        if tag in DEP_TAG_SCOPE and child.text:
            dep_name = child.text.strip()
            dep_ref = f"ros-pkg:{dep_name}"
            edges.append(
                DependencyEdge(
                    src_ref=component.bom_ref,
                    dst_ref=dep_ref,
                    scope=DEP_TAG_SCOPE[tag],  # type: ignore[arg-type]
                    evidence=[Evidence("package_xml", str(path), {"tag": tag, "dep": dep_name})],
                )
            )

    return component, edges
