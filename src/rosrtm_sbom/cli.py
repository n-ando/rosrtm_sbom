from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .analyzers.cmake_link import analyze_link_txt
from .analyzers.elf import analyze_elf
from .analyzers.python_imports import analyze_python_file
from .analyzers.ros_manifest import analyze_package_xml
from .config import ScanConfig
from .model import Component, DependencyEdge, DependencyGraph, Evidence
from .resolver import resolve_target
from .writer.cyclonedx_json import write_cyclonedx_json


def _parse_args(argv: list[str]) -> ScanConfig:
    parser = argparse.ArgumentParser(prog="rosrtm-sbom")
    parser.add_argument("--source", type=Path, default=None)
    parser.add_argument("--build", type=Path, default=None)
    parser.add_argument("--install", type=Path, default=None)
    parser.add_argument("--target", required=True, help="Executable path, python file path, or target file name")
    parser.add_argument("--target-type", default=None)
    parser.add_argument("--profile", choices=["source", "build", "runtime", "full"], default="runtime")
    parser.add_argument("--output", type=Path, default=Path("sbom.cdx.json"))
    parser.add_argument("--include-hashes", action="store_true")
    parser.add_argument("--include-licenses", action="store_true")

    ns = parser.parse_args(argv)
    return ScanConfig(
        source=ns.source,
        build=ns.build,
        install=ns.install,
        target=ns.target,
        target_type=ns.target_type,
        profile=ns.profile,
        output=ns.output,
        include_hashes=ns.include_hashes,
        include_licenses=ns.include_licenses,
    )


def _find_link_txts(build_root: Path, target_name: str) -> list[Path]:
    """
    CMakeFiles/*/link.txt をゆるく探索。
    target名を含むパスを優先する。
    """
    all_linktxt = list(build_root.rglob("link.txt"))
    preferred = [p for p in all_linktxt if target_name in str(p)]
    return preferred if preferred else all_linktxt


def run(config: ScanConfig) -> int:
    graph = DependencyGraph()
    resolved = resolve_target(config)

    primary_component: Component | None = None

    if resolved.is_elf:
        primary, comps, edges = analyze_elf(resolved.path, include_hashes=config.include_hashes)
        primary.properties["target.kind"] = "elf"
        if resolved.package_name:
            primary.properties["package.name"] = resolved.package_name
        graph.add_component(primary)
        primary_component = primary
        for c in comps:
            graph.add_component(c)
        for e in edges:
            graph.add_edge(e)

    elif resolved.is_python:
        primary, comps, edges = analyze_python_file(resolved.path)
        primary.properties["target.kind"] = "python"
        if resolved.package_name:
            primary.properties["package.name"] = resolved.package_name
        graph.add_component(primary)
        primary_component = primary
        for c in comps:
            graph.add_component(c)
        for e in edges:
            graph.add_edge(e)

    else:
        # 不明ファイルでも primary は作る
        primary = Component(
            bom_ref=f"file:{resolved.path}",
            name=resolved.path.name,
            type="application",
            properties={
                "file.path": str(resolved.path),
                "target.kind": "unknown",
            },
            evidence=[Evidence("manual", str(resolved.path), {})],
        )
        if resolved.package_name:
            primary.properties["package.name"] = resolved.package_name
        graph.add_component(primary)
        primary_component = primary

    # package.xml
    if resolved.package_xml and resolved.package_xml.exists():
        pkg_comp, pkg_edges = analyze_package_xml(resolved.package_xml)
        graph.add_component(pkg_comp)

        graph.add_edge(
            DependencyEdge(
                src_ref=primary_component.bom_ref,
                dst_ref=pkg_comp.bom_ref,
                scope="contains",
                evidence=[Evidence("package_xml", str(resolved.package_xml), {"relation": "belongs-to-package"})],
            )
        )
        for e in pkg_edges:
            graph.add_edge(e)

    # link.txt
    if config.build:
        for linktxt in _find_link_txts(config.build, resolved.name):
            comps, edges = analyze_link_txt(linktxt, primary_component.bom_ref)
            for c in comps:
                graph.add_component(c)
            for e in edges:
                graph.add_edge(e)

    write_cyclonedx_json(graph, config, primary_component)
    print(f"Wrote {config.output}")
    return 0


def main() -> int:
    config = _parse_args(sys.argv[1:])
    try:
        return run(config)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
