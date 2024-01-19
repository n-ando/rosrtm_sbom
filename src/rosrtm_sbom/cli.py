from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .analyzers.cmake_link import analyze_link_txt
from .analyzers.elf import analyze_elf
from .analyzers.os_package import (
    enrich_native_lib_with_dpkg,
    enrich_python_module_with_dpkg,
    enrich_python_module_with_pip_metadata,
)
from .analyzers.python_imports import analyze_python_file
from .analyzers.ros_manifest import analyze_package_xml
from .config import ScanConfig
from .model import Component, DependencyEdge, DependencyGraph, Evidence
from .resolver import resolve_target
from .writer.cyclonedx_json import write_cyclonedx_json


def _parse_args(argv: list[str]) -> ScanConfig:
    parser = argparse.ArgumentParser(
        prog="rosrtm_sbom",
        description="Generate SBOM for ROS/OpenRTM targets.",
    )
    parser.add_argument("--source", type=Path, default=None, help="source tree path")
    parser.add_argument("--build", type=Path, default=None, help="build tree path")
    parser.add_argument("--install", type=Path, default=None, help="install tree path")
    parser.add_argument(
        "--target",
        required=True,
        help="Executable path, Python file path, or target file name",
    )
    parser.add_argument("--target-type", default=None, help="optional target type hint")
    parser.add_argument(
        "--profile",
        choices=["source", "build", "runtime", "full"],
        default="runtime",
        help="dependency scope profile",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("sbom.cdx.json"),
        help="output CycloneDX JSON path",
    )
    parser.add_argument(
        "--include-hashes",
        action="store_true",
        help="include file hashes when available",
    )
    parser.add_argument(
        "--include-licenses",
        action="store_true",
        help="reserved flag for license enrichment",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="print debug information",
    )

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
    CMakeFiles/*/link.txt をゆるく探索する。
    target名を含むパスを優先する。
    """
    all_linktxt = list(build_root.rglob("link.txt"))
    preferred = [p for p in all_linktxt if target_name in str(p)]
    return preferred if preferred else all_linktxt


def _add_components_and_edges(
    graph: DependencyGraph,
    components: list[Component],
    edges: list[DependencyEdge],
) -> None:
    for c in components:
        graph.add_component(c)
    for e in edges:
        graph.add_edge(e)


def _debug_dump(graph: DependencyGraph) -> None:
    print("DEBUG components:")
    for key in sorted(graph.components.keys()):
        print(f"  {key}")

    print("DEBUG edges:")
    for e in graph.edges:
        print(f"  {e.src_ref} -> {e.dst_ref} (scope={e.scope})")


def run(config: ScanConfig, debug: bool = False) -> int:
    graph = DependencyGraph()
    resolved = resolve_target(config)

    primary_component: Component | None = None

    # -----------------------------
    # Primary target analysis
    # -----------------------------
    if resolved.is_elf:
        primary, comps, edges = analyze_elf(
            resolved.path,
            include_hashes=config.include_hashes,
        )
        primary.properties["target.kind"] = "elf"
        if resolved.package_name:
            primary.properties["package.name"] = resolved.package_name

        graph.add_component(primary)
        primary_component = primary
        _add_components_and_edges(graph, comps, edges)

        # native-lib -> Debian package
        # さらに primary -> Debian package も張る
        for c in comps:
            extra_comps, extra_edges = enrich_native_lib_with_dpkg(
                c,
                resolved_path=c.properties.get("resolved.path", ""),
            )
            _add_components_and_edges(graph, extra_comps, extra_edges)

            for ec in extra_comps:
                graph.add_edge(
                    DependencyEdge(
                        src_ref=primary_component.bom_ref,
                        dst_ref=ec.bom_ref,
                        scope="runtime",
                        evidence=[
                            Evidence(
                                "dpkg",
                                c.properties.get("resolved.path", ""),
                                {"relation": "runtime-package-from-native-lib"},
                            )
                        ],
                    )
                )

    elif resolved.is_python:
        primary, comps, edges = analyze_python_file(resolved.path)
        primary.properties["target.kind"] = "python"
        if resolved.package_name:
            primary.properties["package.name"] = resolved.package_name

        graph.add_component(primary)
        primary_component = primary
        _add_components_and_edges(graph, comps, edges)

        # python-module -> Debian package
        # 見つからなければ pip metadata で補助
        for c in comps:
            extra_comps, extra_edges = enrich_python_module_with_dpkg(c)
            _add_components_and_edges(graph, extra_comps, extra_edges)

            for ec in extra_comps:
                graph.add_edge(
                    DependencyEdge(
                        src_ref=primary_component.bom_ref,
                        dst_ref=ec.bom_ref,
                        scope="runtime",
                        evidence=[
                            Evidence(
                                "dpkg",
                                ec.properties.get("resolved.from.path", ""),
                                {"relation": "runtime-package-from-python-module"},
                            )
                        ],
                    )
                )

            if not extra_comps:
                pip_comps, pip_edges = enrich_python_module_with_pip_metadata(c)
                _add_components_and_edges(graph, pip_comps, pip_edges)

                for pc in pip_comps:
                    graph.add_edge(
                        DependencyEdge(
                            src_ref=primary_component.bom_ref,
                            dst_ref=pc.bom_ref,
                            scope="runtime",
                            evidence=[
                                Evidence(
                                    "pip_metadata",
                                    pc.name,
                                    {"relation": "runtime-package-from-python-module"},
                                )
                            ],
                        )
                    )
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

    if primary_component is None:
        raise RuntimeError("Failed to create primary component")

    # -----------------------------
    # ROS package.xml analysis
    # -----------------------------
    if resolved.package_xml and resolved.package_xml.exists():
        pkg_comp, pkg_edges = analyze_package_xml(resolved.package_xml)
        graph.add_component(pkg_comp)

        graph.add_edge(
            DependencyEdge(
                src_ref=primary_component.bom_ref,
                dst_ref=pkg_comp.bom_ref,
                scope="contains",
                evidence=[
                    Evidence(
                        "package_xml",
                        str(resolved.package_xml),
                        {"relation": "belongs-to-package"},
                    )
                ],
            )
        )

        for e in pkg_edges:
            graph.add_edge(e)

    # -----------------------------
    # Build-tree link.txt analysis
    # -----------------------------
    if config.build:
        for linktxt in _find_link_txts(config.build, resolved.name):
            comps, edges = analyze_link_txt(linktxt, primary_component.bom_ref)
            _add_components_and_edges(graph, comps, edges)

            # link.txt にフルパスが見えている native-lib を dpkg package に解決
            for c in comps:
                extra_comps, extra_edges = enrich_native_lib_with_dpkg(
                    c,
                    resolved_path=c.properties.get("resolved.path", ""),
                )
                _add_components_and_edges(graph, extra_comps, extra_edges)

                for ec in extra_comps:
                    graph.add_edge(
                        DependencyEdge(
                            src_ref=primary_component.bom_ref,
                            dst_ref=ec.bom_ref,
                            scope="build",
                            evidence=[
                                Evidence(
                                    "dpkg",
                                    c.properties.get("resolved.path", ""),
                                    {"relation": "build-package-from-native-lib"},
                                )
                            ],
                        )
                    )

    if debug:
        _debug_dump(graph)

    write_cyclonedx_json(graph, config, primary_component)
    print(f"Wrote {config.output}")
    return 0


def main() -> int:
    argv = sys.argv[1:]
    debug = "--debug" in argv
    config = _parse_args(argv)
    try:
        return run(config, debug=debug)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
