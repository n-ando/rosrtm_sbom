from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess

from ..model import Component, DependencyEdge, Evidence


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _readelf_dynamic(path: Path) -> dict:
    out = subprocess.check_output(
        ["readelf", "-d", str(path)],
        text=True,
        errors="ignore",
    )
    needed: list[str] = []
    runpath = None
    rpath = None
    soname = None

    for line in out.splitlines():
        if "(NEEDED)" in line:
            m = re.search(r"\[(.+?)\]", line)
            if m:
                needed.append(m.group(1))
        elif "(RUNPATH)" in line:
            m = re.search(r"\[(.+?)\]", line)
            if m:
                runpath = m.group(1)
        elif "(RPATH)" in line:
            m = re.search(r"\[(.+?)\]", line)
            if m:
                rpath = m.group(1)
        elif "(SONAME)" in line:
            m = re.search(r"\[(.+?)\]", line)
            if m:
                soname = m.group(1)

    return {
        "needed": sorted(set(needed)),
        "runpath": runpath,
        "rpath": rpath,
        "soname": soname,
    }


def analyze_elf(path: Path, include_hashes: bool = False) -> tuple[Component, list[Component], list[DependencyEdge]]:
    dyn = _readelf_dynamic(path)

    primary = Component(
        bom_ref=f"file:{path}",
        name=path.name,
        type="application",
        properties={
            "file.path": str(path),
            "elf.soname": dyn["soname"] or "",
            "elf.runpath": dyn["runpath"] or "",
            "elf.rpath": dyn["rpath"] or "",
        },
        evidence=[Evidence("elf_needed", str(path), {})],
    )

    if include_hashes:
        primary.hashes["SHA-256"] = sha256_file(path)

    components: list[Component] = []
    edges: list[DependencyEdge] = []

    for soname in dyn["needed"]:
        dep_ref = f"native-lib:{soname}"
        comp = Component(
            bom_ref=dep_ref,
            name=soname,
            type="library",
            properties={"ecosystem": "native"},
            evidence=[Evidence("elf_needed", str(path), {"soname": soname})],
        )
        components.append(comp)
        edges.append(
            DependencyEdge(
                src_ref=primary.bom_ref,
                dst_ref=dep_ref,
                scope="runtime",
                evidence=[Evidence("elf_needed", str(path), {"soname": soname})],
            )
        )

    return primary, components, edges
