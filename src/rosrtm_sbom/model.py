from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional

ComponentType = Literal[
    "application",
    "library",
    "framework",
    "file",
    "operating-system",
    "container",
]

EvidenceKind = Literal[
    "package_xml",
    "link_txt",
    "elf_needed",
    "elf_runpath",
    "elf_rpath",
    "python_import",
    "python_metadata",
    "dpkg",
    "pip_metadata",
    "manual",
]

EdgeScope = Literal["build", "runtime", "test", "optional", "plugin", "contains"]


@dataclass
class Evidence:
    kind: EvidenceKind
    source: str
    detail: Dict[str, str] = field(default_factory=dict)


@dataclass
class Component:
    bom_ref: str
    name: str
    version: Optional[str] = None
    type: ComponentType = "library"
    purl: Optional[str] = None
    licenses: List[str] = field(default_factory=list)
    hashes: Dict[str, str] = field(default_factory=dict)
    properties: Dict[str, str] = field(default_factory=dict)
    evidence: List[Evidence] = field(default_factory=list)

    # CycloneDX で使える補助メタデータ
    author: Optional[str] = None
    publisher: Optional[str] = None
    description: Optional[str] = None


@dataclass
class DependencyEdge:
    src_ref: str
    dst_ref: str
    scope: EdgeScope = "runtime"
    evidence: List[Evidence] = field(default_factory=list)


class DependencyGraph:
    def __init__(self) -> None:
        self.components: Dict[str, Component] = {}
        self.edges: List[DependencyEdge] = []

    def add_component(self, c: Component) -> None:
        if c.bom_ref not in self.components:
            self.components[c.bom_ref] = c
            return
        self._merge_component(self.components[c.bom_ref], c)

    def add_edge(self, e: DependencyEdge) -> None:
        if not self._edge_exists(e):
            self.edges.append(e)

    def _edge_exists(self, new_edge: DependencyEdge) -> bool:
        for e in self.edges:
            if e.src_ref == new_edge.src_ref and e.dst_ref == new_edge.dst_ref and e.scope == new_edge.scope:
                return True
        return False

    def _merge_component(self, old: Component, new: Component) -> None:
        if not old.version and new.version:
            old.version = new.version
        if not old.purl and new.purl:
            old.purl = new.purl
        if not old.author and new.author:
            old.author = new.author
        if not old.publisher and new.publisher:
            old.publisher = new.publisher
        if not old.description and new.description:
            old.description = new.description

        old.licenses = sorted(set(old.licenses + new.licenses))
        for k, v in new.hashes.items():
            if k not in old.hashes:
                old.hashes[k] = v
        for k, v in new.properties.items():
            if k not in old.properties:
                old.properties[k] = v
        old.evidence.extend(new.evidence)
