from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .config import ScanConfig


@dataclass
class ResolvedTarget:
    name: str
    path: Path
    package_name: Optional[str]
    package_xml: Optional[Path]
    is_elf: bool
    is_python: bool


def _is_elf_file(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            magic = f.read(4)
        return magic == b"\x7fELF"
    except OSError:
        return False


def _is_python_file(path: Path) -> bool:
    if path.suffix == ".py":
        return True
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        return text.startswith("#!") and "python" in text.splitlines()[0]
    except Exception:
        return False


def _find_package_xml_near(path: Path) -> tuple[Optional[str], Optional[Path]]:
    """
    install/<pkg>/lib/<pkg>/node や source tree 配下をゆるく探索する。
    """
    parts = path.parts
    try:
        lib_idx = parts.index("lib")
        if lib_idx >= 1 and lib_idx + 1 < len(parts):
            pkg = parts[lib_idx + 1]
            # install/<pkg>/share/<pkg>/package.xml を推定
            prefix = Path(*parts[:lib_idx - 1]) if lib_idx >= 2 else path.parent
            candidate = prefix / pkg / "share" / pkg / "package.xml"
            if candidate.exists():
                return pkg, candidate
    except ValueError:
        pass

    # 上方向に package.xml を探索
    cur = path.parent
    while True:
        candidate = cur / "package.xml"
        if candidate.exists():
            return cur.name, candidate
        if cur.parent == cur:
            break
        cur = cur.parent
    return None, None


def resolve_target(config: ScanConfig) -> ResolvedTarget:
    if not config.target:
        raise ValueError("--target is required")

    target_path = Path(config.target)

    if target_path.exists():
        path = target_path.resolve()
        pkg_name, pkg_xml = _find_package_xml_near(path)
        return ResolvedTarget(
            name=path.name,
            path=path,
            package_name=pkg_name,
            package_xml=pkg_xml,
            is_elf=_is_elf_file(path),
            is_python=_is_python_file(path),
        )

    # install tree 内からファイル名で探索
    search_roots = [p for p in [config.install, config.build, config.source] if p is not None]
    for root in search_roots:
        for p in root.rglob(config.target):
            if p.is_file():
                pkg_name, pkg_xml = _find_package_xml_near(p)
                return ResolvedTarget(
                    name=p.name,
                    path=p.resolve(),
                    package_name=pkg_name,
                    package_xml=pkg_xml,
                    is_elf=_is_elf_file(p),
                    is_python=_is_python_file(p),
                )

    raise FileNotFoundError(f"Target not found: {config.target}")
