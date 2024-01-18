from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Literal

Profile = Literal["source", "build", "runtime", "full"]


@dataclass
class ScanConfig:
    source: Optional[Path] = None
    build: Optional[Path] = None
    install: Optional[Path] = None
    target: Optional[str] = None
    target_type: Optional[str] = None
    profile: Profile = "runtime"
    output: Path = Path("sbom.cdx.json")
    include_hashes: bool = False
    include_licenses: bool = False