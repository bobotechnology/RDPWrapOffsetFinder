from __future__ import annotations

import os
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path

import pefile


MS_SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"


@dataclass(frozen=True)
class PdbInfo:
    pdb_name: str
    guid_hex: str  # 32 hex chars, upper
    age: int

    @property
    def guid_age(self) -> str:
        # Symbol server directory name uses GUID (no dashes) + age.
        return f"{self.guid_hex}{self.age}"


def _u32(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 4], "little", signed=False)


def get_pdb_info(pe: pefile.PE) -> PdbInfo:
    """Extract PDB (RSDS) info from PE debug directory."""

    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]])
    except Exception:
        pass

    entries = getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []
    for e in entries:
        # IMAGE_DEBUG_TYPE_CODEVIEW == 2
        if int(e.struct.Type) != 2:
            continue
        data = pe.get_data(int(e.struct.AddressOfRawData), int(e.struct.SizeOfData))
        if data[:4] != b"RSDS" or len(data) < 4 + 16 + 4:
            continue

        guid_bytes = data[4:4 + 16]
        age = _u32(data, 4 + 16)
        pdb_path = data[4 + 16 + 4:].split(b"\x00", 1)[0].decode(errors="ignore")
        pdb_name = os.path.basename(pdb_path)
        guid_hex = uuid.UUID(bytes_le=guid_bytes).hex.upper()
        return PdbInfo(pdb_name=pdb_name, guid_hex=guid_hex, age=age)

    raise RuntimeError("RSDS PDB info not found in PE debug directory")


def ensure_pdb_downloaded(pdb: PdbInfo, cache_root: Path, *, server: str = MS_SYMBOL_SERVER) -> Path:
    """Download PDB from Microsoft symbol server into a symsrv-like cache layout."""

    dst_dir = cache_root / pdb.pdb_name / pdb.guid_age
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / pdb.pdb_name
    if dst.exists() and dst.stat().st_size > 0:
        return dst

    url = f"{server}/{pdb.pdb_name}/{pdb.guid_age}/{pdb.pdb_name}"
    req = urllib.request.Request(url, headers={"User-Agent": "rdpwrap-offset-finder"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()
    dst.write_bytes(data)
    return dst
