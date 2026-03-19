from __future__ import annotations

from dataclasses import dataclass

import pefile


@dataclass(frozen=True)
class FileVersion:
    ms: int
    ls: int

    @property
    def major(self) -> int:
        return (self.ms >> 16) & 0xFFFF

    @property
    def minor(self) -> int:
        return self.ms & 0xFFFF

    @property
    def build(self) -> int:
        return (self.ls >> 16) & 0xFFFF

    @property
    def patch(self) -> int:
        return self.ls & 0xFFFF

    def to_ini_section(self) -> str:
        return f"{self.major}.{self.minor}.{self.build}.{self.patch}"


def get_file_version_from_vs_version_info(pe: pefile.PE) -> FileVersion:
    """Return file version from VS_VERSIONINFO (VS_FIXEDFILEINFO).

    C++ original reads resource type 16, id 1 (VS_VERSIONINFO). pefile exposes
    VS_FIXEDFILEINFO when present.
    """

    if hasattr(pe, "VS_FIXEDFILEINFO") and pe.VS_FIXEDFILEINFO:
        ffi = pe.VS_FIXEDFILEINFO[0]
        return FileVersion(ms=int(ffi.FileVersionMS), ls=int(ffi.FileVersionLS))

    # Fallback: try parsing FileVersion string.
    if hasattr(pe, "FileInfo") and pe.FileInfo:
        for fi in pe.FileInfo:
            if fi.Key == b"StringFileInfo":
                for st in fi.StringTable:
                    val = st.entries.get(b"FileVersion")
                    if val:
                        v = val.decode(errors="ignore").split(" ", 1)[0]
                        parts = [int(x) for x in v.split(".") if x.isdigit()]
                        if len(parts) == 4:
                            ms = (parts[0] << 16) | parts[1]
                            ls = (parts[2] << 16) | parts[3]
                            return FileVersion(ms=ms, ls=ls)

    raise RuntimeError("Failed to read VS_VERSIONINFO from PE")
