from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path


class DbgHelpError(RuntimeError):
    pass


def _last_error() -> int:
    return ctypes.get_last_error()


SYMOPT_DEBUG = 0x80000000
SYMOPT_UNDNAME = 0x00000002
SYMOPT_PUBLICS_ONLY = 0x00004000


class SYMBOL_INFOW(ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct", wintypes.ULONG),
        ("TypeIndex", wintypes.ULONG),
        ("Reserved", ctypes.c_uint64 * 2),
        ("Index", wintypes.ULONG),
        ("Size", wintypes.ULONG),
        ("ModBase", ctypes.c_uint64),
        ("Flags", wintypes.ULONG),
        ("Value", ctypes.c_uint64),
        ("Address", ctypes.c_uint64),
        ("Register", wintypes.ULONG),
        ("Scope", wintypes.ULONG),
        ("Tag", wintypes.ULONG),
        ("NameLen", wintypes.ULONG),
        ("MaxNameLen", wintypes.ULONG),
        ("Name", wintypes.WCHAR * 1),
    ]


def _make_symbol_info(max_name_len: int = 1024) -> tuple[ctypes.Array, ctypes.POINTER(SYMBOL_INFOW)]:
    """Allocate SYMBOL_INFOW buffer.

    Important: the returned `buf` must be kept alive while calling SymFromNameW,
    otherwise the pointer becomes invalid and SymFromNameW will scribble into
    freed memory.
    """

    size = ctypes.sizeof(SYMBOL_INFOW) + (max_name_len * ctypes.sizeof(wintypes.WCHAR))
    buf = ctypes.create_string_buffer(size)
    sym = ctypes.cast(buf, ctypes.POINTER(SYMBOL_INFOW))
    sym.contents.SizeOfStruct = ctypes.sizeof(SYMBOL_INFOW)
    sym.contents.MaxNameLen = max_name_len
    return buf, sym


@dataclass
class DbgHelp:
    """Minimal DbgHelp wrapper used to resolve RVAs from PDB symbols."""

    search_path: str | None = None

    def __post_init__(self) -> None:
        self._k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._dbg = ctypes.WinDLL("dbghelp", use_last_error=True)
        self._proc = self._k32.GetCurrentProcess()

        self._dbg.SymSetOptions.argtypes = [wintypes.DWORD]
        self._dbg.SymSetOptions.restype = wintypes.DWORD

        self._dbg.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
        self._dbg.SymInitializeW.restype = wintypes.BOOL

        self._dbg.SymCleanup.argtypes = [wintypes.HANDLE]
        self._dbg.SymCleanup.restype = wintypes.BOOL

        self._dbg.SymLoadModuleExW.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            ctypes.c_uint64,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
        ]
        self._dbg.SymLoadModuleExW.restype = ctypes.c_uint64

        self._dbg.SymFromNameW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPVOID]
        self._dbg.SymFromNameW.restype = wintypes.BOOL

        self._initialized = False
        self._mod_base: int | None = None

    def initialize(self) -> None:
        if self._initialized:
            return
        self._dbg.SymSetOptions(SYMOPT_DEBUG | SYMOPT_PUBLICS_ONLY)
        ok = self._dbg.SymInitializeW(self._proc, self.search_path, False)
        if not ok:
            raise DbgHelpError(f"SymInitializeW failed: { _last_error() }")
        self._initialized = True

    def add_symbol_path(self, path: str) -> None:
        """Append an additional symbol search directory."""

        if not self._initialized:
            self.initialize()
        # DbgHelp uses ';' separated search paths.
        if not self.search_path:
            self.search_path = path
        elif path not in self.search_path:
            self.search_path = f"{self.search_path};{path}"
        # Re-initialize with new path is simplest (cleanup+initialize).
        # DbgHelp also supports SymSetSearchPath, but keeping surface minimal.
        self._dbg.SymCleanup(self._proc)
        self._initialized = False
        self.initialize()

    def cleanup(self) -> None:
        if self._initialized:
            self._dbg.SymCleanup(self._proc)
            self._initialized = False
            self._mod_base = None

    def load_module(self, image_path: Path, image_base: int, size_of_image: int) -> int:
        self.initialize()

        mod = self._dbg.SymLoadModuleExW(
            self._proc,
            None,
            str(image_path),
            None,
            ctypes.c_uint64(image_base),
            wintypes.DWORD(size_of_image),
            None,
            0,
        )
        if not mod:
            raise DbgHelpError(f"SymLoadModuleExW failed: { _last_error() }")
        self._mod_base = int(mod)
        return self._mod_base

    def set_undname(self, enable: bool) -> None:
        # This mirrors the C++ tool which enables UNDNAME before resolving C++ names.
        if not self._initialized:
            self.initialize()
        opt = SYMOPT_DEBUG | (SYMOPT_UNDNAME if enable else 0)
        self._dbg.SymSetOptions(opt)

    def sym_rva(self, sym_name: str) -> int | None:
        if not self._initialized or self._mod_base is None:
            raise DbgHelpError("DbgHelp not initialized/module not loaded")

        buf, symp = _make_symbol_info(2048)
        ok = self._dbg.SymFromNameW(self._proc, sym_name, ctypes.cast(symp, wintypes.LPVOID))
        if not ok:
            return None
        sym = symp.contents
        return int(sym.Address - sym.ModBase)

    def __enter__(self) -> "DbgHelp":
        self.initialize()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.cleanup()
