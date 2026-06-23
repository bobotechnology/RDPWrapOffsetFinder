from __future__ import annotations

import os
import ssl
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path

import pefile


MS_SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"

# Retry policy for transient network failures.
# 404 responses short-circuit immediately (PDB genuinely missing).
_MAX_RETRIES = 3
_RETRY_BACKOFF_SECONDS = (1.0, 2.0, 5.0)
_DOWNLOAD_TIMEOUT = 60
_CHUNK_SIZE = 64 * 1024

# PDB files start with one of these magic signatures (MSF 3.00 / 7.00 / BigPDB).
# Used to sanity-check downloads so we never cache a truncated HTML error page.
_PDB_MAGICS = (
    b"Microsoft C/C++ MSF 7.00",
    b"Microsoft C/C++ program database 2.00",
    b"Microsoft C/C++ MSF 6.00",
    b"DSMAP",
    b"MSDS",
    b"MD20",
)


@dataclass(frozen=True)
class PdbInfo:
    pdb_name: str
    guid_hex: str
    age: int

    @property
    def guid_age(self) -> str:
        return f"{self.guid_hex}{self.age}"


def _u32(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 4], "little", signed=False)


def get_pdb_info(pe: pefile.PE) -> PdbInfo:
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]])
    except Exception:
        pass

    entries = getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []
    for e in entries:
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


def _is_transient_http_error(exc: BaseException) -> bool:
    if isinstance(exc, urllib.error.HTTPError):
        # 404 means the PDB is genuinely absent on the server; retrying won't help.
        return exc.code != 404
    # URLError covers DNS failures, refused connections, timeouts (socket.timeout
    # is wrapped into URLError by urllib). TimeoutError / ConnectionError are
    # raised by the underlying socket layer in some Python builds.
    return isinstance(exc, (urllib.error.URLError, TimeoutError, ConnectionError, OSError))


def _probe_range_support(url: str, ssl_ctx: ssl.SSLContext) -> tuple[bool, int]:
    """Issue HEAD to learn whether the server advertises range requests and the
    total content length. Returns (supports_range, total_size). On any failure
    returns (False, 0) so the caller falls back to a plain GET."""
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "rdpwrap-offset-finder"})
    try:
        with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as r:
            accepts = r.headers.get("Accept-Ranges", "").lower() == "bytes"
            try:
                total = int(r.headers.get("Content-Length", "0") or "0")
            except ValueError:
                total = 0
            return accepts, total
    except Exception:
        return False, 0


def _validate_pdb_magic(path: Path) -> None:
    """Reject obviously-corrupt downloads (HTML error pages, empty files, etc.)
    by checking the PDB magic signature."""
    try:
        with open(path, "rb") as f:
            head = f.read(32)
    except OSError as exc:
        raise RuntimeError(f"Cannot read downloaded PDB for validation: {exc}") from exc

    if not head:
        raise RuntimeError("Downloaded PDB is empty")

    for magic in _PDB_MAGICS:
        if head.startswith(magic):
            return

    raise RuntimeError(
        f"Downloaded PDB has unexpected magic (got {head[:24]!r}); "
        f"server may have returned an error page"
    )


def _download_once(url: str, dst: Path, ssl_ctx: ssl.SSLContext) -> Path:
    """Perform a single download attempt with optional Range resume.

    - Probes Accept-Ranges via HEAD; if supported and a partial file exists,
      appends to it (HTTP 206). Otherwise does a fresh GET (HTTP 200).
    - Streams to ``dst.with_suffix(dst.suffix + ".part")`` in 64KB chunks so
      large PDBs don't have to fit in RAM.
    - Atomically renames the .part file to ``dst`` after validating the PDB
      magic, so a crash mid-download never leaves a corrupt cached file.
    """
    supports_range, _total = _probe_range_support(url, ssl_ctx)
    tmp = dst.with_suffix(dst.suffix + ".part")

    existing = dst.stat().st_size if dst.exists() else 0
    resume_from = existing if (supports_range and existing > 0) else 0

    headers = {"User-Agent": "rdpwrap-offset-finder"}
    if resume_from > 0:
        headers["Range"] = f"bytes={resume_from}-"

    if resume_from == 0:
        # Fresh download: discard any stale .part file from a previous attempt.
        tmp.unlink(missing_ok=True)

    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=_DOWNLOAD_TIMEOUT, context=ssl_ctx) as r:
        # If we asked for a range but the server ignored it (returned 200),
        # we must truncate and start over to avoid appending duplicates.
        status = getattr(r, "status", None) or 200
        if resume_from > 0 and status == 200:
            resume_from = 0
            tmp.unlink(missing_ok=True)

        mode = "ab" if resume_from > 0 else "wb"
        with open(tmp, mode) as f:
            while True:
                chunk = r.read(_CHUNK_SIZE)
                if not chunk:
                    break
                f.write(chunk)

    _validate_pdb_magic(tmp)

    # Atomic on the same filesystem (cache_root is always on disk).
    tmp.replace(dst)
    return dst


def ensure_pdb_downloaded(pdb: PdbInfo, cache_root: Path, *, server: str = MS_SYMBOL_SERVER) -> Path:
    """Download a PDB from the Microsoft Symbol Server with caching, retry and
    resume. Returns the local path of the cached file.

    Behavior:
    - If the file already exists and is non-empty, it is returned immediately.
    - Otherwise up to ``_MAX_RETRIES`` attempts are made with exponential
      backoff. Transient errors (5xx, timeouts, connection resets) are retried;
      404 raises immediately since the PDB is genuinely missing.
    - Each attempt streams to a ``.part`` temp file and atomically renames on
      success, so a half-downloaded file is never exposed as a valid cache entry.
    - If the server supports Range requests, an interrupted download resumes
      from the existing ``.part`` bytes on the next attempt.
    """
    dst_dir = cache_root / pdb.pdb_name / pdb.guid_age
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / pdb.pdb_name
    if dst.exists() and dst.stat().st_size > 0:
        # Validate cached file isn't a corrupt leftover; if it is, redownload.
        try:
            _validate_pdb_magic(dst)
            return dst
        except RuntimeError:
            dst.unlink(missing_ok=True)

    url = f"{server}/{pdb.pdb_name}/{pdb.guid_age}/{pdb.pdb_name}"
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = True
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED

    last_err: Exception | None = None
    for attempt in range(_MAX_RETRIES):
        try:
            return _download_once(url, dst, ssl_ctx)
        except Exception as exc:  # noqa: BLE001 - we re-raise the last error below
            last_err = exc if isinstance(exc, Exception) else RuntimeError(str(exc))
            if not _is_transient_http_error(exc):
                # 404 or validation failure — don't waste retries.
                raise
            if attempt < _MAX_RETRIES - 1:
                time.sleep(_RETRY_BACKOFF_SECONDS[attempt])

    raise RuntimeError(
        f"PDB download failed after {_MAX_RETRIES} attempts: {url} "
        f"(last error: {last_err})"
    ) from last_err
