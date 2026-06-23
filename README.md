# RDPWrap Offset Finder

A tool to find offsets in `termsrv.dll` for use with [RDPWrap](https://github.com/stascorp/rdpwrap) and generate corresponding `rdpwrap.ini` sections.

## Features

- Extracts RDPWrap offsets from `termsrv.dll` for enabling multiple RDP connections
- Supports both symbol-based and heuristic analysis methods
- Generates properly formatted INI sections compatible with RDPWrap
- Handles both x86 and x64 architectures via a unified `ArchStrategy` layer
- PDB downloads from the Microsoft Symbol Server with retry, resume and magic validation
- Can be built as standalone console and GUI executables via PyInstaller
- 55 unit tests covering patch detection, PE image mapping, exception directory parsing and INI normalization
- Optional cross-platform GUI (tkinter) for users who prefer not to use the command line

## Usage

```bash
# Analyze default system termsrv.dll with symbol-based approach
rdpwrap-offset-finder

# Analyze specific termsrv.dll file
rdpwrap-offset-finder C:\Path\To\termsrv.dll

# Use heuristic pattern search instead of PDB symbols
rdpwrap-offset-finder C:\Path\To\termsrv.dll --nosymbol
```

### GUI mode

```bash
rdpwrap-offset-finder-gui
```

The GUI lets you pick a `termsrv.dll` file, choose between **Symbol-based** and **No-symbol** analysis, and run the analysis with one click. Results are shown in an editable text pane with **Copy** and **Save INI…** buttons. Analysis runs in the background so the window stays responsive while the PDB is downloaded.

### Options

- `[termsrv]`: Path to termsrv.dll (default: `%SystemRoot%\System32\termsrv.dll`)
- `--nosymbol`: Use heuristic pattern search instead of PDB symbols
- `--help`: Show help message and exit

### Output

- INI sections are written to **stdout**.
- In `--nosymbol` mode, a diagnostic log is written to `./log/<version>_<arch>.log` in the current working directory, recording string RVAs, IAT slots, xref hits and disassembly context around each patch site.

## Build standalone executable

```bash
python build_exe.py
```

Output goes to:

- `dist/rdpwrap-offset-finder.exe` — console/CLI version
- `dist/rdpwrap-offset-finder-gui.exe` — windowed GUI version

Requires Python 3.9+ and PyInstaller. The GUI executable embeds Tcl/Tk and can be run on a machine without a separate Python installation.

## How It Works

The tool works in two modes:

1. **Symbol-based** (default): Downloads the PDB from the Microsoft Symbol Server (with retry, Range-resume and PDB magic validation) and uses `DbgHelp` to resolve function/variable RVAs by name, then applies instruction-level pattern matching to locate the exact patch site within each function.
2. **Heuristic** (`--nosymbol`): When no symbols are available, the tool locates C++ class/method name strings in `.rdata`, finds cross-references to them (x64: `LEA [RIP+disp]` / `MOV reg, imm64`; x86: `PUSH imm32` / `MOV reg, imm32`), derives function boundaries (x64: `.pdata` exception directory + unwind chain backtrace; x86: `push ebp; mov ebp, esp` prologue scan), and applies the same instruction-level pattern matching.

Both modes extract the same information but may be more or less reliable depending on the availability of symbols and the specific version of `termsrv.dll`.

### Architecture

```
termsrv.py        # Top-level orchestration: PE load -> version -> symbol/nosymbol -> INI normalize
├── symbols.py    # Mode 1: PDB-based analysis (DbgHelp)
├── nosymbol.py   # Mode 2: heuristic analysis (shared x86/x64 flow)
│   └── nosymbol_arch.py  # ArchStrategy protocol + X86Strategy / X64Strategy
├── patches.py    # Patch pattern engine: LocalOnly / SingleUser / DefPolicy
├── ms_pdb.py     # PDB download (retry + resume + magic check)
├── pe_image.py   # PE -> flat memory image
├── imports.py    # IAT slot lookup
├── exception_table.py  # x64 .pdata parsing + unwind chain backtrace
├── disasm.py     # iced-x86 decoder context
├── winver.py     # VS_VERSIONINFO extraction
└── dbghelp.py    # Windows DbgHelp API ctypes bindings
```

The `nosymbol` module uses an `ArchStrategy` protocol to isolate the handful of operations that differ between x86 and x64 (function enumeration, string xref instruction, JMP thunk resolution, CDefPolicy::Query locating, SLInit global scan), keeping the main `analyze()` flow a single linear path shared by both architectures.

## Testing

```bash
python -m pytest tests/
```

55 tests cover:

- `patches.py`: LocalOnly / DefPolicy / SingleUser pattern detection (positive + negative cases, x86 & x64)
- `pe_image.py`: section mapping, VirtualSize truncation, zero-fill of uninitialized regions
- `exception_table.py`: `.pdata` parsing, unwind chain backtrace, indirect unwind RVA
- `nosymbol` xref helpers: `_xref_lea_rip` (x64) and `_xref_imm32_x86` (x86)
- `termsrv._normalize_ini_output`: key ordering, SLInit alignment, defaults, garbage resilience
- `winver.FileVersion`: field decoding, `to_ini_section()` formatting, frozen dataclass

Tests use iced-x86's `Encoder` (not `BlockEncoder`) to force rel32 branch encodings, giving deterministic instruction layouts for offset assertions.

## Output Format

The tool outputs INI sections that can be added to `rdpwrap.ini`:

```ini
[VERSION_NUMBER]
; Enable local-only patch
LocalOnlyPatch.Arch=FLAG_VALUE
; Offset for local-only patch
LocalOnlyOffset.Arch=HEX_OFFSET_VALUE
; Code type for local-only patch (e.g., jmpshort, nopjmp)
LocalOnlyCode.Arch=CODE_TYPE

; Enable single-user patch
SingleUserPatch.Arch=FLAG_VALUE
; Offset for single-user patch
SingleUserOffset.Arch=HEX_OFFSET_VALUE
; Code type for single-user patch (e.g., mov_eax_1_nop_N, nop_N)
SingleUserCode.Arch=CODE_TYPE

; Enable default policy patch
DefPolicyPatch.Arch=FLAG_VALUE
; Offset for default policy patch
DefPolicyOffset.Arch=HEX_OFFSET_VALUE
; Code type for default policy patch
;   e.g. CDefPolicy_Query_eax_rcx       (register-based CMP)
;        CDefPolicy_Query_r9d_rdi_jmp   (register-based MOV+CMP+JNE)
DefPolicyCode.Arch=POLICY_CODE_TYPE

; Enable SLInit hook
SLInitHook.Arch=FLAG_VALUE
; Offset for SLInit hook
SLInitOffset.Arch=HEX_OFFSET_VALUE
; Function name for SLInit
SLInitFunc.Arch=FUNCTION_NAME

[VERSION_NUMBER-SLInit]
; Offset for bInitialized variable
bInitialized.Arch      =HEX_OFFSET_VALUE
; Offset for bServerSku variable
bServerSku.Arch        =HEX_OFFSET_VALUE
; Offset for lMaxUserSessions variable
lMaxUserSessions.Arch  =HEX_OFFSET_VALUE
; Offset for bAppServerAllowed variable
bAppServerAllowed.Arch =HEX_OFFSET_VALUE
; Offset for bRemoteConnAllowed variable
bRemoteConnAllowed.Arch=HEX_OFFSET_VALUE
; Offset for bMultimonAllowed variable
bMultimonAllowed.Arch  =HEX_OFFSET_VALUE
; Offset for ulMaxDebugSessions variable
ulMaxDebugSessions.Arch=HEX_OFFSET_VALUE
; Offset for bFUSEnabled variable
bFUSEnabled.Arch       =HEX_OFFSET_VALUE
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for educational purposes and authorized testing only. Please ensure you comply with applicable laws and regulations when using this tool. Misuse of this tool may violate terms of service or local laws.
