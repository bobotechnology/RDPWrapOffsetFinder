# RDPWrap Offset Finder

A tool to find offsets in `termsrv.dll` for use with [RDPWrap](https://github.com/stascorp/rdpwrap) and generate corresponding `rdpwrap.ini` sections.

## ✨ Features

- Extracts RDPWrap offsets from `termsrv.dll` for enabling multiple RDP connections
- Supports both symbol-based and heuristic analysis methods
- Generates properly formatted INI sections compatible with RDPWrap
- Handles both x86 and x64 architectures
- Works with various Windows versions
- Command-line interface for easy automation
- Fixed lowercase register naming in generated configurations

## 🛠️ Installation

### Prerequisites

- Python 3.9 or higher
- Windows OS (since this analyzes Windows system files)
- Administrator privileges (recommended for accessing system files)

### From Source

```bash
git clone https://github.com/llccd/rdpwrap-offset-finder.git
cd rdpwrap-offset-finder
pip install -e .
```

### Direct Install

```bash
pip install git+https://github.com/llccd/rdpwrap-offset-finder.git
```

## 📖 Usage

### Basic Usage

```bash
# Analyze default system termsrv.dll with symbol-based approach
rdpwrap-offset-finder

# Analyze specific termsrv.dll file
rdpwrap-offset-finder C:\Path\To\termsrv.dll

# Use heuristic pattern search instead of PDB symbols
rdpwrap-offset-finder --nosymbol

# Analyze specific file with heuristic approach
rdpwrap-offset-finder C:\Path\To\termsrv.dll --nosymbol
```

### Options

- `[termsrv]`: Path to termsrv.dll (default: `%SystemRoot%\System32\termsrv.dll`)
- `--nosymbol`: Use heuristic pattern search instead of PDB symbols
- `--help`: Show help message and exit

## 🔍 How It Works

The tool works in two modes:

1. **Symbol-based** (default): Uses PDB files to locate functions and variables with high precision
2. **Heuristic** (with `--nosymbol`): Uses pattern matching to find relevant code sections when symbols are unavailable

Both approaches extract the same information but may be more or less reliable depending on the availability of symbols and the specific version of `termsrv.dll`.

## 📤 Output Format

The tool outputs INI sections that can be added to `rdpwrap.ini`:

```ini
[VERSION.BUILD.REVISION.NUMBER]
; Enable local-only patch
LocalOnlyPatch.Arch=FLAG_VALUE
; Offset for local-only patch
LocalOnlyOffset.Arch=HEX_OFFSET_VALUE
; Code type for local-only patch (e.g., jmpshort, nop_N)
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
; Code type for default policy patch (e.g., CDefPolicy_Query_eax_rcx_jmp)
DefPolicyCode.Arch=POLICY_CODE_TYPE

; Enable SLInit hook
SLInitHook.Arch=FLAG_VALUE
; Offset for SLInit hook
SLInitOffset.Arch=HEX_OFFSET_VALUE
; Function name for SLInit
SLInitFunc.Arch=FUNCTION_NAME

[VERSION.BUILD.REVISION.NUMBER-SLInit]
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

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for educational purposes and authorized testing only. Please ensure you comply with applicable laws and regulations when using this tool. Misuse of this tool may violate terms of service or local laws.