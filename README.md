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
LocalOnlyPatch.Arch=1
LocalOnlyOffset.Arch=OFFSET_HEX_VALUE
LocalOnlyCode.Arch=jmpshort
SingleUserPatch.Arch=1
SingleUserOffset.Arch=OFFSET_HEX_VALUE
SingleUserCode.Arch=mov_eax_1_nop_2
DefPolicyPatch.Arch=1
DefPolicyOffset.Arch=OFFSET_HEX_VALUE
DefPolicyCode.Arch=CDefPolicy_Query_eax_rcx_jmp
SLInitHook.Arch=1
SLInitOffset.Arch=OFFSET_HEX_VALUE
SLInitFunc.Arch=New_CSLQuery_Initialize

[VERSION.BUILD.REVISION.NUMBER-SLInit]
bInitialized.Arch      =OFFSET_HEX_VALUE
bServerSku.Arch        =OFFSET_HEX_VALUE
lMaxUserSessions.Arch  =OFFSET_HEX_VALUE
bAppServerAllowed.Arch =OFFSET_HEX_VALUE
bRemoteConnAllowed.Arch=OFFSET_HEX_VALUE
bMultimonAllowed.Arch  =OFFSET_HEX_VALUE
ulMaxDebugSessions.Arch=OFFSET_HEX_VALUE
bFUSEnabled.Arch       =OFFSET_HEX_VALUE
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for educational purposes and authorized testing only. Please ensure you comply with applicable laws and regulations when using this tool. Misuse of this tool may violate terms of service or local laws.