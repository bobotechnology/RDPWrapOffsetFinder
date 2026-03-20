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
LocalOnlyPatch.Arch=FLAG_VALUE
LocalOnlyOffset.Arch=HEX_OFFSET_VALUE
LocalOnlyCode.Arch=CODE_TYPE
SingleUserPatch.Arch=FLAG_VALUE
SingleUserOffset.Arch=HEX_OFFSET_VALUE
SingleUserCode.Arch=CODE_TYPE
DefPolicyPatch.Arch=FLAG_VALUE
DefPolicyOffset.Arch=HEX_OFFSET_VALUE
DefPolicyCode.Arch=POLICY_CODE_TYPE
SLInitHook.Arch=FLAG_VALUE
SLInitOffset.Arch=HEX_OFFSET_VALUE
SLInitFunc.Arch=FUNCTION_NAME

[VERSION.BUILD.REVISION.NUMBER-SLInit]
bInitialized.Arch      =HEX_OFFSET_VALUE
bServerSku.Arch        =HEX_OFFSET_VALUE
lMaxUserSessions.Arch  =HEX_OFFSET_VALUE
bAppServerAllowed.Arch =HEX_OFFSET_VALUE
bRemoteConnAllowed.Arch=HEX_OFFSET_VALUE
bMultimonAllowed.Arch  =HEX_OFFSET_VALUE
ulMaxDebugSessions.Arch=HEX_OFFSET_VALUE
bFUSEnabled.Arch       =HEX_OFFSET_VALUE
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for educational purposes and authorized testing only. Please ensure you comply with applicable laws and regulations when using this tool. Misuse of this tool may violate terms of service or local laws.