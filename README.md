# RDPWrap Offset Finder

A tool to find offsets in `termsrv.dll` for use with [RDPWrap](https://github.com/stascorp/rdpwrap) and generate corresponding `rdpwrap.ini` sections.

## Features

- Extracts RDPWrap offsets from `termsrv.dll`
- Supports both symbol-based and heuristic analysis
- Generates properly formatted INI sections
- Handles both x86 and x64 architectures
- Works with various Windows versions

## Installation

### Prerequisites

- Python 3.9 or higher
- Windows OS (since this analyzes Windows system files)

### From Source

```bash
git clone <repository-url>
cd rdpwrap-offset-finder
pip install .
```

### Direct Install

```bash
pip install git+https://github.com/yourusername/rdpwrap-offset-finder.git
```

## Usage

### Basic Usage

```bash
# Analyze default system termsrv.dll with symbol-based approach
rdpwrap-offset-finder

# Analyze specific termsrv.dll file
rdpwrap-offset-finder /path/to/termsrv.dll

# Use heuristic pattern search instead of PDB symbols
rdpwrap-offset-finder --nosymbol
```

### Options

- `termsrv`: Path to termsrv.dll (default: `%SystemRoot%\System32\termsrv.dll`)
- `--nosymbol`: Use heuristic pattern search instead of PDB symbols

## How It Works

The tool works in two modes:

1. **Symbol-based** (default): Uses PDB files to locate functions and variables
2. **Heuristic** (with `--nosymbol`): Uses pattern matching to find relevant code sections

Both approaches extract the same information but may be more or less reliable depending on the availability of symbols and the specific version of `termsrv.dll`.

## Output Format

The tool outputs INI sections that can be added to `rdpwrap.ini`:

```ini
[10.0.19041.4474]
LocalOnlyPatch.x64=1
LocalOnlyOffset.x64=93EB1
LocalOnlyCode.x64=jmpshort
SingleUserPatch.x64=1
...
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.