import subprocess
import sys
import shutil
from pathlib import Path


ROOT = Path(__file__).parent
DIST = ROOT / "dist"
SPEC_NAME = "rdpwrap-offset-finder.spec"


def check_pyinstaller() -> bool:
    try:
        import PyInstaller  # noqa: F401
        return True
    except ImportError:
        return False


def install_pyinstaller() -> None:
    print("PyInstaller not found, installing...")
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "pyinstaller>=5.0"]
    )


def clean_old_build() -> None:
    for p in [
        ROOT / "build",
        ROOT / "build-gui",
        DIST,
        ROOT / SPEC_NAME,
        ROOT / "rdpwrap-offset-finder-gui.spec",
    ]:
        if p.exists():
            print(f"  removing {p.name}")
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()


def build_console_exe() -> None:
    print("Building console exe from main.py...")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--console",
        "--name", "rdpwrap-offset-finder",
        "--distpath", str(DIST),
        "--workpath", str(ROOT / "build"),
        "--specpath", str(ROOT),
        "--clean",
        "--noconfirm",
        "--hidden-import", "symbols",
        "--hidden-import", "nosymbol",
        "--hidden-import", "nosymbol_arch",
        "--hidden-import", "ms_pdb",
        "--hidden-import", "patches",
        "--hidden-import", "pe_image",
        "--hidden-import", "imports",
        "--hidden-import", "exception_table",
        "--hidden-import", "disasm",
        "--hidden-import", "winver",
        "--hidden-import", "dbghelp",
        str(ROOT / "main.py"),
    ]

    subprocess.check_call(cmd, cwd=ROOT)
    print(f"\nDone! Console exe at: {DIST / 'rdpwrap-offset-finder.exe'}")


def build_gui_exe() -> None:
    print("Building GUI exe from gui.py...")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",
        "--name", "rdpwrap-offset-finder-gui",
        "--distpath", str(DIST),
        "--workpath", str(ROOT / "build-gui"),
        "--specpath", str(ROOT),
        "--clean",
        "--noconfirm",
        "--hidden-import", "symbols",
        "--hidden-import", "nosymbol",
        "--hidden-import", "nosymbol_arch",
        "--hidden-import", "ms_pdb",
        "--hidden-import", "patches",
        "--hidden-import", "pe_image",
        "--hidden-import", "imports",
        "--hidden-import", "exception_table",
        "--hidden-import", "disasm",
        "--hidden-import", "winver",
        "--hidden-import", "dbghelp",
        str(ROOT / "gui.py"),
    ]

    subprocess.check_call(cmd, cwd=ROOT)
    print(f"\nDone! GUI exe at: {DIST / 'rdpwrap-offset-finder-gui.exe'}")


def main() -> None:
    if not check_pyinstaller():
        install_pyinstaller()

    print("Cleaning old build artifacts...")
    clean_old_build()

    build_console_exe()
    build_gui_exe()
    print(f"\nBoth executables are in: {DIST}")


if __name__ == "__main__":
    main()
