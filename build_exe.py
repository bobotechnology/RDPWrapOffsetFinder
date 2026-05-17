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
    for p in [ROOT / "build", DIST, ROOT / SPEC_NAME]:
        if p.exists():
            print(f"  removing {p.name}")
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()


def build_exe() -> None:
    print(f"Building exe from main.py...")

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
        str(ROOT / "main.py"),
    ]

    subprocess.check_call(cmd, cwd=ROOT)
    print(f"\nDone! Exe at: {DIST / 'rdpwrap-offset-finder.exe'}")


def main() -> None:
    if not check_pyinstaller():
        install_pyinstaller()

    print("Cleaning old build artifacts...")
    clean_old_build()

    build_exe()


if __name__ == "__main__":
    main()
