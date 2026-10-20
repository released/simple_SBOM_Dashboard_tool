"""Compatibility entry for the desktop launcher."""
from pathlib import Path
import runpy

if __name__ == "__main__":
    runpy.run_path(str(Path(__file__).resolve().parent / "src" / "launcher.py"), run_name="__main__")
