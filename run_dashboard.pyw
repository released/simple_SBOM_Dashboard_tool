from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path
from tkinter import BOTH, DISABLED, NORMAL, Button, Label, Tk, messagebox


BASE_DIR = Path(__file__).resolve().parent
VENV_PYTHON = BASE_DIR / ".venv" / "Scripts" / "python.exe"
REQUIREMENTS = BASE_DIR / "requirements.txt"
APP_FILE = BASE_DIR / "app.py"
LOG_FILE = BASE_DIR / "run_dashboard.log"
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def write_log(message: str) -> None:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with LOG_FILE.open("a", encoding="utf-8") as log:
        log.write(f"[{timestamp}] {message}\n")


def subprocess_flags() -> int:
    return CREATE_NO_WINDOW if os.name == "nt" else 0


def current_console_python() -> Path | None:
    executable = Path(sys.executable)
    if executable.name.lower() == "pythonw.exe":
        candidate = executable.with_name("python.exe")
        if candidate.exists():
            return candidate
    if executable.exists():
        return executable
    return None


def run_command(candidates: list[list[str]], cwd: Path, description: str) -> None:
    errors: list[str] = []
    for args in candidates:
        write_log(f"{description}: {' '.join(args)}")
        with LOG_FILE.open("a", encoding="utf-8") as log:
            try:
                result = subprocess.run(
                    args,
                    cwd=str(cwd),
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    creationflags=subprocess_flags(),
                    check=False,
                )
            except FileNotFoundError as exc:
                errors.append(f"{args[0]}: {exc}")
                continue
        if result.returncode == 0:
            return
        errors.append(f"{' '.join(args)} returned {result.returncode}")
    raise RuntimeError(f"{description} failed. See log: {LOG_FILE}\n" + "\n".join(errors))


def ensure_virtual_environment() -> None:
    if VENV_PYTHON.exists():
        return

    candidates: list[list[str]] = []
    console_python = current_console_python()
    if console_python is not None:
        candidates.append([str(console_python), "-m", "venv", ".venv"])
    candidates.extend(
        [
            ["py", "-3.10", "-m", "venv", ".venv"],
            ["py", "-3", "-m", "venv", ".venv"],
            ["python", "-m", "venv", ".venv"],
        ]
    )
    run_command(candidates, BASE_DIR, "Create virtual environment")

    if not VENV_PYTHON.exists():
        raise RuntimeError("Virtual environment was created, but .venv\\Scripts\\python.exe was not found.")


def install_requirements() -> None:
    run_command(
        [[str(VENV_PYTHON), "-m", "pip", "install", "-r", str(REQUIREMENTS)]],
        BASE_DIR,
        "Install requirements",
    )


def find_available_port(start_port: int = 8501) -> int:
    port = start_port
    while port < 9000:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                port += 1
                continue
        return port
    raise RuntimeError("No available local port found between 8501 and 8999.")


def wait_for_http(url: str, process: subprocess.Popen[str], timeout_seconds: int = 60) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Streamlit exited early with code {process.returncode}. See log: {LOG_FILE}")
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(1)
    raise RuntimeError(f"Timed out waiting for Streamlit at {url}. See log: {LOG_FILE}")


class DashboardLauncher:
    def __init__(self, root: Tk) -> None:
        self.root = root
        self.process: subprocess.Popen[str] | None = None
        self.url = ""

        self.root.title("SBOM Dashboard")
        self.root.geometry("520x210")
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self.stop)

        self.status = Label(
            root,
            text="Starting SBOM Dashboard...",
            anchor="w",
            justify="left",
            padx=16,
            pady=16,
            wraplength=480,
        )
        self.status.pack(fill=BOTH, expand=True)

        self.open_button = Button(root, text="Open Dashboard", command=self.open_dashboard, state=DISABLED)
        self.open_button.pack(fill="x", padx=16, pady=(0, 8))

        self.log_button = Button(root, text="Open Log", command=self.open_log)
        self.log_button.pack(fill="x", padx=16, pady=(0, 8))

        self.stop_button = Button(root, text="Stop Dashboard", command=self.stop, state=DISABLED)
        self.stop_button.pack(fill="x", padx=16, pady=(0, 16))

        threading.Thread(target=self.start_dashboard, daemon=True).start()

    def set_status(self, text: str) -> None:
        self.root.after(0, lambda: self.status.config(text=text))

    def enable_running_controls(self) -> None:
        self.root.after(0, lambda: self.open_button.config(state=NORMAL))
        self.root.after(0, lambda: self.stop_button.config(state=NORMAL))

    def show_error(self, message: str) -> None:
        def _show() -> None:
            self.stop_button.config(text="Close", state=NORMAL)
            messagebox.showerror("SBOM Dashboard", message)

        self.root.after(0, _show)

    def start_dashboard(self) -> None:
        try:
            LOG_FILE.write_text("", encoding="utf-8")
            write_log(f"Project: {BASE_DIR}")

            self.set_status("Checking Python virtual environment...")
            ensure_virtual_environment()

            self.set_status("Installing or checking Python packages. This may take a few minutes on first run...")
            install_requirements()

            port = find_available_port()
            self.url = f"http://127.0.0.1:{port}"
            self.set_status(f"Starting Streamlit server...\n{self.url}")

            with LOG_FILE.open("a", encoding="utf-8") as log:
                self.process = subprocess.Popen(
                    [
                        str(VENV_PYTHON),
                        "-m",
                        "streamlit",
                        "run",
                        str(APP_FILE),
                        "--server.address=127.0.0.1",
                        f"--server.port={port}",
                        "--server.headless=true",
                        "--browser.gatherUsageStats=false",
                    ],
                    cwd=str(BASE_DIR),
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    creationflags=subprocess_flags(),
                    text=True,
                )

            wait_for_http(self.url, self.process)
            self.set_status(
                "Dashboard is running.\n"
                f"{self.url}\n\n"
                "Keep this window open while using the dashboard. Closing it stops the server."
            )
            self.enable_running_controls()
            webbrowser.open(self.url)
        except Exception as exc:
            write_log(f"ERROR: {exc}")
            self.set_status(f"Failed to start dashboard.\nSee log: {LOG_FILE}")
            self.show_error(f"{exc}\n\nLog file:\n{LOG_FILE}")

    def open_dashboard(self) -> None:
        if self.url:
            webbrowser.open(self.url)

    def open_log(self) -> None:
        if LOG_FILE.exists() and os.name == "nt":
            os.startfile(LOG_FILE)  # type: ignore[attr-defined]
        elif LOG_FILE.exists():
            webbrowser.open(LOG_FILE.as_uri())

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.set_status("Stopping dashboard...")
            self.process.terminate()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.root.destroy()


def main() -> None:
    if "--check" in sys.argv:
        print("Launcher check passed.")
        return

    root = Tk()
    DashboardLauncher(root)
    root.mainloop()


if __name__ == "__main__":
    main()
