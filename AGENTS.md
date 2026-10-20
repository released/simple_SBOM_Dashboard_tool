# AGENTS.md

## File-only Python Clean

Clean must preflight all cache/source paths before calling the companion `scripts/clean_intermediates.ps1`. Remove allowlisted compiler/PyInstaller files in build/obj and only .pyc/.pyo inside root/source/test/script __pycache__; never recursively purge obj/cache folders. Preserve EXE/INI/unknown files inside those folders; remove only empty directories. Keep both cleaner/helper when reusing this profile and run expanded preservation tests automatically.


- Follow workspace `#READ_ME_FIRST#/PROJECT_LAYOUT.md`.

- The Python clean also removes the explicitly named project-root `__pycache__`; do not scan private output trees for arbitrary folders to purge.
- Application and desktop-launcher logic live under `src`; automation under
  `scripts`; screenshots under `docs/images`. Root launchers are compatibility
  entry points and must keep working.
- Preserve project-root `.venv`, requirements, templates, sample_data, exports,
  and log path semantics. Never publish uploaded/customer SBOMs, generated reports,
  virtual environments, logs, or private vulnerability data.
- Keep `Not scanned != Clean` and scope/unknown-vulnerability semantics intact.
- For layout changes run syntax compilation, `tests` unittest discovery, launcher
  `--check`, and `scripts/clean_python.bat` preservation verification.
- The source requires Python/Streamlit; do not claim a native or standalone EXE
  build unless a real packaging/build path has been implemented and tested.
