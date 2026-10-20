# AGENTS.md

- Follow workspace `#READ_ME_FIRST#/PROJECT_LAYOUT.md`.
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
