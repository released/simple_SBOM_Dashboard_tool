# HANDOFF.md

## Layout Update 2026-10-20

- Application moved to `src/app.py`, desktop launcher to `src/launcher.py`, batch
  automation to `scripts/run_tool.bat`, and three screenshots to `docs/images`.
- The six moves were no-overwrite and SHA-256 verified before the required path
  edits. Root `app.py`, `run_dashboard.pyw`, and `run_dashboard.bat` are thin
  compatibility entries; existing startup commands remain usable.
- Project-root venv, requirements, templates, sample_data, exports, and log path
  semantics are preserved. No customer input or generated report was published.
- Added generic safe Python cache/object clean and focused layout regression tests.

## Actual Verification

- PASS: `python -m compileall -q src tests app.py run_dashboard.pyw`.
- PASS: `python -m unittest discover -s tests -v`, 2 tests: desktop-launcher path
  contract and Streamlit initial screen with no customer input/exceptions.
- PASS: `scripts/run_tool.bat --check`; no package installation/server launch.
- PASS: actual `scripts/clean_python.bat` plus isolated sentinels/idempotence.
  No existing protected build files were present; 9 build sentinels plus source
  were verified in the fixture.
- Streamlit emitted its bare-mode ScriptRunContext warning in the test harness.
- NOT RUN: native/standalone EXE build (none defined), customer SBOM/vulnerability
  data tests, actual desktop-launcher GUI/venv installation.

## Publication

Use existing origin only after staged diff/privacy review. Exact commit/push
result is recorded in workspace `#READ_ME_FIRST#/PROJECT_LAYOUT_MIGRATION.md`.
