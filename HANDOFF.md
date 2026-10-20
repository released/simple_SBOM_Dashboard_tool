# HANDOFF.md

## File-only Python clean follow-up (2026-10-21)

- Changed scripts/clean.ps1, scripts/clean_python.bat and new companion clean_intermediates.ps1. Final cross-profile review found the earlier cleaner still purged whole build/obj/cache folders; replaced it with file allowlists and empty-directory-only removal.
- PASS: shared verify_clean_preservation.ps1 with -CleanActualProject -CheckNestedDelivery -CheckPythonCaches -CheckReparseRejection. Twenty-three protected fixture files plus source retained, including EXE/INI/unknowns inside obj AND root/source caches; known obj/pyc/PYO removed, help/idempotence passed, both native and source/cache junctions rejected before native deletion.
- PASS: actual clean protected delivery hashes unchanged (no build delivery files present). Source/application behavior unchanged from the previously verified baseline; no application rebuild/version bump solely for clean changes. No new packaging or hardware/GUI acceptance claim.
- No private runtime files or new EXEs staged; ordinary reviewed publication only to the existing origin.


## Layout Update 2026-10-20

### Root-cache clean follow-up (2026-10-20)

- Added the exact root `__pycache__` to the existing checked cache targets; unknown build/user-output folders remain protected.
- PASS on resume: actual clean, root/source cache removal, 9 protected build sentinels plus source, idempotence, and junction rejection before deletion. No actual protected build outputs existed; 2 source/launcher/Streamlit screen tests PASS (existing bare-mode context warning only).
- Publication evidence is recorded in workspace `PROJECT_LAYOUT_MIGRATION.md`.

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
