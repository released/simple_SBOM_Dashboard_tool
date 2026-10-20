# SELF_CHECK.md

## File-only Python clean follow-up (2026-10-21)

- Changed scripts/clean.ps1, scripts/clean_python.bat and new companion clean_intermediates.ps1. Final cross-profile review found the earlier cleaner still purged whole build/obj/cache folders; replaced it with file allowlists and empty-directory-only removal.
- PASS: shared verify_clean_preservation.ps1 with -CleanActualProject -CheckNestedDelivery -CheckPythonCaches -CheckReparseRejection. Twenty-three protected fixture files plus source retained, including EXE/INI/unknowns inside obj AND root/source caches; known obj/pyc/PYO removed, help/idempotence passed, both native and source/cache junctions rejected before native deletion.
- PASS: actual clean protected delivery hashes unchanged (no build delivery files present). Source/application behavior unchanged from the previously verified baseline; no application rebuild/version bump solely for clean changes. No new packaging or hardware/GUI acceptance claim.
- No private runtime files or new EXEs staged; ordinary reviewed publication only to the existing origin.


## Layout Audit 2026-10-20

### Root-cache clean follow-up (2026-10-20)

- Added the exact root `__pycache__` to the existing checked cache targets; unknown build/user-output folders remain protected.
- PASS on resume: actual clean, root/source cache removal, 9 protected build sentinels plus source, idempotence, and junction rejection before deletion. No actual protected build outputs existed; 2 source/launcher/Streamlit screen tests PASS (existing bare-mode context warning only).
- Publication evidence is recorded in workspace `PROJECT_LAYOUT_MIGRATION.md`.

| Check | Actual result |
| --- | --- |
| Six source/script/screenshot moves; no overwrite; SHA-256 | PASS |
| `python -m compileall -q src tests app.py run_dashboard.pyw` | PASS |
| `python -m unittest discover -s tests -v` | PASS, 2 tests |
| Source launcher root/requirements/venv/app/log paths | PASS |
| Streamlit initial page with no customer input | PASS, no app exceptions |
| `scripts/run_tool.bat --check` | PASS |
| Actual `scripts/clean_python.bat` | PASS |
| Isolated EXE/INI/DLL/firmware/data/log/unknown/evidence/source sentinels and repeat-clean | PASS |
| Native/standalone EXE packaging | NOT RUN, no such build path |
| Customer-input/report regression and desktop GUI/first-install | NOT RUN, directory task only |

Keep private data, exports, venv, caches, and logs out of the Git diff. Do not
interpret this layout audit as product vulnerability/security acceptance.
