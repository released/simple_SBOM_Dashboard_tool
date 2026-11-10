from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from build_info import BUILD_LABEL, BUILD_DATETIME, BUILD_VERSION
from streamlit.testing.v1 import AppTest

if __name__ == '__main__':
    app = AppTest.from_file(str(ROOT / 'src/app.py')).run(timeout=30)
    assert not app.exception, [e.message for e in app.exception]
    assert app.title[0].value == 'Offline SBOM Dashboard'
    assert any(BUILD_LABEL in m.value and 'text-align:right' in m.value and BUILD_DATETIME in m.value for m in app.markdown)
    assert (ROOT / 'VERSION').read_text().strip() == BUILD_VERSION
    print('PASS: real Streamlit app renders prepared right header; no input files or scans replayed')
