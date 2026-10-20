from pathlib import Path
import runpy
import unittest


ROOT = Path(__file__).resolve().parents[1]


class LayoutTests(unittest.TestCase):
    def test_launcher_preserves_project_root_paths(self):
        launcher = runpy.run_path(str(ROOT / 'src' / 'launcher.py'), run_name='layout_test')
        self.assertEqual(launcher['BASE_DIR'], ROOT)
        self.assertEqual(launcher['APP_FILE'], ROOT / 'src' / 'app.py')
        self.assertEqual(launcher['REQUIREMENTS'], ROOT / 'requirements.txt')
        self.assertEqual(launcher['VENV_PYTHON'], ROOT / '.venv' / 'Scripts' / 'python.exe')
        self.assertEqual(launcher['LOG_FILE'], ROOT / 'run_dashboard.log')

    def test_streamlit_initial_screen_without_customer_input(self):
        from streamlit.testing.v1 import AppTest

        for entry in (ROOT / 'src' / 'app.py', ROOT / 'app.py'):
            with self.subTest(entry=entry.relative_to(ROOT)):
                app = AppTest.from_file(str(entry)).run(timeout=30)
                self.assertEqual(len(app.exception), 0)


if __name__ == '__main__':
    unittest.main()
