@echo off
python "%~dp0prepare_build_identity.py" --module "src/build_info.py"
exit /b %errorlevel%
