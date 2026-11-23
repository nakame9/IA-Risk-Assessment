@echo off
rem Chay cong cu danh gia rui ro cho SME. Vi du:
rem   run.bat init "D:\Khach hang\Cong ty A" --company "Cong ty A"
rem   run.bat run "D:\Khach hang\Cong ty A"
rem   run.bat run "D:\Khach hang\Cong ty A" --baseline "D:\Khach hang\Cong ty A\runs\2026-11-23\state.json"
where python >nul 2>nul
if errorlevel 1 (
  echo Khong tim thay Python. Cai Python 3.11+ tu https://www.python.org/downloads/ va chon "Add python.exe to PATH".
  exit /b 1
)
python "%~dp0sme.py" %*
