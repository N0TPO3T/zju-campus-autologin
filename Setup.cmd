@echo off
setlocal
cd /d "%~dp0"
if not exist "%~dp0setup_gui.py" goto missing
py -3 -c "import sys, tkinter; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if not errorlevel 1 goto use_py
python -c "import sys, tkinter; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if not errorlevel 1 goto use_python
echo No supported Python interpreter was found.
echo Install Python 3.10 or later with Tcl/Tk support and the Python launcher
echo or add python.exe to PATH, then run Setup.cmd again.
echo No files were downloaded and no scheduled task was changed.
pause
exit /b 1

:use_py
py -3 "%~dp0setup_gui.py"
goto result

:use_python
python "%~dp0setup_gui.py"
goto result

:missing
echo setup_gui.py is missing. Keep the complete source directory together.
pause
exit /b 1

:result
if not errorlevel 1 exit /b 0
echo Setup could not complete. Check the error above and that Tk is installed.
pause
exit /b 1
