@echo off
rem One-click build for Windows: runs tools\build.py with whatever Python 3 is available.
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if not errorlevel 1 (
    py -3 -I tools\build.py %*
    goto :done
)
where python >nul 2>&1
if not errorlevel 1 (
    python -I tools\build.py %*
    goto :done
)
echo [!] Python 3 not found. Install it from https://www.python.org/ and retry.
pause
exit /b 1
:done
if errorlevel 1 (
    echo.
    echo [!] build failed
    pause
    exit /b 1
)
echo.
echo Done. Run dist\BigRiceScan.bat to start.
pause
