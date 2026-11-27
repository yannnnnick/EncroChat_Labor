@echo off
setlocal
title Lab - Steuerung
rem Standard ohne Argumente: Presentation Mode. Alternativ --mode fresh oder --mode resume.
pushd "%~dp0"
if errorlevel 1 exit /b 1

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -X utf8 -u start_lab.py %*
    goto finished
)
where py.exe >nul 2>nul
if not errorlevel 1 (
    py -3 -X utf8 -u start_lab.py %*
    goto finished
)
where python.exe >nul 2>nul
if not errorlevel 1 (
    python -X utf8 -u start_lab.py %*
    goto finished
)
echo [LAB] Python ab Version 3.10 fehlt. Installation siehe README.md.
cmd /c exit 1

:finished
set "LAB_EXIT_CODE=%errorlevel%"
popd
if not "%LAB_EXIT_CODE%"=="0" pause
exit /b %LAB_EXIT_CODE%
