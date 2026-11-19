@echo off
setlocal
set "PYTHON=%~dp0..\..\.venv\Scripts\python.exe"
if not exist "%PYTHON%" (
    echo Project Python environment not found: "%PYTHON%"
    pause
    exit /b 1
)
pushd "%~dp0"
"%PYTHON%" "%~dp0xmss_ota_gui.py"
set "RESULT=%ERRORLEVEL%"
popd
if not "%RESULT%"=="0" pause
exit /b %RESULT%
