@echo off
echo ========================================================
echo   CYBERGUARD: AI-Powered Cyber Defence Operations Center
echo ========================================================
echo Starting CYBERGUARD Flask backend server...

set PYTHON_EXE=C:\Users\Aryan Jena\AppData\Local\Programs\Python\Python311\python.exe
if not exist "%PYTHON_EXE%" (
    set PYTHON_EXE=python
)

start "CYBERGUARD Backend API" "%PYTHON_EXE%" backend\run.py

echo Waiting for backend server to initialize...
timeout /t 3 /nobreak >nul

echo Opening CYBERGUARD Command Dashboard in browser...
start http://127.0.0.1:5000

echo CYBERGUARD is running!
echo Backend API: http://127.0.0.1:5000/api/health
echo Press any key to exit this launcher window...
pause
