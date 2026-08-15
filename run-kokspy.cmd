@echo off
setlocal
cd /d "%~dp0"
if "%~1"=="" (
  echo Drag a Windows EXE or DLL onto this file, or run:
  echo   run-kokspy.cmd C:\path\to\program.exe
  echo.
  kokspy.exe -version
  pause
  exit /b 0
)
kokspy.exe "%~1"
if errorlevel 1 pause
