@echo off
setlocal
cd /d "%~dp0"

if not exist tools mkdir tools

echo [1/3] Testing KokSpy...
go test ./... || exit /b 1

echo [2/3] Building native Windows GUI...
go build -trimpath -ldflags "-H windowsgui -s -w" -o KokSpy.exe ./cmd/kokspy || exit /b 1

echo [3/3] Building optional CLI tools...
go build -trimpath -ldflags "-s -w" -o tools\KokSpy-CLI.exe ./cmd/kokspy-cli || exit /b 1

echo.
echo Built KokSpy.exe and tools\KokSpy-CLI.exe successfully.
