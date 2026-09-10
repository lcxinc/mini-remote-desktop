@echo off
setlocal enabledelayedexpansion

echo Setting up Visual Studio environment...
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

if not exist build mkdir build
cd build

echo Running CMake...
cmake .. -G "Visual Studio 17 2022" -A x64

if %ERRORLEVEL% NEQ 0 (
    echo CMake failed!
    exit /b 1
)

echo Building viewer...
cmake --build . --config Release --target viewer

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Build successful!
    echo.
    echo Running viewer...
    echo.
    cd Release
    viewer.exe
) else (
    echo Build failed!
)

endlocal
