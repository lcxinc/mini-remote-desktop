@echo off
setlocal

REM Setup Visual Studio environment
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

set SRC_DIR=viewer\src
set INC_DIR=viewer\include
set OUT_DIR=viewer_build

if not exist %OUT_DIR% mkdir %OUT_DIR%

echo Compiling viewer...

cl.exe /c /EHsc /std:c++20 /I%INC_DIR% ^
    %SRC_DIR%\window.cpp ^
    %SRC_DIR%\d3d11_renderer.cpp ^
    /Fo%OUT_DIR%\

if %ERRORLEVEL% NEQ 0 (
    echo Compilation failed!
    exit /b 1
)

echo Linking...

link.exe /SUBSYSTEM:WINDOWS ^
    /ENTRY:wWinMainCRTStartup ^
    %OUT_DIR%\window.obj ^
    %OUT_DIR%\d3d11_renderer.obj ^
    %SRC_DIR%\viewer_main.cpp ^
    /OUT:%OUT_DIR%\viewer.exe ^
    d3d11.lib dxgi.lib d3dcompiler.lib user32.lib gdi32.lib

if %ERRORLEVEL% NEQ 0 (
    echo Linking failed!
    exit /b 1
)

echo Build successful!
echo Running viewer...
%OUT_DIR%\viewer.exe

endlocal
