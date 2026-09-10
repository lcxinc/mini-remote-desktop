@echo off
setlocal
pushd "%~dp0"

echo Setting up Visual Studio environment...
set "VCVARS="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set "VCVARS=%%i\VC\Auxiliary\Build\vcvars64.bat"
    )
)

if not defined VCVARS if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

if not exist "%VCVARS%" (
    echo Visual Studio C++ build tools were not found.
    exit /b 1
)

call "%VCVARS%"

set SRC_DIR=viewer\src
set INC_DIR=viewer\include
set OUT_DIR=viewer_build

if not exist %OUT_DIR% mkdir %OUT_DIR%

echo Compiling viewer components...

echo [1/10] Compiling window.cpp...
cl.exe /c /EHsc /std:c++20 /I%INC_DIR% ^
    %SRC_DIR%\window.cpp ^
    /Fo%OUT_DIR%\window.obj

if %ERRORLEVEL% NEQ 0 goto :error

echo [2/10] Compiling d3d11_renderer.cpp...
cl.exe /c /EHsc /std:c++20 /I%INC_DIR% ^
    %SRC_DIR%\d3d11_renderer.cpp ^
    /Fo%OUT_DIR%\d3d11_renderer.obj

if %ERRORLEVEL% NEQ 0 goto :error

echo [3/10] Compiling overlay_renderer.cpp...
cl.exe /c /EHsc /std:c++20 /I%INC_DIR% ^
    %SRC_DIR%\overlay_renderer.cpp ^
    /Fo%OUT_DIR%\overlay_renderer.obj

if %ERRORLEVEL% NEQ 0 goto :error

echo [4/10] Compiling desktop_duplication_capture.cpp...
cl.exe /c /EHsc /std:c++20 /I%INC_DIR% ^
    %SRC_DIR%\desktop_duplication_capture.cpp ^
    /Fo%OUT_DIR%\desktop_duplication_capture.obj

if %ERRORLEVEL% NEQ 0 goto :error

echo [5/10] Compiling capture_render_metrics.cpp...
cl.exe /c /EHsc /std:c++20 /I%INC_DIR% ^
    %SRC_DIR%\capture_render_metrics.cpp ^
    /Fo%OUT_DIR%\capture_render_metrics.obj

if %ERRORLEVEL% NEQ 0 goto :error

echo [6/10] Compiling viewer_options.cpp...
cl.exe /c /EHsc /std:c++20 /I%INC_DIR% ^
    %SRC_DIR%\viewer_options.cpp ^
    /Fo%OUT_DIR%\viewer_options.obj

if %ERRORLEVEL% NEQ 0 goto :error

echo [7/10] Compiling capture_sources.cpp...
cl.exe /c /EHsc /std:c++20 /I%INC_DIR% ^
    %SRC_DIR%\capture_sources.cpp ^
    /Fo%OUT_DIR%\capture_sources.obj

if %ERRORLEVEL% NEQ 0 goto :error

echo [8/10] Compiling viewer_main.cpp...
cl.exe /c /EHsc /std:c++20 /I%INC_DIR% ^
    %SRC_DIR%\viewer_main.cpp ^
    /Fo%OUT_DIR%\viewer_main.obj

if %ERRORLEVEL% NEQ 0 goto :error

echo.
echo [9/10] Linking...

link.exe /SUBSYSTEM:WINDOWS ^
    /ENTRY:wWinMainCRTStartup ^
    /DYNAMICBASE:NO ^
    %OUT_DIR%\window.obj ^
    %OUT_DIR%\d3d11_renderer.obj ^
    %OUT_DIR%\overlay_renderer.obj ^
    %OUT_DIR%\desktop_duplication_capture.obj ^
    %OUT_DIR%\capture_render_metrics.obj ^
    %OUT_DIR%\viewer_options.obj ^
    %OUT_DIR%\capture_sources.obj ^
    %OUT_DIR%\viewer_main.obj ^
    /OUT:%OUT_DIR%\viewer.exe ^
    d3d11.lib dxgi.lib d3dcompiler.lib d2d1.lib dwrite.lib user32.lib gdi32.lib ole32.lib psapi.lib shell32.lib windowsapp.lib

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [10/10] Build successful!
    if /I "%CAPTEST_SKIP_RUN%"=="1" (
        echo Skipping viewer run because CAPTEST_SKIP_RUN=1.
    ) else (
        echo.
        echo Running viewer...
        echo.
        %OUT_DIR%\viewer.exe %*
    )
) else (
    goto :error
)

goto :end

:error
    echo.
    echo Build failed!
    popd
    if /I not "%CAPTEST_NO_PAUSE%"=="1" pause
    exit /b 1

:end
popd
endlocal
if /I not "%CAPTEST_NO_PAUSE%"=="1" pause
