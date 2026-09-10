@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cd /d D:\Project\TestProject\CapTest\cpp\build
msbuild viewer.vcxproj /p:Configuration=Release /v:m
if %ERRORLEVEL% EQU 0 (
    echo Build successful!
    echo Running viewer...
    cd /d D:\Project\TestProject\CapTest\cpp\build\bin\Release
    viewer.exe
) else (
    echo Build failed!
)
