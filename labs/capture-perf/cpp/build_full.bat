@echo off
setlocal
call "D:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cd /d D:\Project\TestProject\CapTest\cpp
if not exist build mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
if errorlevel 1 exit /b 1
cmake --build . --config Release
if errorlevel 1 exit /b 1
endlocal
