@echo off
echo Setting up Visual Studio environment...
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

echo.
echo Building Graphics Capture...
cd /d D:\Project\TestProject\CapTest\cpp\build
msbuild graphics_capture.vcxproj /p:Configuration=Release /p:Platform=x64 /v:m /t:Rebuild

echo.
echo Build complete!
echo.
echo Run the test with: build\bin\Release\graphics_capture.exe
pause
