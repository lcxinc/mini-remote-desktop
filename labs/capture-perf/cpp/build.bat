@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cd /d D:\Project\TestProject\CapTest\cpp\build
msbuild graphics_capture.vcxproj /p:Configuration=Release /v:m
