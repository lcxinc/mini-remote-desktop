@echo off
setlocal

echo Building Rust capture tools...
echo.

echo Building desktop-duplication...
cd desktop-duplication
cargo build --release
if errorlevel 1 (
    echo Failed to build desktop-duplication
    cd ..
    exit /b 1
)
cd ..

echo Building graphics-capture...
cd graphics-capture
cargo build --release
if errorlevel 1 (
    echo Failed to build graphics-capture
    cd ..
    exit /b 1
)
cd ..

echo.
echo Build successful!
echo.
echo Run tests:
echo   desktop-duplication/target/release/desktop-duplication.exe
echo   graphics-capture/target/release/graphics-capture.exe

endlocal
