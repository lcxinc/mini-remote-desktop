# C++ Graphics Capture 编译说明

## 方法 1: 使用 Visual Studio (推荐)

1. 打开 Visual Studio 2022
2. File -> Open -> Project/Solution
3. 选择 `D:\Project\TestProject\CapTest\cpp\build\CapTest.sln`
4. 右键点击 `graphics_capture` 项目 -> Build
5. 运行 `build\bin\Release\graphics_capture.exe`

## 方法 2: 使用 Developer Command Prompt

1. 开始菜单 -> Visual Studio 2022 -> Developer Command Prompt for VS 2022
2. 运行以下命令:
```
cd D:\Project\TestProject\CapTest\cpp\build
msbuild graphics_capture.vcxproj /p:Configuration=Release /p:Platform=x64
```

## 方法 3: 使用提供的批处理文件

直接运行: `D:\Project\TestProject\CapTest\cpp\rebuild.bat`

## 代码更改摘要

更新的 `main.cpp` 包含:
- 完整的 Graphics Capture API 实现
- 使用 Direct3D11CaptureFramePool 和 GraphicsCaptureSession
- 通过 IGraphicsCaptureItemInterop 从显示器创建捕获项
- 事件驱动的 FrameArrived 回调
- 线程安全的帧时间队列

## 预期结果

与 Rust 版本类似:
- 捕获时间: ~0.7-1.5ms
- FPS: 数千 (取决于刷新率)
