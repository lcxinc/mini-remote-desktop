# Viewer 编译说明

由于 D3D12 渲染器仍在开发中，当前建议只编译 D3D11 版本。

## 手动编译步骤

### 方法 1: 使用 Visual Studio

1. 打开 Visual Studio 2022
2. 打开 "开发人员 PowerShell" 或 "开发人员命令提示符"
3. 进入项目目录：
   ```
   cd D:\Project\TestProject\CapTest\cpp
   ```
4. 运行以下命令：
   ```
   mkdir build
   cd build
   cmake .. -G "Visual Studio 17 2022" -A x64
   cmake --build . --config Release --target viewer
   ```
5. 运行：
   ```
   build\Release\viewer.exe
   ```

### 方法 2: 使用批处理文件

直接运行：
```
build_viewer_d3d11.bat
```

## 当前功能

- ✅ Desktop Duplication 实时捕获
- ✅ D3D11 渲染
- ✅ 叠加层显示（FPS、分辨率、捕获时间）
- ⏳ D3D12 渲染器（开发中）

## 预期输出

窗口左上角显示：
```
Desktop Duplication (D3D11)
FPS: 144.2
Resolution: 2560x1440
Capture: 6.85 ms
```

## 如果编译失败

1. 确保安装了 Visual Studio 2022
2. 确保 C++ 桌面开发组件已安装
3. 确保 Windows SDK 已安装
4. 检查 `d3d11.lib`, `d2d1.lib`, `dwrite.lib` 是否可用
