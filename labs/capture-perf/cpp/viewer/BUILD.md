# Viewer 构建说明

## 方法 1: 使用 Visual Studio

1. 在 Visual Studio 2022 中打开 `cpp\build\CapTest.sln`
2. 右键点击解决方案 → 添加 → 现有项目
3. 选择 `cpp\viewer\viewer.vcxproj`（需要先用 CMake 生成）
4. 右键点击 viewer 项目 → 生成

## 方法 2: 命令行构建

```cmd
cd cpp
build_viewer_simple.bat
```

## 方法 3: 使用 CMake

```cmd
cd cpp\build
cmake .. -G "Visual Studio 17 2022" -A x64
msbuild viewer.vcxproj /p:Configuration=Release
```

## 运行

构建完成后，viewer 将显示：
- 实时桌面捕获内容
- FPS 信息
- 分辨率信息
- 捕获时间

## 已实现功能

- ✅ Win32 窗口管理
- ✅ D3D11 渲染器
- ✅ Desktop Duplication 集成
- ✅ 实时捕获和显示
- ⏳ FPS/分辨率叠加层（待完善）
- ⏳ D3D12 渲染器（待实现）
