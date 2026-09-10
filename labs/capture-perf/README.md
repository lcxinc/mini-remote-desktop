# Windows屏幕捕获性能测试

使用C++和Rust对比Windows不同屏幕捕获API的性能。

## 测试的API

- **Desktop Duplication API** - Windows 8+ 传统方案
- **Graphics Capture API** - Windows 10 1803+ 现代方案
- **Desktop Duplication + 共享内存** - 优化方案

## 性能指标

- 帧捕获时间（延迟）
- 帧率（FPS）
- CPU使用率
- 内存使用量
- P95/P99百分位数

## 构建

### C++

```bash
cd cpp
build.bat
```

### Rust

```bash
cd rust
build.bat
```

## 运行测试

### C++

```bash
cpp\build\bin\Release\desktop_duplication.exe
```

### Rust

```bash
rust\desktop-duplication\target\release\desktop-duplication.exe
```

## 对比结果

```bash
python scripts/compare_results.py
```

## 输出格式

每个测试生成两个文件：

- `[timestamp]_[lang]_[api].csv` - 原始帧数据
- `[timestamp]_[lang]_[api].json` - 统计摘要

## 项目结构

```
CapTest/
├── cpp/                    # C++ 实现
│   ├── include/            # 头文件
│   ├── src/                # 源码
│   └── build.bat           # 构建脚本
├── rust/                   # Rust 实现
│   ├── common/             # 公共库
│   ├── desktop-duplication/
│   └── graphics-capture/
├── results/                # 测试结果
└── scripts/                # 工具脚本
```

## 依赖

### C++

- Visual Studio 2022
- Windows SDK
- CMake 3.20+

### Rust

- Rust 1.70+
- Cargo

## 系统要求

- Windows 10 1803 或更高版本
- 支持DirectX 11的显卡

## 许可

MIT License
