cmake_minimum_required(VERSION 3.20)
project(CapTest VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_library(metrics_collector STATIC
    src/common/metrics_collector.cpp
)
target_include_directories(metrics_collector PUBLIC include)

add_executable(desktop_duplication
    src/desktop_duplication/main.cpp
)
target_link_libraries(desktop_duplication
    metrics_collector
    d3d11.lib
    dxgi.lib
    dxguid.lib
)

add_executable(graphics_capture
    src/graphics_capture/main.cpp
)
target_link_libraries(graphics_capture
    metrics_collector
    d3d11.lib
    dxgi.lib
    WindowsApp.lib
)

add_executable(shared_memory_dd
    src/shared_memory_dd/main.cpp
)
target_link_libraries(shared_memory_dd
    metrics_collector
    d3d11.lib
    dxgi.lib
    dxguid.lib
)

# Add viewer subdirectory
add_subdirectory(viewer)
