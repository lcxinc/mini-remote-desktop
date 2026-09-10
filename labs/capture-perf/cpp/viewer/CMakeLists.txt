cmake_minimum_required(VERSION 3.20)
project(Viewer)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(COMMON_SOURCES
    src/window.cpp
    src/overlay_renderer.cpp
    src/capture_render_metrics.cpp
    src/viewer_options.cpp
    src/capture_sources.cpp
)

set(D3D11_SOURCES
    ${COMMON_SOURCES}
    src/d3d11_renderer.cpp
    src/desktop_duplication_capture.cpp
    src/viewer_main.cpp
)

set(D3D12_SOURCES
    ${COMMON_SOURCES}
    src/d3d12_renderer.cpp
    src/desktop_duplication_capture.cpp
    src/viewer_main.cpp
)

add_executable(viewer WIN32 ${D3D11_SOURCES})
add_executable(viewer_d3d12 WIN32 ${D3D12_SOURCES})

# Include directories
target_include_directories(viewer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(viewer_d3d12 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link libraries for D3D11 viewer
target_link_libraries(viewer PRIVATE
    d3d11
    dxgi
    d3dcompiler
    d2d1
    dwrite
    psapi
    shell32
    windowsapp
)

target_compile_definitions(viewer_d3d12 PRIVATE USE_D3D12=1)

target_link_libraries(viewer_d3d12 PRIVATE
    d3d12
    d3d11
    dxgi
    d3dcompiler
    d2d1
    dwrite
    psapi
    shell32
    windowsapp
)

# Set subsystem to Windows
if(MSVC)
    set_target_properties(viewer PROPERTIES
        LINK_FLAGS "/SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup"
    )
    set_target_properties(viewer_d3d12 PROPERTIES
        LINK_FLAGS "/SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup"
    )
endif()

add_executable(capture_render_metrics_tests
    tests/capture_render_metrics_tests.cpp
    src/capture_render_metrics.cpp
)

target_include_directories(capture_render_metrics_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(viewer_options_tests
    tests/viewer_options_tests.cpp
    src/viewer_options.cpp
)

target_include_directories(viewer_options_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(viewer_options_tests PRIVATE shell32)

add_executable(capture_source_tests
    tests/capture_source_tests.cpp
    src/capture_sources.cpp
    src/desktop_duplication_capture.cpp
    src/viewer_options.cpp
)

target_include_directories(capture_source_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(capture_source_tests PRIVATE
    d3d11
    dxgi
    windowsapp
    shell32
)

# Register existing non-capturing tests for migration validation.
enable_testing()
add_test(NAME capture_render_metrics COMMAND capture_render_metrics_tests)
add_test(NAME viewer_options COMMAND viewer_options_tests)
add_test(NAME capture_source_factory COMMAND capture_source_tests)
