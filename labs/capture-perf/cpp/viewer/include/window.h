#pragma once

#include <windows.h>
#include <string>
#include <functional>

class Window {
public:
    using ResizeCallback = std::function<void(int width, int height)>;

    Window() : hwnd_(nullptr), width_(0), height_(0) {}
    ~Window();

    bool Initialize(const wchar_t* title, int width, int height);
    void MessageLoop();
    void Close();

    HWND GetHandle() const { return hwnd_; }
    int GetWidth() const { return width_; }
    int GetHeight() const { return height_; }

    void SetResizeCallback(ResizeCallback callback) { resize_callback_ = callback; }

private:
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);

    HWND hwnd_;
    int width_;
    int height_;
    ResizeCallback resize_callback_;
};
