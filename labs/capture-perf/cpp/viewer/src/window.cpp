#include "window.h"

Window::~Window() {
    Close();
}

bool Window::Initialize(const wchar_t* title, int width, int height) {
    width_ = width;
    height_ = height;

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)COLOR_WINDOW;
    wc.lpszClassName = L"CapTestViewer";

    if (!RegisterClassExW(&wc)) {
        return false;
    }

    DWORD style = WS_OVERLAPPEDWINDOW;
    RECT rect = {0, 0, width, height};
    AdjustWindowRect(&rect, style, FALSE);

    hwnd_ = CreateWindowExW(
        0,
        L"CapTestViewer",
        title,
        style,
        CW_USEDEFAULT, CW_USEDEFAULT,
        rect.right - rect.left,
        rect.bottom - rect.top,
        nullptr,
        nullptr,
        GetModuleHandle(nullptr),
        this
    );

    if (!hwnd_) {
        return false;
    }

    ShowWindow(hwnd_, SW_SHOW);
    UpdateWindow(hwnd_);

    return true;
}

void Window::MessageLoop() {
    MSG msg = {};
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

void Window::Close() {
    if (hwnd_) {
        DestroyWindow(hwnd_);
        hwnd_ = nullptr;
    }
}

LRESULT CALLBACK Window::WindowProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    Window* window = nullptr;

    if (msg == WM_NCCREATE) {
        CREATESTRUCT* cs = (CREATESTRUCT*)lparam;
        window = (Window*)cs->lpCreateParams;
        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)window);
    } else {
        window = (Window*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    }

    switch (msg) {
        case WM_SIZE:
            if (window && window->resize_callback_) {
                window->resize_callback_(LOWORD(lparam), HIWORD(lparam));
            }
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, msg, wparam, lparam);
    }

    return 0;
}
