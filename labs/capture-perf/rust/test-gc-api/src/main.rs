use windows::{
    core::*,
    Graphics::Capture::*,
    Win32::Foundation::*,
    Win32::System::Com::*,
    Win32::System::WinRT::*,
    Win32::UI::WindowsAndMessaging::*,
};

// 定义 IGraphicsCaptureItemInterop 接口
#[windows_core::imp::interface(IUnknown)]
unsafe trait IGraphicsCaptureItemInterop: IUnknown {
    unsafe fn CreateForWindow(
        &self,
        window: HWND,
        iid: *const GUID,
    ) -> Result<*mut c_void>;
}

// 实现 IGraphicsCaptureItemInterop 的 VTable
#[repr(C)]
struct IGraphicsCaptureItemInterop_Vtbl {
    base: IUnknown_Vtbl,
    CreateForWindow: unsafe extern "system" fn(
        this: *mut c_void,
        window: HWND,
        iid: *const GUID,
        result: *mut *mut c_void,
    ) -> HRESULT,
}

fn main() -> Result<()> {
    println!("Testing GraphicsCaptureItem with custom interface...");
    
    unsafe {
        // 初始化 COM
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        
        // 获取桌面窗口
        let hwnd = GetDesktopWindow();
        println!("Desktop window: {:?}", hwnd);
        
        // 方法：使用 RoGetActivationFactory 获取 IInspectable，然后转换
        let hstring = windows::core::HSTRING::from("Windows.Graphics.Capture.GraphicsCaptureItem");
        
        match RoGetActivationFactory::<IInspectable>(&hstring) {
            Ok(factory) => {
                println!("Got IInspectable factory");
                
                // 尝试手动查询 IGraphicsCaptureItemInterop 接口
                let interop_iid = GUID::from_u128(0x3628e81b_3cac_4c60_b7f4_23ce0e0c3356);
                
                match factory.cast::<IGraphicsCaptureItemInterop>() {
                    Ok(interop) => {
                        println!("Got IGraphicsCaptureItemInterop!");
                        
                        match interop.CreateForWindow(hwnd, &GraphicsCaptureItem::IID) {
                            Ok(item_ptr) => {
                                let item: GraphicsCaptureItem = FromPointer::from_ptr(item_ptr)?;
                                println!("Created capture item!");
                                let size = item.Size()?;
                                println!("Item size: {}x{}", size.Width, size.Height);
                            }
                            Err(e) => {
                                println!("CreateForWindow failed: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        println!("Failed to cast to IGraphicsCaptureItemInterop: {:?}", e);
                    }
                }
            }
            Err(e) => {
                println!("Failed to get factory: {:?}", e);
            }
        }
    }
    
    Ok(())
}
