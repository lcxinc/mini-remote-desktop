use anyhow::{ensure, Result};
use windows::core::Interface;
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL_11_0};
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, D3D11_CPU_ACCESS_READ,
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_SDK_VERSION,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};
use windows::Win32::Graphics::Dxgi::{
    IDXGIDevice, IDXGIOutput, IDXGIOutput1, IDXGIOutputDuplication, DXGI_ERROR_WAIT_TIMEOUT,
    DXGI_OUTDUPL_FRAME_INFO,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    Bgra8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedFrame {
    pub width: u32,
    pub height: u32,
    pub format: PixelFormat,
    pub data: Vec<u8>,
}

impl CapturedFrame {
    pub fn from_bgra(width: u32, height: u32, data: Vec<u8>) -> Result<Self> {
        let expected_len = (width as usize)
            .checked_mul(height as usize)
            .and_then(|pixels| pixels.checked_mul(4))
            .expect("frame dimensions should fit in memory");
        ensure!(
            data.len() == expected_len,
            "BGRA frame length mismatch: expected {expected_len} bytes, got {}",
            data.len()
        );

        Ok(Self {
            width,
            height,
            format: PixelFormat::Bgra8,
            data,
        })
    }
}

/// A persistent capture session that maintains D3D11 and desktop duplication state.
pub struct CaptureSession {
    _device: ID3D11Device,
    context: ID3D11DeviceContext,
    duplication: IDXGIOutputDuplication,
    staging_texture: ID3D11Texture2D,
    width: u32,
    height: u32,
}

impl CaptureSession {
    /// Validate that the given dimensions are non-zero.
    pub fn validate_dimensions(width: u32, height: u32) -> Result<()> {
        ensure!(width > 0, "width must be greater than 0");
        ensure!(height > 0, "height must be greater than 0");
        Ok(())
    }

    /// Create a new capture session for the primary desktop output.
    pub fn new() -> Result<Self> {
        let (device, context) = create_d3d11_device()?;
        let dxgi_device: IDXGIDevice = device.cast()?;
        let adapter = unsafe { dxgi_device.GetAdapter()? };
        let output: IDXGIOutput = unsafe { adapter.EnumOutputs(0)? };
        let output1: IDXGIOutput1 = output.cast()?;
        let duplication = unsafe { output1.DuplicateOutput(&device)? };

        let output_desc = unsafe { output.GetDesc()? };
        let width = (output_desc.DesktopCoordinates.right - output_desc.DesktopCoordinates.left) as u32;
        let height = (output_desc.DesktopCoordinates.bottom - output_desc.DesktopCoordinates.top) as u32;
        let staging_texture = create_staging_texture(&device, width, height)?;

        Ok(Self {
            _device: device,
            context,
            duplication,
            staging_texture,
            width,
            height,
        })
    }

    /// Get the capture width.
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Get the capture height.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Capture the next available frame from the desktop duplication API.
    ///
    /// This will wait up to 30 retries (about 3 seconds total) for a frame to become available.
    pub fn capture_next_frame(&mut self) -> Result<CapturedFrame> {
        for _ in 0..30 {
            let mut frame_resource = None;
            let mut frame_info = DXGI_OUTDUPL_FRAME_INFO::default();
            let acquire_result =
                unsafe { self.duplication.AcquireNextFrame(100, &mut frame_info, &mut frame_resource) };

            match acquire_result {
                Ok(()) => {
                    let result = (|| -> Result<CapturedFrame> {
                        let resource = frame_resource.ok_or_else(|| {
                            anyhow::anyhow!("desktop duplication returned no frame resource")
                        })?;
                        let desktop_texture: ID3D11Texture2D = resource.cast()?;
                        unsafe {
                            self.context.CopyResource(&self.staging_texture, &desktop_texture);
                        }

                        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
                        unsafe {
                            self.context
                                .Map(&self.staging_texture, 0, D3D11_MAP_READ, 0, Some(&mut mapped))?;
                        }

                        let mut bgra = vec![0u8; self.width as usize * self.height as usize * 4];
                        let src = unsafe {
                            std::slice::from_raw_parts(
                                mapped.pData as *const u8,
                                mapped.RowPitch as usize * self.height as usize,
                            )
                        };

                        for row in 0..self.height as usize {
                            let src_start = row * mapped.RowPitch as usize;
                            let src_end = src_start + self.width as usize * 4;
                            let dst_start = row * self.width as usize * 4;
                            let dst_end = dst_start + self.width as usize * 4;
                            bgra[dst_start..dst_end].copy_from_slice(&src[src_start..src_end]);
                        }

                        unsafe {
                            self.context.Unmap(&self.staging_texture, 0);
                        }

                        CapturedFrame::from_bgra(self.width, self.height, bgra)
                    })();

                    unsafe {
                        self.duplication.ReleaseFrame()?;
                    }
                    return result;
                }
                Err(err) if err.code() == DXGI_ERROR_WAIT_TIMEOUT => continue,
                Err(err) => return Err(err.into()),
            }
        }

        Err(anyhow::anyhow!("timed out waiting for desktop frame"))
    }
}

pub fn capture_one_frame() -> Result<CapturedFrame> {
    let (device, context) = create_d3d11_device()?;
    let dxgi_device: IDXGIDevice = device.cast()?;
    let adapter = unsafe { dxgi_device.GetAdapter()? };
    let output: IDXGIOutput = unsafe { adapter.EnumOutputs(0)? };
    let output1: IDXGIOutput1 = output.cast()?;
    let duplication = unsafe { output1.DuplicateOutput(&device)? };

    let output_desc = unsafe { output.GetDesc()? };
    let width = (output_desc.DesktopCoordinates.right - output_desc.DesktopCoordinates.left) as u32;
    let height = (output_desc.DesktopCoordinates.bottom - output_desc.DesktopCoordinates.top) as u32;
    let staging_texture = create_staging_texture(&device, width, height)?;

    for _ in 0..30 {
        let mut frame_resource = None;
        let mut frame_info = DXGI_OUTDUPL_FRAME_INFO::default();
        let acquire_result =
            unsafe { duplication.AcquireNextFrame(100, &mut frame_info, &mut frame_resource) };

        match acquire_result {
            Ok(()) => {
                let result = (|| -> Result<CapturedFrame> {
                    let resource = frame_resource
                        .ok_or_else(|| anyhow::anyhow!("desktop duplication returned no frame resource"))?;
                    let desktop_texture: ID3D11Texture2D = resource.cast()?;
                    unsafe {
                        context.CopyResource(&staging_texture, &desktop_texture);
                    }

                    let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
                    unsafe {
                        context.Map(&staging_texture, 0, D3D11_MAP_READ, 0, Some(&mut mapped))?;
                    }

                    let mut bgra = vec![0u8; width as usize * height as usize * 4];
                    let src = unsafe {
                        std::slice::from_raw_parts(
                            mapped.pData as *const u8,
                            mapped.RowPitch as usize * height as usize,
                        )
                    };

                    for row in 0..height as usize {
                        let src_start = row * mapped.RowPitch as usize;
                        let src_end = src_start + width as usize * 4;
                        let dst_start = row * width as usize * 4;
                        let dst_end = dst_start + width as usize * 4;
                        bgra[dst_start..dst_end].copy_from_slice(&src[src_start..src_end]);
                    }

                    unsafe {
                        context.Unmap(&staging_texture, 0);
                    }

                    CapturedFrame::from_bgra(width, height, bgra)
                })();

                unsafe {
                    duplication.ReleaseFrame()?;
                }
                return result;
            }
            Err(err) if err.code() == DXGI_ERROR_WAIT_TIMEOUT => continue,
            Err(err) => return Err(err.into()),
        }
    }

    Err(anyhow::anyhow!("timed out waiting for desktop frame"))
}

fn create_d3d11_device() -> Result<(ID3D11Device, ID3D11DeviceContext)> {
    let mut device: Option<ID3D11Device> = None;
    let mut context: Option<ID3D11DeviceContext> = None;
    unsafe {
        D3D11CreateDevice(
            None,
            D3D_DRIVER_TYPE_HARDWARE,
            windows::Win32::Foundation::HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            Some(&[D3D_FEATURE_LEVEL_11_0]),
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )?;
    }

    Ok((
        device.ok_or_else(|| anyhow::anyhow!("failed to create D3D11 device"))?,
        context.ok_or_else(|| anyhow::anyhow!("failed to create D3D11 device context"))?,
    ))
}

fn create_staging_texture(device: &ID3D11Device, width: u32, height: u32) -> Result<ID3D11Texture2D> {
    let desc = D3D11_TEXTURE2D_DESC {
        Width: width,
        Height: height,
        MipLevels: 1,
        ArraySize: 1,
        Format: DXGI_FORMAT_B8G8R8A8_UNORM,
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        Usage: D3D11_USAGE_STAGING,
        BindFlags: 0,
        CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
        MiscFlags: 0,
    };

    let mut texture: Option<ID3D11Texture2D> = None;
    unsafe {
        device.CreateTexture2D(&desc, None, Some(&mut texture))?;
    }
    texture.ok_or_else(|| anyhow::anyhow!("failed to create staging texture"))
}
