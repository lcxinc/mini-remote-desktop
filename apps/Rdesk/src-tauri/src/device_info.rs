//! 设备信息获取模块
//!
//! 获取主板序列号、机器名、操作系统版本等硬件信息用于设备注册

use serde::{Deserialize, Serialize};
use std::fmt;

/// 设备硬件信息（用于注册设备）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInfo {
    /// 主板序列号（作为设备唯一标识）
    pub motherboard_serial: String,
    /// 机器名/主机名
    pub hostname: String,
    /// 操作系统类型
    pub os_type: String,
    /// 操作系统版本
    pub os_version: String,
    /// CPU 信息
    pub cpu_info: CpuInfo,
    /// 内存总量 (MB)
    pub total_memory_mb: u64,
    /// GPU 信息（如果有）
    pub gpu_info: Vec<GpuInfo>,
}

/// CPU 信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInfo {
    pub name: String,
    pub vendor_id: String,
    pub cores: u32,
    pub max_frequency_mhz: Option<u32>,
}

/// GPU 信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInfo {
    pub name: String,
    pub vendor: String,
    pub memory_mb: Option<u64>,
}

impl fmt::Display for HardwareInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}) - {} {}",
            self.hostname, self.motherboard_serial, self.os_type, self.os_version
        )
    }
}

/// 获取主板序列号（Windows）
fn get_motherboard_serial() -> String {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        // 使用 WMIC 获取主板序列号
        let output = Command::new("wmic")
            .args(["baseboard", "get", "serialnumber"])
            .output();

        if let Ok(out) = output {
            if let Ok(text) = String::from_utf8(out.stdout) {
                for line in text.lines() {
                    let trimmed = line.trim();
                    // 过滤掉表头和空行
                    if !trimmed.is_empty()
                        && !trimmed.eq_ignore_ascii_case("SerialNumber")
                        && trimmed.len() > 5
                    {
                        return trimmed.to_string();
                    }
                }
            }
        }

        // 回退方案：使用 MachineGuid
        use winreg::enums::*;
        use winreg::RegKey;

        if let Ok(key) =
            RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SOFTWARE\Microsoft\Cryptography")
        {
            if let Ok(guid) = key.get_value::<String, _>("MachineGuid") {
                // MachineGuid 格式: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
                // 取前8位作为短ID
                return guid.chars().take(8).collect();
            }
        }

        // 最终回退：生成随机ID
        format!("{:08x}", rand_seed())
    }

    #[cfg(not(target_os = "windows"))]
    {
        // 非Windows系统使用机器ID
        get_hostname()
    }
}

/// 简单的随机种子生成器（用于回退场景）
#[cfg(target_os = "windows")]
fn rand_seed() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u32)
        .unwrap_or(0x12345678)
}

/// 获取主机名
fn get_hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "Unknown".to_string())
}

/// 获取操作系统版本
fn get_os_version() -> String {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;

        if let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        {
            let product_name = key
                .get_value::<String, _>("ProductName")
                .unwrap_or_else(|_| "Windows".to_string());
            let display_version = key
                .get_value::<String, _>("DisplayVersion")
                .unwrap_or_else(|_| "".to_string());
            let build_number = key
                .get_value::<String, _>("CurrentBuild")
                .unwrap_or_else(|_| "".to_string());

            if display_version.is_empty() {
                format!("{} Build {}", product_name, build_number)
            } else {
                format!(
                    "{} {} Build {}",
                    product_name, display_version, build_number
                )
            }
        } else {
            "Windows".to_string()
        }
    }

    #[cfg(target_os = "linux")]
    {
        // 尝试读取 /etc/os-release
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            content
                .lines()
                .find(|line| line.starts_with("PRETTY_NAME="))
                .and_then(|line| line.split('=').nth(1))
                .map(|s| s.trim_matches('"').to_string())
                .unwrap_or_else(|| "Linux".to_string())
        } else {
            "Linux".to_string()
        }
    }

    #[cfg(target_os = "macos")]
    {
        "macOS".to_string()
    }
}

/// 获取 CPU 信息
fn get_cpu_info() -> CpuInfo {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        let name = Command::new("wmic")
            .args(["cpu", "get", "name"])
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|s| {
                s.lines()
                    .nth(1)
                    .map(|l| l.trim().to_string())
                    .unwrap_or_else(|| "Unknown CPU".to_string())
            })
            .unwrap_or_else(|| "Unknown CPU".to_string());

        let vendor_id = Command::new("wmic")
            .args(["cpu", "get", "Manufacturer"])
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|s| {
                s.lines()
                    .nth(1)
                    .map(|l| l.trim().to_string())
                    .unwrap_or_else(|| "Unknown".to_string())
            })
            .unwrap_or_else(|| "Unknown".to_string());

        let cores = num_cpus::get() as u32;

        CpuInfo {
            name,
            vendor_id,
            cores,
            max_frequency_mhz: None,
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        CpuInfo {
            name: "Unknown CPU".to_string(),
            vendor_id: "Unknown".to_string(),
            cores: num_cpus::get() as u32,
            max_frequency_mhz: None,
        }
    }
}

/// 获取总内存量（MB）
fn get_total_memory_mb() -> u64 {
    #[cfg(target_os = "windows")]
    {
        use std::mem;
        use winapi::um::sysinfoapi::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

        unsafe {
            let mut stat: MEMORYSTATUSEX = mem::zeroed();
            stat.dwLength = mem::size_of::<MEMORYSTATUSEX>() as u32;
            GlobalMemoryStatusEx(&mut stat);
            stat.ullTotalPhys / (1024 * 1024)
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        8192 // 默认 8GB
    }
}

/// 获取 GPU 信息
fn get_gpu_info() -> Vec<GpuInfo> {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        let output = Command::new("wmic")
            .args(["path", "win32_VideoController", "get", "name,AdapterRAM"])
            .output();

        if let Ok(out) = output {
            if let Ok(text) = String::from_utf8(out.stdout) {
                return parse_gpu_info(&text);
            }
        }

        Vec::new()
    }

    #[cfg(not(target_os = "windows"))]
    {
        Vec::new()
    }
}

#[cfg(target_os = "windows")]
fn parse_gpu_info(text: &str) -> Vec<GpuInfo> {
    let mut gpus = Vec::new();
    let lines: Vec<&str> = text.lines().collect();

    // WMIC 输出格式:
    // AdapterRAM    Name
    // 2147483648    NVIDIA GeForce RTX 3060

    for line in lines.iter().skip(1) {
        let line = line.trim();
        if line.is_empty() || line.starts_with("No") {
            continue;
        }

        // 解析格式: "bytes_count    GPU Name"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        // 第一个数字是显存（字节），后面是GPU名称
        let memory_bytes = parts
            .first()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&n| n > 1000)
            .map(|b| b / (1024 * 1024)); // 转换为 MB

        // GPU 名称是剩余部分拼接
        let name: String = if memory_bytes.is_some() {
            parts.iter().skip(1).cloned().collect::<Vec<_>>().join(" ")
        } else {
            parts.join(" ")
        };

        if name.is_empty() || name == "AdapterRAM" {
            continue;
        }

        // 简单的厂商检测
        let vendor = if name.contains("NVIDIA")
            || name.contains("GeForce")
            || name.contains("Quadro")
            || name.contains("RTX")
        {
            "NVIDIA".to_string()
        } else if name.contains("AMD") || name.contains("Radeon") || name.contains("AMD Radeon") {
            "AMD".to_string()
        } else if name.contains("Intel") {
            "Intel".to_string()
        } else {
            "Unknown".to_string()
        };

        gpus.push(GpuInfo {
            name,
            vendor,
            memory_mb: memory_bytes,
        });
    }

    gpus
}

/// 获取完整的硬件信息
pub fn get_hardware_info() -> HardwareInfo {
    HardwareInfo {
        motherboard_serial: get_motherboard_serial(),
        hostname: get_hostname(),
        os_type: std::env::consts::OS.to_string(),
        os_version: get_os_version(),
        cpu_info: get_cpu_info(),
        total_memory_mb: get_total_memory_mb(),
        gpu_info: get_gpu_info(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_hardware_info() {
        let info = get_hardware_info();
        assert!(
            !info.motherboard_serial.is_empty(),
            "Motherboard serial should not be empty"
        );
        assert!(!info.hostname.is_empty(), "Hostname should not be empty");
        assert!(!info.os_type.is_empty(), "OS type should not be empty");
        println!("Hardware Info: {}", info);
    }

    #[test]
    fn test_motherboard_serial_stability() {
        let serial1 = get_motherboard_serial();
        let serial2 = get_motherboard_serial();
        assert_eq!(serial1, serial2, "Motherboard serial should be stable");
    }
}
