[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
  [ValidateSet("Native", "Docker", "Wsl2")][string]$Target,
  [string]$InstallRoot = "$env:ProgramFiles\MRD Relay",
  [string]$DataRoot = "$env:ProgramData\MRD\RelayAgent",
  [string]$RecoveryRoot = "$env:ProgramData\MRD\RelayAgentRecovery",
  [string]$DockerExecutable = "$env:ProgramFiles\Docker\Docker\resources\bin\docker.exe",
  [switch]$SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$AgentServiceName = "mrd-relay-agent"
$BrokerServiceName = "mrd-relay-coturn-control"
$NativeCoturnServiceName = "mrd-coturn-native"
$DockerContainerName = "mrd-coturn"
$DockerExpectedPath = "/usr/bin/turnserver"
$DockerExpectedArgs = @("--config", "/run/mrd/turnserver.conf")
$DockerExpectedNetworkMode = "bridge"
$DockerExpectedSecurityOpt = "no-new-privileges:true"
$WslDistributionName = "MRDRelay"
$ControlPipeName = "\\.\pipe\mrd-relay-coturn-control"
$RecoveryRootMarkerName = ".mrd-relay-recovery-root.json"
$DeploymentLockName = ".mrd-relay-deploy.lock"
$DeploymentLockContent = "MRD relay deployment lock v1`n"
$knownProgramData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
if ([string]::IsNullOrWhiteSpace($knownProgramData)) { throw "relay_uninstall_common_application_data_unavailable" }
$ProgramDataSystemRoot = [IO.Path]::GetFullPath($knownProgramData).TrimEnd([IO.Path]::DirectorySeparatorChar)
$DefaultManagedBoundary = [IO.Path]::Combine($ProgramDataSystemRoot, "MRD")
$FirewallRuleNames = @(
  "MRD Relay TURN UDP 3478", "MRD Relay TURN TCP 3478", "MRD Relay TURN TLS TCP",
  "MRD Relay Range UDP", "MRD Relay Range TCP"
)

function Fail {
  param([Parameter(Mandatory = $true)][string]$Reason)
  throw $Reason
}

function Assert-DockerMountSafeDataRoot {
  param([Parameter(Mandatory = $true)][string]$Path)
  if ($Path.IndexOf(',') -ge 0 -or $Path.IndexOf('=') -ge 0) {
    Fail "relay_uninstall_docker_data_root_mount_syntax_invalid"
  }
}

function Test-RunningWslDistribution {
  param([Parameter(Mandatory = $true)][object[]]$Lines, [Parameter(Mandatory = $true)][string]$Name)
  foreach ($line in $Lines) {
    if (([string]$line).Trim() -ieq $Name) { return $true }
  }
  return $false
}

function Assert-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail "relay_uninstall_requires_administrator"
  }
}

function Test-WslExecutionIdentity {
  param(
    [Parameter(Mandatory = $true)][ValidateSet("Native", "Docker", "Wsl2")][string]$SelectedTarget,
    [Parameter(Mandatory = $true)][string]$IdentitySid
  )
  return $SelectedTarget -cne "Wsl2" -or $IdentitySid -ceq "S-1-5-18"
}

function Assert-WslLocalSystemContext {
  param([Parameter(Mandatory = $true)][ValidateSet("Native", "Docker", "Wsl2")][string]$SelectedTarget)
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not (Test-WslExecutionIdentity $SelectedTarget $identity.User.Value)) {
    Fail "relay_uninstall_wsl_requires_local_system"
  }
}

function Get-SafeFullPath {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [switch]$MustExist,
    [switch]$Leaf
  )
  if (-not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith("\\")) {
    Fail "relay_uninstall_unsafe_path"
  }
  $full = [IO.Path]::GetFullPath($Path)
  if ($full.StartsWith("\\?\") -or $full.StartsWith("\\.\") -or
      ($full.Length -gt 2 -and $full.Substring(2).Contains(":"))) {
    Fail "relay_uninstall_device_or_ads_path_rejected"
  }
  if ([IO.File]::Exists($full)) {
    $leaf = Get-Item -LiteralPath $full -Force
    if (($leaf.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      Fail "relay_uninstall_reparse_target_rejected"
    }
  }
  $cursor = if ([IO.File]::Exists($full)) { [IO.Path]::GetDirectoryName($full) } else { $full }
  while (-not [string]::IsNullOrEmpty($cursor)) {
    if ([IO.Directory]::Exists($cursor)) {
      $item = Get-Item -LiteralPath $cursor -Force
      if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail "relay_uninstall_reparse_target_rejected"
      }
    }
    $parent = [IO.Directory]::GetParent($cursor)
    if ($null -eq $parent) { break }
    $cursor = $parent.FullName
  }
  if ($MustExist -and -not ([IO.File]::Exists($full) -or [IO.Directory]::Exists($full))) {
    Fail "relay_uninstall_path_missing"
  }
  if ($Leaf -and -not [IO.File]::Exists($full)) { Fail "relay_uninstall_leaf_missing" }
  return $full
}

function ConvertTo-NativeCommandLineArgument {
  param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
  if ($Value.IndexOf([char]0) -ge 0 -or $Value.IndexOf("`r") -ge 0 -or $Value.IndexOf("`n") -ge 0) {
    Fail "relay_uninstall_external_process_argument_invalid"
  }
  if ($Value.Length -gt 32767) { Fail "relay_uninstall_external_process_argument_invalid" }
  if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
  $builder = New-Object Text.StringBuilder
  [void]$builder.Append('"')
  $backslashes = 0
  for ($index = 0; $index -lt $Value.Length; $index++) {
    $character = $Value[$index]
    if ($character -eq [char]92) {
      $backslashes++
      continue
    }
    if ($character -eq [char]34) {
      if ($backslashes -gt 0) { [void]$builder.Append(('\' * ($backslashes * 2) -join '')) }
      [void]$builder.Append('\"')
      $backslashes = 0
      continue
    }
    if ($backslashes -gt 0) {
      [void]$builder.Append(('\' * $backslashes -join ''))
      $backslashes = 0
    }
    [void]$builder.Append($character)
  }
  if ($backslashes -gt 0) { [void]$builder.Append(('\' * ($backslashes * 2) -join '')) }
  [void]$builder.Append('"')
  return $builder.ToString()
}

function ConvertTo-NativeCommandLine {
  param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Arguments)
  if ($Arguments.Count -gt 128) { Fail "relay_uninstall_external_process_argument_invalid" }
  return (@($Arguments | ForEach-Object { ConvertTo-NativeCommandLineArgument $_ }) -join ' ')
}

function ConvertFrom-BoundedProcessBytes {
  param(
    [Parameter(Mandatory = $true)][byte[]]$Bytes,
    [Parameter(Mandatory = $true)][ValidateSet("Utf8", "Utf16Le")][string]$EncodingName,
    [Parameter(Mandatory = $true)][string]$FailurePrefix
  )
  $offset = 0
  $count = $Bytes.Length
  if ($EncodingName -ceq "Utf8") {
    if ($count -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
      $offset = 3; $count -= 3
    }
    $encoding = New-Object Text.UTF8Encoding($false, $true)
  } else {
    if (($count % 2) -ne 0) { Fail ($FailurePrefix + "_output_invalid") }
    if ($count -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) {
      $offset = 2; $count -= 2
    }
    $encoding = New-Object Text.UnicodeEncoding($false, $true, $true)
  }
  try { $text = $encoding.GetString($Bytes, $offset, $count) } catch {
    Fail ($FailurePrefix + "_output_invalid")
  }
  if ($text.IndexOf([char]0) -ge 0) { Fail ($FailurePrefix + "_output_invalid") }
  return $text
}

function Invoke-BoundedNativeProcess {
  param(
    [Parameter(Mandatory = $true)][string]$Executable,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Arguments,
    [Parameter(Mandatory = $true)][int]$TimeoutMilliseconds,
    [Parameter(Mandatory = $true)][int]$MaxStdoutBytes,
    [Parameter(Mandatory = $true)][int]$MaxStderrBytes,
    [Parameter(Mandatory = $true)][string]$FailurePrefix,
    [Parameter(Mandatory = $true)][ValidateSet("Utf8", "Utf16Le")][string]$OutputEncoding
  )
  if (-not [IO.Path]::IsPathRooted($Executable) -or -not [IO.File]::Exists($Executable) -or
      $TimeoutMilliseconds -lt 1 -or $TimeoutMilliseconds -gt 120000 -or
      $MaxStdoutBytes -lt 1 -or $MaxStdoutBytes -gt 1048576 -or
      $MaxStderrBytes -lt 1 -or $MaxStderrBytes -gt 1048576) {
    Fail ($FailurePrefix + "_launch_failed")
  }
  $startInfo = New-Object Diagnostics.ProcessStartInfo
  $startInfo.FileName = $Executable
  $startInfo.Arguments = ConvertTo-NativeCommandLine $Arguments
  $startInfo.UseShellExecute = $false
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  $startInfo.CreateNoWindow = $true
  $process = New-Object Diagnostics.Process
  $process.StartInfo = $startInfo
  $stdout = New-Object IO.MemoryStream
  $stderr = New-Object IO.MemoryStream
  $stdout.Capacity = $MaxStdoutBytes
  $stderr.Capacity = $MaxStderrBytes
  $failureReason = $null
  $exitCode = $null
  try {
    try {
      if (-not $process.Start()) { $failureReason = $FailurePrefix + "_launch_failed" }
    } catch { $failureReason = $FailurePrefix + "_launch_failed" }
    if ($null -eq $failureReason) {
      $stdoutBuffer = New-Object byte[] 4096
      $stderrBuffer = New-Object byte[] 4096
      $stdoutTask = $process.StandardOutput.BaseStream.ReadAsync($stdoutBuffer, 0, $stdoutBuffer.Length)
      $stderrTask = $process.StandardError.BaseStream.ReadAsync($stderrBuffer, 0, $stderrBuffer.Length)
      $stdoutDone = $false
      $stderrDone = $false
      $timer = [Diagnostics.Stopwatch]::StartNew()
      while ($null -eq $failureReason -and (-not $process.HasExited -or -not $stdoutDone -or -not $stderrDone)) {
        if (-not $stdoutDone -and $stdoutTask.IsCompleted) {
          try { $read = [int]$stdoutTask.Result } catch { $failureReason = $FailurePrefix + "_output_invalid"; continue }
          if ($read -eq 0) { $stdoutDone = $true } else {
            if (($stdout.Length + $read) -gt $MaxStdoutBytes) {
              $failureReason = $FailurePrefix + "_output_limit"
              continue
            }
            $stdout.Write($stdoutBuffer, 0, $read)
            $stdoutTask = $process.StandardOutput.BaseStream.ReadAsync($stdoutBuffer, 0, $stdoutBuffer.Length)
          }
        }
        if (-not $stderrDone -and $stderrTask.IsCompleted) {
          try { $read = [int]$stderrTask.Result } catch { $failureReason = $FailurePrefix + "_output_invalid"; continue }
          if ($read -eq 0) { $stderrDone = $true } else {
            if (($stderr.Length + $read) -gt $MaxStderrBytes) {
              $failureReason = $FailurePrefix + "_output_limit"
              continue
            }
            $stderr.Write($stderrBuffer, 0, $read)
            $stderrTask = $process.StandardError.BaseStream.ReadAsync($stderrBuffer, 0, $stderrBuffer.Length)
          }
        }
        if ($timer.ElapsedMilliseconds -ge $TimeoutMilliseconds) {
          $failureReason = $FailurePrefix + "_timeout"
          continue
        }
        if ($null -eq $failureReason -and
            (-not $process.HasExited -or -not $stdoutDone -or -not $stderrDone)) {
          Start-Sleep -Milliseconds 5
        }
      }
      $timer.Stop()
      if ($null -ne $failureReason -and -not $process.HasExited) {
        try { $process.Kill() } catch { }
        if (-not $process.WaitForExit(5000)) { $failureReason = $FailurePrefix + "_kill_failed" }
      }
      if ($null -eq $failureReason) {
        if (-not $process.WaitForExit(1000)) { $failureReason = $FailurePrefix + "_timeout" }
        else { $exitCode = [int]$process.ExitCode }
      }
    }
    if ($null -ne $failureReason) { Fail $failureReason }
    $stdoutBytes = $stdout.ToArray()
    $stderrBytes = $stderr.ToArray()
    try {
      return [pscustomobject]@{
        ExitCode = $exitCode
        Stdout = ConvertFrom-BoundedProcessBytes $stdoutBytes $OutputEncoding $FailurePrefix
        Stderr = ConvertFrom-BoundedProcessBytes $stderrBytes $OutputEncoding $FailurePrefix
      }
    } finally {
      if ($stdoutBytes.Length -gt 0) { [Array]::Clear($stdoutBytes, 0, $stdoutBytes.Length) }
      if ($stderrBytes.Length -gt 0) { [Array]::Clear($stderrBytes, 0, $stderrBytes.Length) }
    }
  } finally {
    $stdout.Dispose()
    $stderr.Dispose()
    $process.Dispose()
  }
}

function Test-ServiceExists {
  param([Parameter(Mandatory = $true)][string]$Name)
  $null = & sc.exe query $Name 2>$null
  return ($LASTEXITCODE -eq 0)
}

function Stop-ExactService {
  param([Parameter(Mandatory = $true)][string]$Name)
  if (-not (Test-ServiceExists $Name)) { return }
  $null = & sc.exe stop $Name 2>$null
  for ($attempt = 0; $attempt -lt 30; $attempt++) {
    $query = @(& sc.exe query $Name 2>&1)
    if (($query -join "`n") -match 'STATE\s*:\s*1\s+STOPPED') { return }
    Start-Sleep -Milliseconds 500
  }
  Fail "relay_uninstall_service_stop_timeout"
}

function Test-ServiceRunning {
  param([Parameter(Mandatory = $true)][string]$Name)
  if (-not (Test-ServiceExists $Name)) { return $false }
  $query = @(& sc.exe query $Name 2>&1)
  return (($query -join "`n") -match 'STATE\s*:\s*4\s+RUNNING')
}

function Wait-ServiceRunning {
  param([Parameter(Mandatory = $true)][string]$Name)
  for ($attempt = 0; $attempt -lt 30; $attempt++) {
    $query = @(& sc.exe query $Name 2>&1)
    if ($LASTEXITCODE -ne 0 -or ($query -join "`n").Length -gt 16384) {
      Fail "relay_uninstall_service_start_readback_failed"
    }
    $text = $query -join "`n"
    if ($text -match 'STATE\s*:\s*4\s+RUNNING') { return }
    if ($text -notmatch 'STATE\s*:\s*2\s+START_PENDING') {
      Fail "relay_uninstall_service_start_readback_failed"
    }
    Start-Sleep -Milliseconds 500
  }
  Fail "relay_uninstall_service_start_timeout"
}

function Get-ServiceStateEntry {
  param([Parameter(Mandatory = $true)]$States, [Parameter(Mandatory = $true)][string]$Name)
  if ($States -is [Collections.IDictionary]) { return $States[$Name] }
  $property = $States.PSObject.Properties[$Name]
  if ($null -eq $property) { Fail "relay_uninstall_wal_schema_invalid" }
  return $property.Value
}

function Invoke-Sc {
  param([Parameter(Mandatory = $true)][string[]]$Arguments)
  $result = @(& sc.exe @Arguments 2>&1)
  if ($LASTEXITCODE -ne 0 -or ($result -join "`n").Length -gt 16384) {
    Fail "relay_uninstall_scm_operation_failed"
  }
  return $result
}

function Initialize-ScmUnicodeApi {
  if ($null -ne ('MrdRelay.UninstallScmNative' -as [type])) { return }
  $source = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace MrdRelay {
  public static class UninstallScmNative {
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryConfig = 0x0001;
    private const uint ServiceConfigDelayedAutoStartInfo = 3;
    private const int ErrorInsufficientBuffer = 122;

    public sealed class BaseConfiguration {
      public string BinaryPath { get; private set; }
      public string Account { get; private set; }
      public uint StartType { get; private set; }
      public bool DelayedAutoStart { get; private set; }
      public string[] Dependencies { get; private set; }

      public BaseConfiguration(string binaryPath, string account, uint startType,
          bool delayedAutoStart, string[] dependencies) {
        BinaryPath = binaryPath;
        Account = account;
        StartType = startType;
        DelayedAutoStart = delayedAutoStart;
        Dependencies = dependencies;
      }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct QueryServiceConfigData {
      public uint ServiceType;
      public uint StartType;
      public uint ErrorControl;
      public IntPtr BinaryPathName;
      public IntPtr LoadOrderGroup;
      public uint TagId;
      public IntPtr Dependencies;
      public IntPtr ServiceStartName;
      public IntPtr DisplayName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceDelayedAutoStartInfo {
      [MarshalAs(UnmanagedType.Bool)]
      public bool DelayedAutoStart;
    }

    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true,
      CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenScManager(string machineName, string databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", ExactSpelling = true,
      CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr scManager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfigW", ExactSpelling = true,
      CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool NativeQueryServiceConfig(IntPtr service, IntPtr config,
      uint bufferBytes, out uint bytesNeeded);

    [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfig2W", ExactSpelling = true,
      CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool NativeQueryServiceConfig2(IntPtr service, uint infoLevel,
      ref ServiceDelayedAutoStartInfo info, uint bufferBytes, out uint bytesNeeded);

    [DllImport("advapi32.dll", EntryPoint = "CloseServiceHandle", ExactSpelling = true,
      SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    private static int RelativeOffset(IntPtr value, IntPtr buffer, uint bufferBytes) {
      if (value == IntPtr.Zero) throw new InvalidOperationException("required_pointer_missing");
      long relative = value.ToInt64() - buffer.ToInt64();
      if (relative < 0 || relative >= bufferBytes || (relative & 1) != 0) {
        throw new InvalidOperationException("configuration_pointer_invalid");
      }
      return (int)relative;
    }

    private static string ReadRequiredString(IntPtr value, IntPtr buffer, uint bufferBytes) {
      int relative = RelativeOffset(value, buffer, bufferBytes);
      int capacityChars = ((int)bufferBytes - relative) / 2;
      int length = 0;
      while (length < capacityChars && Marshal.ReadInt16(value, length * 2) != 0) length++;
      if (length == 0 || length >= capacityChars) {
        throw new InvalidOperationException("configuration_string_invalid");
      }
      return Marshal.PtrToStringUni(value, length);
    }

    private static string[] ParseMultiSz(IntPtr value, int capacityChars) {
      if (value == IntPtr.Zero) return new string[0];
      var result = new List<string>();
      int cursor = 0;
      while (true) {
        if (cursor >= capacityChars) throw new InvalidOperationException("unterminated_multi_sz");
        if (Marshal.ReadInt16(value, cursor * 2) == 0) return result.ToArray();
        int start = cursor;
        while (cursor < capacityChars && Marshal.ReadInt16(value, cursor * 2) != 0) cursor++;
        if (cursor >= capacityChars) throw new InvalidOperationException("unterminated_multi_sz");
        result.Add(Marshal.PtrToStringUni(IntPtr.Add(value, start * 2), cursor - start));
        cursor++;
      }
    }

    public static BaseConfiguration GetConfiguration(string serviceName) {
      IntPtr manager = OpenScManager(null, null, ScManagerConnect);
      if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
      try {
        IntPtr service = OpenService(manager, serviceName, ServiceQueryConfig);
        if (service == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
          uint needed;
          NativeQueryServiceConfig(service, IntPtr.Zero, 0, out needed);
          if (Marshal.GetLastWin32Error() != ErrorInsufficientBuffer ||
              needed < Marshal.SizeOf(typeof(QueryServiceConfigData)) || needed > 65536) {
            throw new InvalidOperationException("query_service_config_size_invalid");
          }
          uint bufferBytes = needed;
          IntPtr buffer = Marshal.AllocHGlobal((int)bufferBytes);
          try {
            uint returnedNeeded;
            if (!NativeQueryServiceConfig(service, buffer, bufferBytes, out returnedNeeded)) {
              throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            QueryServiceConfigData config = (QueryServiceConfigData)Marshal.PtrToStructure(
              buffer, typeof(QueryServiceConfigData));
            string binaryPath = ReadRequiredString(config.BinaryPathName, buffer, bufferBytes);
            string account = ReadRequiredString(config.ServiceStartName, buffer, bufferBytes);
            string[] dependencies;
            if (config.Dependencies == IntPtr.Zero) {
              dependencies = new string[0];
            } else {
              int relative = RelativeOffset(config.Dependencies, buffer, bufferBytes);
              dependencies = ParseMultiSz(
                config.Dependencies, ((int)bufferBytes - relative) / 2);
            }
            var delayed = new ServiceDelayedAutoStartInfo();
            uint delayedBytes;
            uint delayedSize = (uint)Marshal.SizeOf(typeof(ServiceDelayedAutoStartInfo));
            if (!NativeQueryServiceConfig2(service, ServiceConfigDelayedAutoStartInfo,
                ref delayed, delayedSize, out delayedBytes)) {
              throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return new BaseConfiguration(binaryPath, account, config.StartType,
              delayed.DelayedAutoStart, dependencies);
          } finally {
            Marshal.FreeHGlobal(buffer);
          }
        } finally {
          CloseServiceHandle(service);
        }
      } finally {
        CloseServiceHandle(manager);
      }
    }

    public static string[] GetDependencies(string serviceName) {
      return GetConfiguration(serviceName).Dependencies;
    }

    public static string[] DecodeMultiSzForContract(byte[] bytes) {
      if (bytes == null || bytes.Length < 2 || (bytes.Length & 1) != 0) {
        throw new ArgumentException("invalid_multi_sz_bytes");
      }
      GCHandle pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
      try {
        return ParseMultiSz(pinned.AddrOfPinnedObject(), bytes.Length / 2);
      } finally {
        pinned.Free();
      }
    }
  }
}
'@
  try { Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop } catch {
    Fail "relay_uninstall_scm_unicode_api_unavailable"
  }
}

function Get-ScmUnicodeConfiguration {
  param([Parameter(Mandatory = $true)][string]$ServiceName)
  Initialize-ScmUnicodeApi
  try { $native = [MrdRelay.UninstallScmNative]::GetConfiguration($ServiceName) } catch {
    Fail "relay_uninstall_scm_snapshot_incomplete"
  }
  $start = switch ([uint32]$native.StartType) {
    0 { "boot" }
    1 { "system" }
    2 { if ([bool]$native.DelayedAutoStart) { "delayed-auto" } else { "auto" } }
    3 { "demand" }
    4 { "disabled" }
    default { Fail "relay_uninstall_scm_snapshot_incomplete" }
  }
  if ([uint32]$native.StartType -ne 2 -and [bool]$native.DelayedAutoStart) {
    Fail "relay_uninstall_scm_snapshot_incomplete"
  }
  return [pscustomobject]@{
    binary_path = [string]$native.BinaryPath
    account = [string]$native.Account
    start = $start
    dependencies = @($native.Dependencies)
  }
}

function Get-ScmUnicodeDependencies {
  param([Parameter(Mandatory = $true)][string]$ServiceName)
  $configuration = Get-ScmUnicodeConfiguration $ServiceName
  return @($configuration.dependencies)
}

function Test-ScDependencyToken {
  param([Parameter(Mandatory = $true)][string]$Value)
  if ($Value.Length -lt 1 -or $Value.Length -gt 256 -or $Value.Trim() -cne $Value -or
      $Value -ceq "+" -or $Value.IndexOf('/') -ge 0 -or $Value.IndexOf('\') -ge 0 -or
      $Value.IndexOf('"') -ge 0) {
    return $false
  }
  foreach ($character in $Value.ToCharArray()) {
    if ([char]::IsControl($character)) { return $false }
  }
  return $true
}

function ConvertTo-CanonicalScBaseConfiguration {
  param([Parameter(Mandatory = $true)]$Configuration)
  $propertyNames = @($Configuration.PSObject.Properties.Name | Sort-Object)
  if (($propertyNames -join "`n") -cne ((@("account", "binary_path", "start") | Sort-Object) -join "`n")) {
    Fail "relay_uninstall_scm_base_configuration_invalid"
  }
  $binaryPath = [string]$Configuration.binary_path
  $account = [string]$Configuration.account
  $start = [string]$Configuration.start
  if ($binaryPath.Length -lt 1 -or $binaryPath.Length -gt 32768 -or
      $account.Length -lt 1 -or $account.Length -gt 256 -or
      $binaryPath -match '[\x00-\x1f\x7f]' -or $account -match '[\x00-\x1f\x7f]' -or
      $start -notin @("boot", "system", "auto", "delayed-auto", "demand", "disabled")) {
    Fail "relay_uninstall_scm_base_configuration_invalid"
  }
  return [ordered]@{ binary_path = $binaryPath; account = $account; start = $start }
}

function ConvertFrom-ScDependencies {
  param([Parameter(Mandatory = $true)][string]$Qc)
  $lines = @([regex]::Split($Qc, '\r?\n'))
  $headerIndexes = New-Object Collections.ArrayList
  for ($index = 0; $index -lt $lines.Count; $index++) {
    if ([regex]::IsMatch($lines[$index], '^\s*DEPENDENCIES\s*:', [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
      [void]$headerIndexes.Add($index)
    }
  }
  if ($headerIndexes.Count -ne 1) { Fail "relay_uninstall_scm_snapshot_incomplete" }
  $headerIndex = [int]$headerIndexes[0]
  $header = [regex]::Match($lines[$headerIndex], '^\s*DEPENDENCIES\s*:\s*(.*?)\s*$',
    [Text.RegularExpressions.RegexOptions]::IgnoreCase)
  if (-not $header.Success) { Fail "relay_uninstall_scm_snapshot_incomplete" }

  $dependencies = New-Object Collections.ArrayList
  $seen = @{}
  $consumedContinuations = @{}
  $first = $header.Groups[1].Value
  if (-not [string]::IsNullOrEmpty($first)) {
    if (-not (Test-ScDependencyToken $first)) { Fail "relay_uninstall_scm_snapshot_incomplete" }
    [void]$dependencies.Add($first)
    $seen[$first] = $true
  }
  for ($index = $headerIndex + 1; $index -lt $lines.Count; $index++) {
    $line = $lines[$index]
    $continuation = [regex]::Match($line, '^\s+:\s*(.*?)\s*$')
    if ($continuation.Success) {
      $value = $continuation.Groups[1].Value
      if ([string]::IsNullOrEmpty($first) -or [string]::IsNullOrEmpty($value) -or
          -not (Test-ScDependencyToken $value) -or
          $seen.ContainsKey($value) -or $dependencies.Count -ge 64) {
        Fail "relay_uninstall_scm_snapshot_incomplete"
      }
      [void]$dependencies.Add($value)
      $seen[$value] = $true
      $consumedContinuations[$index] = $true
      continue
    }
    if ([regex]::IsMatch($line, '^\s*[A-Z][A-Z0-9_ ]{0,63}\s*:',
        [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
      break
    }
    if (-not [string]::IsNullOrWhiteSpace($line)) {
      Fail "relay_uninstall_scm_snapshot_incomplete"
    }
    break
  }
  for ($index = 0; $index -lt $lines.Count; $index++) {
    if (-not $consumedContinuations.ContainsKey($index) -and
        [regex]::IsMatch($lines[$index], '^\s+:')) {
      Fail "relay_uninstall_scm_snapshot_incomplete"
    }
  }
  return @($dependencies)
}

function ConvertTo-ScDependencyValue {
  param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Dependencies)
  if ($Dependencies.Count -eq 0) { return "/" }
  if ($Dependencies.Count -gt 64) { Fail "relay_uninstall_scm_snapshot_incomplete" }
  $seen = @{}
  $values = New-Object Collections.ArrayList
  foreach ($dependency in $Dependencies) {
    if ($dependency -isnot [string]) { Fail "relay_uninstall_scm_snapshot_incomplete" }
    $value = [string]$dependency
    if (-not (Test-ScDependencyToken $value) -or $seen.ContainsKey($value)) {
      Fail "relay_uninstall_scm_snapshot_incomplete"
    }
    $seen[$value] = $true
    [void]$values.Add($value)
  }
  return (@($values) -join "/")
}

function ConvertFrom-ScServiceTranscript {
  param(
    [Parameter(Mandatory = $true)][string]$ServiceName,
    [Parameter(Mandatory = $true)][string]$Qc,
    [Parameter(Mandatory = $true)][string]$Failure,
    [Parameter(Mandatory = $true)][string]$FailureFlag,
    [Parameter(Mandatory = $true)][string]$SidType,
    [AllowEmptyCollection()][string[]]$ExactDependencies = @(),
    [switch]$UseExactDependencies,
    $ExactBaseConfiguration,
    [switch]$UseExactBaseConfiguration
  )
  foreach ($transcript in @($Qc, $Failure, $FailureFlag, $SidType)) {
    if ([string]::IsNullOrWhiteSpace($transcript) -or [Text.Encoding]::UTF8.GetByteCount($transcript) -gt 16384) {
      Fail "relay_uninstall_scm_snapshot_incomplete"
    }
  }
  $binaryMatch = [regex]::Match($Qc, '(?im)^\s*BINARY_PATH_NAME\s*:\s*(.+?)\s*$')
  $startMatch = [regex]::Match($Qc, '(?im)^\s*START_TYPE\s*:\s*[0-9]+\s+(BOOT_START|SYSTEM_START|AUTO_START|DEMAND_START|DISABLED)(?:\s+\((DELAYED)\))?\s*$')
  $accountMatch = [regex]::Match($Qc, '(?im)^\s*SERVICE_START_NAME\s*:\s*(.+?)\s*$')
  $resetMatch = [regex]::Match($Failure, '(?im)^\s*RESET_PERIOD[^:]*:\s*(INFINITE|[0-9]+)\s*$')
  $commandMatch = [regex]::Match($Failure, '(?im)^\s*COMMAND_LINE\s*:\s*(.*?)\s*$')
  $rebootMatch = [regex]::Match($Failure, '(?im)^\s*REBOOT_MESSAGE\s*:\s*(.*?)\s*$')
  $flagMatches = [regex]::Matches($FailureFlag, '(?im)^[^:\r\n]{1,256}:\s*(TRUE|FALSE|[01])\s*$')
  $sidMatch = [regex]::Match($SidType, '(?im):\s*(NONE|UNRESTRICTED|RESTRICTED)\s*$')
  if (-not $binaryMatch.Success -or -not $startMatch.Success -or -not $accountMatch.Success -or
      -not $resetMatch.Success -or -not $commandMatch.Success -or
      -not $rebootMatch.Success -or $flagMatches.Count -ne 1 -or -not $sidMatch.Success) {
    Fail "relay_uninstall_scm_snapshot_incomplete"
  }
  $actions = New-Object Collections.ArrayList
  foreach ($match in [regex]::Matches(
      $Failure,
      '(?im)^\s*(?:FAILURE_ACTIONS\s*:\s*)?(RESTART|RUN PROCESS|REBOOT|NONE)\s+--\s+Delay\s*=\s*([0-9]+)')) {
    [void]$actions.Add([ordered]@{
      action = $match.Groups[1].Value.ToLowerInvariant().Replace(' process', '')
      delay_ms = [uint32]$match.Groups[2].Value
    })
  }
  if ($actions.Count -eq 0 -or $actions.Count -gt 3) { Fail "relay_uninstall_scm_snapshot_incomplete" }
  $startValue = switch ($startMatch.Groups[1].Value) {
    "BOOT_START" { "boot" }; "SYSTEM_START" { "system" }
    "AUTO_START" { if ($startMatch.Groups[2].Success) { "delayed-auto" } else { "auto" } }
    "DEMAND_START" { "demand" }; "DISABLED" { "disabled" }
  }
  $transcriptDependencies = @(ConvertFrom-ScDependencies $Qc)
  if ($UseExactDependencies) {
    if ($transcriptDependencies.Count -ne $ExactDependencies.Count -or $ExactDependencies.Count -gt 64) {
      Fail "relay_uninstall_scm_snapshot_incomplete"
    }
    $exactSeen = @{}
    foreach ($dependency in $ExactDependencies) {
      if (-not (Test-ScDependencyToken $dependency) -or $exactSeen.ContainsKey($dependency)) {
        Fail "relay_uninstall_scm_snapshot_incomplete"
      }
      $exactSeen[$dependency] = $true
    }
    $dependencies = @($ExactDependencies)
  } else {
    $dependencies = @($transcriptDependencies)
  }
  $exactBase = $null
  if ($UseExactBaseConfiguration) {
    if ($null -eq $ExactBaseConfiguration) { Fail "relay_uninstall_scm_base_configuration_invalid" }
    $exactBase = ConvertTo-CanonicalScBaseConfiguration $ExactBaseConfiguration
  }
  $binaryPathValue = $binaryMatch.Groups[1].Value
  $accountValue = $accountMatch.Groups[1].Value
  if ($UseExactBaseConfiguration) {
    $binaryPathValue = [string]$exactBase.binary_path
    $accountValue = [string]$exactBase.account
    $startValue = [string]$exactBase.start
  }
  $flagToken = $flagMatches[0].Groups[1].Value.ToUpperInvariant()
  return [ordered]@{
    schema_version = 1; service_name = $ServiceName
    binary_path = $binaryPathValue; start = $startValue
    account = $accountValue; dependencies = $dependencies
    sid_type = $sidMatch.Groups[1].Value.ToLowerInvariant()
    failure_flag = if ($flagToken -ceq "TRUE" -or $flagToken -ceq "1") { 1 } else { 0 }
    failure_reset_seconds = if ($resetMatch.Groups[1].Value -ceq "INFINITE") { [uint32]4294967295 } else { [uint32]$resetMatch.Groups[1].Value }
    failure_command = $commandMatch.Groups[1].Value
    failure_reboot_message = $rebootMatch.Groups[1].Value
    failure_actions = @($actions)
  }
}

function Get-ExactScmSnapshot {
  param([Parameter(Mandatory = $true)][string]$Name)
  $outputs = @{}
  foreach ($query in @("qc", "qfailure", "qfailureflag", "qsidtype")) {
    $lines = @(& sc.exe $query $Name 2>&1)
    if ($LASTEXITCODE -ne 0 -or ($lines -join "`n").Length -gt 16384) {
      Fail "relay_uninstall_scm_snapshot_incomplete"
    }
    $outputs[$query] = $lines -join "`n"
  }
  $wideConfiguration = Get-ScmUnicodeConfiguration $Name
  $exactDependencies = @($wideConfiguration.dependencies)
  $exactBaseConfiguration = [pscustomobject]@{
    binary_path = [string]$wideConfiguration.binary_path
    account = [string]$wideConfiguration.account
    start = [string]$wideConfiguration.start
  }
  return ConvertFrom-ScServiceTranscript $Name $outputs.qc $outputs.qfailure `
    $outputs.qfailureflag $outputs.qsidtype -ExactDependencies $exactDependencies `
    -UseExactDependencies -ExactBaseConfiguration $exactBaseConfiguration `
    -UseExactBaseConfiguration
}

function Assert-ExactScmSnapshotEqual {
  param([Parameter(Mandatory = $true)]$Expected, [Parameter(Mandatory = $true)]$Actual)
  if (($Expected | ConvertTo-Json -Depth 8 -Compress) -cne
      ($Actual | ConvertTo-Json -Depth 8 -Compress)) {
    Fail "relay_uninstall_scm_rollback_readback_mismatch"
  }
}

function Wait-ServiceAbsent {
  param([Parameter(Mandatory = $true)][string]$Name)
  for ($attempt = 0; $attempt -lt 30; $attempt++) {
    $query = @(& sc.exe query $Name 2>&1)
    if ($LASTEXITCODE -eq 1060) { return }
    if ($LASTEXITCODE -eq 0) { Start-Sleep -Milliseconds 500; continue }
    # ERROR_SERVICE_MARKED_FOR_DELETE and all other unknown states are retried
    # only inside this fixed deadline, then fail closed with the WAL preserved.
    Start-Sleep -Milliseconds 500
  }
  Fail "relay_uninstall_service_absence_readback_failed"
}

function Remove-ExactScmRegistration {
  param([Parameter(Mandatory = $true)][string]$Name)
  if (Test-ServiceExists $Name) {
    $output = @(& sc.exe delete $Name 2>&1)
    if ($LASTEXITCODE -ne 0 -or ($output -join "`n").Length -gt 16384) {
      Fail "relay_uninstall_scm_delete_failed"
    }
  }
  Wait-ServiceAbsent $Name
}

function Restore-ExactScmSnapshot {
  param([Parameter(Mandatory = $true)]$Snapshot)
  $name = [string]$Snapshot.service_name
  $dependencyValue = ConvertTo-ScDependencyValue @($Snapshot.dependencies)
  $definitionRestored = $false
  for ($attempt = 0; $attempt -lt 30; $attempt++) {
    $verb = if (Test-ServiceExists $name) { "config" } else { "create" }
    $definitionOutput = @(& sc.exe $verb $name "binPath=" ([string]$Snapshot.binary_path) `
        "start=" ([string]$Snapshot.start) "obj=" ([string]$Snapshot.account) `
        "depend=" $dependencyValue 2>&1)
    if ($LASTEXITCODE -eq 0) { $definitionRestored = $true; break }
    if (($definitionOutput -join "`n").Length -gt 16384) { break }
    # This also covers ERROR_SERVICE_MARKED_FOR_DELETE. No unbounded retry and
    # no path leaves the protected WAL before an exact readback succeeds.
    Start-Sleep -Milliseconds 500
  }
  if (-not $definitionRestored) { Fail "relay_uninstall_scm_marked_delete_timeout" }
  $null = Invoke-Sc @("sidtype", $name, [string]$Snapshot.sid_type)
  $actionParts = @($Snapshot.failure_actions | ForEach-Object { "$($_.action)/$($_.delay_ms)" })
  $null = Invoke-Sc @(
    "failure", $name, "reset=", [string]$Snapshot.failure_reset_seconds,
    "reboot=", [string]$Snapshot.failure_reboot_message,
    "command=", [string]$Snapshot.failure_command,
    "actions=", ($actionParts -join "/")
  )
  $null = Invoke-Sc @("failureflag", $name, [string]$Snapshot.failure_flag)
  Assert-ExactScmSnapshotEqual $Snapshot (Get-ExactScmSnapshot $name)
}

function Get-UninstallRollbackPlan {
  param([Parameter(Mandatory = $true)]$ServiceStates)
  $plan = New-Object Collections.ArrayList
  [void]$plan.Add("RestoreRoots")
  [void]$plan.Add("RestoreFirewall")
  foreach ($name in @($NativeCoturnServiceName, $BrokerServiceName, $AgentServiceName)) {
    $state = Get-ServiceStateEntry $ServiceStates $name
    if ([bool]$state.existed) {
      [void]$plan.Add("RestoreService:$name")
    } else {
      [void]$plan.Add("VerifyAbsent:$name")
    }
  }
  foreach ($name in @($NativeCoturnServiceName, $BrokerServiceName, $AgentServiceName)) {
    $state = Get-ServiceStateEntry $ServiceStates $name
    if ([bool]$state.was_running) { [void]$plan.Add("StartService:$name") }
  }
  return @($plan)
}

function Assert-UninstallRollbackPlanSelfTest {
  $qc = @'
SERVICE_NAME: mrd-relay-agent
        START_TYPE         : 2   AUTO_START  (DELAYED)
        BINARY_PATH_NAME   : "C:\MRD\mrd-relay-agent.exe" run --config "C:\MRD\agent.json"
        DEPENDENCIES       : mrd-relay-coturn-control
                           : RpcSs
                           : +NetworkProvider
                           : MSSQL$SQLEXPRESS
                           : MRD 辅助服务
        SERVICE_START_NAME : NT AUTHORITY\LocalService
'@
  $failure = @'
        RESET_PERIOD (in seconds) : 4294967295
        REBOOT_MESSAGE             :
        COMMAND_LINE               :
        FAILURE_ACTIONS            : RESTART -- Delay = 5000 milliseconds.
                                     RESTART -- Delay = 30000 milliseconds.
                                     NONE -- Delay = 0 milliseconds.
'@
  $snapshot = ConvertFrom-ScServiceTranscript $AgentServiceName $qc $failure `
    "FAILURE_ACTIONS_ON_NONCRASH_FAILURES: TRUE" "SERVICE_SID_TYPE: RESTRICTED"
  $falseSnapshot = ConvertFrom-ScServiceTranscript $AgentServiceName $qc $failure `
    "FAILURE_ACTIONS_ON_NONCRASH_FAILURES: FALSE" "SERVICE_SID_TYPE: RESTRICTED"
  if ([int]$snapshot.failure_flag -ne 1 -or [int]$falseSnapshot.failure_flag -ne 0) {
    Fail "relay_uninstall_scm_self_test_failureflag_not_normalized"
  }
  if ((@($snapshot.dependencies) -join "|") -cne
      'mrd-relay-coturn-control|RpcSs|+NetworkProvider|MSSQL$SQLEXPRESS|MRD 辅助服务') {
    Fail "relay_uninstall_scm_self_test_multiline_dependencies_lost"
  }
  $expectedDependencies = @(
    "mrd-relay-coturn-control", "RpcSs", "+NetworkProvider", 'MSSQL$SQLEXPRESS', "MRD 辅助服务"
  )
  Initialize-ScmUnicodeApi
  $nul = [char]0
  $multiSzBytes = (New-Object Text.UnicodeEncoding($false, $false, $true)).GetBytes(
    ($expectedDependencies -join $nul) + $nul + $nul)
  try {
    $wideDependencies = @([MrdRelay.UninstallScmNative]::DecodeMultiSzForContract($multiSzBytes))
  } finally {
    [Array]::Clear($multiSzBytes, 0, $multiSzBytes.Length)
  }
  if (($wideDependencies -join "|") -cne ($expectedDependencies -join "|")) {
    Fail "relay_uninstall_scm_self_test_unicode_multi_sz_corrupted"
  }
  $mojibakeQc = $qc.Replace('MSSQL$SQLEXPRESS', 'MSSQL?SQLEXPRESS').Replace(
    'MRD 辅助服务', 'MRD ?????'
  ).Replace(
    '"C:\MRD\mrd-relay-agent.exe" run --config "C:\MRD\agent.json"',
    '"C:\MRD\????.exe" run --config "C:\MRD\????.json"'
  ).Replace('NT AUTHORITY\LocalService', 'NT AUTHORITY\????')
  $expectedWideBaseConfiguration = [pscustomobject]@{
    binary_path = '"C:\MRD\中继代理.exe" run --config "C:\MRD\配置.json"'
    account = 'NT AUTHORITY\本地服务'
    start = 'delayed-auto'
  }
  $wideSnapshot = ConvertFrom-ScServiceTranscript $AgentServiceName $mojibakeQc $failure `
    "FAILURE_ACTIONS_ON_NONCRASH_FAILURES: TRUE" "SERVICE_SID_TYPE: RESTRICTED" `
    -ExactDependencies $wideDependencies -UseExactDependencies `
    -ExactBaseConfiguration $expectedWideBaseConfiguration -UseExactBaseConfiguration
  if ((@($wideSnapshot.dependencies) -join "|") -cne ($expectedDependencies -join "|")) {
    Fail "relay_uninstall_scm_self_test_unicode_authority_not_used"
  }
  if ([string]$wideSnapshot.binary_path -cne [string]$expectedWideBaseConfiguration.binary_path -or
      [string]$wideSnapshot.account -cne [string]$expectedWideBaseConfiguration.account -or
      [string]$wideSnapshot.start -cne [string]$expectedWideBaseConfiguration.start) {
    Fail "relay_uninstall_scm_self_test_unicode_base_configuration_not_used"
  }
  $liveUnicodeDependencies = @(Get-ScmUnicodeDependencies "Winmgmt")
  foreach ($dependency in $liveUnicodeDependencies) {
    if (-not (Test-ScDependencyToken $dependency)) {
      Fail "relay_uninstall_scm_self_test_live_unicode_api_invalid"
    }
  }
  if ((ConvertTo-ScDependencyValue @($snapshot.dependencies)) -cne
      'mrd-relay-coturn-control/RpcSs/+NetworkProvider/MSSQL$SQLEXPRESS/MRD 辅助服务' -or
      (ConvertTo-ScDependencyValue @()) -cne "/") {
    Fail "relay_uninstall_scm_self_test_dependency_restore_value_invalid"
  }
  $emptyQc = $qc -replace '(?m)^\s*DEPENDENCIES\s*:.*(?:\r?\n\s*:.*){4}', '        DEPENDENCIES       :'
  $emptySnapshot = ConvertFrom-ScServiceTranscript $AgentServiceName $emptyQc $failure `
    "FAILURE_ACTIONS_ON_NONCRASH_FAILURES: TRUE" "SERVICE_SID_TYPE: RESTRICTED"
  if (@($emptySnapshot.dependencies).Count -ne 0) {
    Fail "relay_uninstall_scm_self_test_empty_dependencies_invalid"
  }
  foreach ($invalidQc in @(
      ($qc + "`n        DEPENDENCIES       : duplicate"),
      ($qc -replace ': RpcSs', ': mrd-relay-coturn-control'),
      ($qc -replace ': RpcSs', ': bad/name'),
      ($qc -replace ': RpcSs', ': bad\name'),
      ($qc -replace ': RpcSs', '                           RpcSs'),
      ($emptyQc + "`n                           : hidden-dependency")
    )) {
    $invalidRejected = $false
    try {
      $null = ConvertFrom-ScServiceTranscript $AgentServiceName $invalidQc $failure `
        "FAILURE_ACTIONS_ON_NONCRASH_FAILURES: TRUE" "SERVICE_SID_TYPE: RESTRICTED"
    } catch { $invalidRejected = $true }
    if (-not $invalidRejected) {
      Fail "relay_uninstall_scm_self_test_malformed_dependencies_accepted"
    }
  }
  $shortSnapshot = [ordered]@{}
  foreach ($property in $snapshot.GetEnumerator()) { $shortSnapshot[$property.Key] = $property.Value }
  $shortSnapshot.dependencies = @("mrd-relay-coturn-control", "RpcSs")
  $readbackMismatchRejected = $false
  try { Assert-ExactScmSnapshotEqual $snapshot $shortSnapshot } catch { $readbackMismatchRejected = $true }
  if (-not $readbackMismatchRejected) {
    Fail "relay_uninstall_scm_self_test_dependency_readback_mismatch_accepted"
  }
  $unknownRejected = $false
  try {
    $null = ConvertFrom-ScServiceTranscript $AgentServiceName $qc $failure `
      "FAILURE_ACTIONS_ON_NONCRASH_FAILURES: ENABLED" "SERVICE_SID_TYPE: RESTRICTED"
  } catch { $unknownRejected = $true }
  if (-not $unknownRejected) { Fail "relay_uninstall_scm_self_test_unknown_failureflag_accepted" }
  $states = [ordered]@{
    $AgentServiceName = [ordered]@{ existed = $true; was_running = $true; snapshot = $snapshot }
    $BrokerServiceName = [ordered]@{ existed = $true; was_running = $true; snapshot = $snapshot }
    $NativeCoturnServiceName = [ordered]@{ existed = $false; was_running = $false; snapshot = $null }
  }
  $plan = @(Get-UninstallRollbackPlan $states)
  if ($plan -notcontains "RestoreService:$AgentServiceName" -or
      $plan -notcontains "RestoreService:$BrokerServiceName" -or
      $plan -notcontains "VerifyAbsent:$NativeCoturnServiceName" -or
      [Array]::IndexOf($plan, "RestoreRoots") -ge [Array]::IndexOf($plan, "RestoreService:$AgentServiceName")) {
    Fail "relay_uninstall_scm_self_test_partial_delete_restore_invalid"
  }
  foreach ($phase in @("pre-mutation-checkpoint", "scm-delete:mrd-relay-agent", "data-archived")) {
    if (-not (Test-UninstallWalPhase $phase)) { Fail "relay_uninstall_wal_self_test_valid_phase_rejected" }
  }
  foreach ($phase in @("", "scm-delete:attacker", "complete-ish")) {
    if (Test-UninstallWalPhase $phase) { Fail "relay_uninstall_wal_self_test_unknown_phase_accepted" }
  }
}

function Assert-WslExecutionIdentitySelfTest {
  if (-not (Test-WslExecutionIdentity "Wsl2" "S-1-5-18") -or
      (Test-WslExecutionIdentity "Wsl2" "S-1-5-32-544") -or
      (Test-WslExecutionIdentity "Wsl2" "S-1-5-21-1-2-3-1001") -or
      -not (Test-WslExecutionIdentity "Docker" "S-1-5-32-544") -or
      -not (Test-WslExecutionIdentity "Native" "S-1-5-32-544")) {
    Fail "relay_uninstall_wsl_identity_self_test_failed"
  }
  $source = [IO.File]::ReadAllText($PSCommandPath)
  $stopStart = $source.IndexOf('function Stop-VerifiedWslDistribution')
  $stopIdentity = $source.IndexOf('Assert-WslLocalSystemContext "Wsl2"', $stopStart)
  $stopInvocation = $source.IndexOf('Invoke-BoundedNativeProcess $wslPath', $stopStart)
  $preMutationIdentity = $source.LastIndexOf(
    'if (-not [string]::IsNullOrEmpty($Target)) { Assert-WslLocalSystemContext $Target }')
  $approval = $source.LastIndexOf('if (-not $PSCmdlet.ShouldProcess(')
  $deploymentLock = $source.LastIndexOf('$deploymentLock = Enter-DeploymentLock')
  $recoveryInitialization = $source.LastIndexOf('Initialize-OrValidateRecoveryRoot $RecoveryRoot')
  if ($stopStart -lt 0 -or $stopIdentity -le $stopStart -or $stopInvocation -le $stopIdentity -or
      $approval -lt 0 -or $deploymentLock -le $approval -or
      $preMutationIdentity -le $deploymentLock -or $recoveryInitialization -le $preMutationIdentity) {
    Fail "relay_uninstall_wsl_identity_self_test_invocation_order_invalid"
  }
}

function Assert-TransactionLockSelfTest {
  $directory = [IO.Path]::Combine([IO.Path]::GetTempPath(), "mrd-uninstall-lock-" + [Guid]::NewGuid().ToString("N"))
  [void][IO.Directory]::CreateDirectory($directory)
  $lockPath = [IO.Path]::Combine($directory, "transaction.lock")
  $readyPath = [IO.Path]::Combine($directory, "ready")
  $holderPath = [IO.Path]::Combine($directory, "hold-lock.ps1")
  $holderScript = @'
param([string]$LockPath, [string]$ReadyPath)
$stream = [IO.File]::Open($LockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
try {
  [IO.File]::WriteAllText($ReadyPath, "ready")
  Start-Sleep -Seconds 30
} finally {
  $stream.Dispose()
}
'@
  [IO.File]::WriteAllText($holderPath, $holderScript, (New-Object Text.UTF8Encoding($false)))
  $hostExecutable = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
  $startInfo = New-Object Diagnostics.ProcessStartInfo
  $startInfo.FileName = $hostExecutable
  $startInfo.Arguments = ConvertTo-NativeCommandLine @(
    "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $holderPath,
    "-LockPath", $lockPath, "-ReadyPath", $readyPath
  )
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $holder = New-Object Diagnostics.Process
  $holder.StartInfo = $startInfo
  $holderStarted = $false
  $reacquired = $null
  try {
    $holderStarted = $holder.Start()
    if (-not $holderStarted) { Fail "relay_uninstall_lock_self_test_holder_failed" }
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    while (-not [IO.File]::Exists($readyPath) -and $deadline.ElapsedMilliseconds -lt 5000 -and
        -not $holder.HasExited) {
      Start-Sleep -Milliseconds 10
    }
    if (-not [IO.File]::Exists($readyPath) -or $holder.HasExited) {
      Fail "relay_uninstall_lock_self_test_holder_failed"
    }
    $busyRejected = $false
    try {
      $second = Open-ExclusiveFileLock $lockPath.ToUpperInvariant() "relay_uninstall_deploy_lock_busy"
      $second.Dispose()
    } catch {
      $busyRejected = ($_.Exception.Message -ceq "relay_uninstall_deploy_lock_busy")
    }
    if (-not $busyRejected) { Fail "relay_uninstall_lock_self_test_parallel_writer_accepted" }
    $holder.Kill()
    if (-not $holder.WaitForExit(5000)) { Fail "relay_uninstall_lock_self_test_holder_kill_failed" }
    $reacquired = Open-ExclusiveFileLock $lockPath "relay_uninstall_deploy_lock_busy"
  } finally {
    if ($null -ne $reacquired) { $reacquired.Dispose() }
    if ($holderStarted -and -not $holder.HasExited) {
      try { $holder.Kill(); $null = $holder.WaitForExit(5000) } catch { }
    }
    $holder.Dispose()
    foreach ($temporaryPath in @($readyPath, $lockPath, $holderPath)) {
      if ([IO.File]::Exists($temporaryPath)) {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
      }
    }
    if ([IO.Directory]::Exists($directory)) {
      Remove-Item -LiteralPath $directory -Force -ErrorAction SilentlyContinue
    }
  }
  $expectedLockPath = [IO.Path]::Combine(
    [IO.Path]::GetFullPath([Environment]::GetFolderPath(
      [Environment+SpecialFolder]::CommonApplicationData)).TrimEnd([IO.Path]::DirectorySeparatorChar),
    "MRD", ".mrd-relay-deploy.lock"
  )
  $firstRecoveryRootLock = Get-DeploymentLockPath
  $savedProgramData = $env:ProgramData
  try {
    $env:ProgramData = "Z:\attacker-controlled-programdata"
    $secondRecoveryRootLock = Get-DeploymentLockPath
  } finally {
    $env:ProgramData = $savedProgramData
  }
  if ($firstRecoveryRootLock -ine $expectedLockPath -or
      $secondRecoveryRootLock -ine $expectedLockPath -or
      $DeploymentLockContent -cne "MRD relay deployment lock v1`n") {
    Fail "relay_uninstall_lock_self_test_machine_scope_invalid"
  }
  $source = [IO.File]::ReadAllText($PSCommandPath)
  $lockPathFunctionStart = $source.IndexOf('function Get-DeploymentLockPath')
  if ($lockPathFunctionStart -lt 0) { Fail "relay_uninstall_lock_self_test_machine_scope_invalid" }
  $lockPathFunctionEnd = $source.IndexOf('function Initialize-DeploymentLockFileIfMissing', $lockPathFunctionStart)
  if ($lockPathFunctionEnd -le $lockPathFunctionStart) {
    Fail "relay_uninstall_lock_self_test_machine_scope_invalid"
  }
  $lockPathFunction = $source.Substring(
    $lockPathFunctionStart, $lockPathFunctionEnd - $lockPathFunctionStart)
  if ($lockPathFunction.Contains('$RecoveryRoot') -or $lockPathFunction.Contains('$env:ProgramData')) {
    Fail "relay_uninstall_lock_self_test_recovery_root_or_env_key_accepted"
  }
  $approvalIndex = $source.LastIndexOf('if (-not $PSCmdlet.ShouldProcess(')
  $enterIndex = $source.LastIndexOf('$deploymentLock = Enter-DeploymentLock')
  $rootDispositionIndex = $source.LastIndexOf(
    '$recoveryRootExistedBeforeLock = [IO.Directory]::Exists($RecoveryRoot)')
  $lockedManifestGateIndex = $source.LastIndexOf('$lockedManifestTarget =')
  $explicitWslGateIndex = $source.LastIndexOf(
    'if (-not [string]::IsNullOrEmpty($Target)) { Assert-WslLocalSystemContext $Target }')
  $initializeIndex = $source.LastIndexOf('Initialize-OrValidateRecoveryRoot $RecoveryRoot')
  $scanIndex = $source.LastIndexOf('$incompleteWal = Find-IncompleteUninstallWal')
  $walWslGateIndex = $source.LastIndexOf(
    'Assert-WslLocalSystemContext ([string]$incompleteWal.Wal.target)')
  $walRestoreIndex = $source.LastIndexOf(
    'Restore-UninstallCheckpoint $incompleteWal.Wal', $source.Length - 1)
  if ($approvalIndex -lt 0 -or $enterIndex -le $approvalIndex -or
      $rootDispositionIndex -le $enterIndex -or $lockedManifestGateIndex -le $rootDispositionIndex -or
      $explicitWslGateIndex -le $lockedManifestGateIndex -or
      $initializeIndex -le $explicitWslGateIndex -or
      $scanIndex -le $initializeIndex -or $walWslGateIndex -le $scanIndex -or
      $walRestoreIndex -le $walWslGateIndex) {
    Fail "relay_uninstall_lock_self_test_whatif_or_scan_order_invalid"
  }
}

function Assert-BoundedNativeProcessSelfTest {
  $hostExecutable = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
  $success = Invoke-BoundedNativeProcess $hostExecutable @(
    "-NoProfile", "-NonInteractive", "-Command",
    "[Console]::Out.Write('stdout-ok'); [Console]::Error.Write('stderr-ok'); exit 7"
  ) 5000 128 128 "relay_uninstall_process_self_test" "Utf8"
  if ($success.ExitCode -ne 7 -or $success.Stdout -cne "stdout-ok" -or
      $success.Stderr -cne "stderr-ok") {
    Fail "relay_uninstall_process_self_test_success_invalid"
  }
  $timeoutRejected = $false
  $pidPath = [IO.Path]::Combine([IO.Path]::GetTempPath(), "mrd-uninstall-timeout-" + [Guid]::NewGuid().ToString("N"))
  $escapedPidPath = $pidPath.Replace("'", "''")
  try {
    $null = Invoke-BoundedNativeProcess $hostExecutable @(
      "-NoProfile", "-NonInteractive", "-Command",
      "[IO.File]::WriteAllText('$escapedPidPath', [string]`$PID); Start-Sleep -Seconds 5"
    ) 1500 128 128 "relay_uninstall_process_self_test" "Utf8"
  } catch { $timeoutRejected = ($_.Exception.Message -ceq "relay_uninstall_process_self_test_timeout") }
  if (-not $timeoutRejected) { Fail "relay_uninstall_process_self_test_timeout_not_enforced" }
  if (-not [IO.File]::Exists($pidPath)) { Fail "relay_uninstall_process_self_test_timeout_child_not_started" }
  $timedOutPid = [int][IO.File]::ReadAllText($pidPath)
  Remove-Item -LiteralPath $pidPath -Force
  $timedOutChildStillRunning = $false
  try {
    $timedOutProcess = [Diagnostics.Process]::GetProcessById($timedOutPid)
    $timedOutChildStillRunning = -not $timedOutProcess.HasExited
    $timedOutProcess.Dispose()
  } catch [ArgumentException] { }
  if ($timedOutChildStillRunning) { Fail "relay_uninstall_process_self_test_timeout_child_survived" }
  $overflowRejected = $false
  try {
    $null = Invoke-BoundedNativeProcess $hostExecutable @(
      "-NoProfile", "-NonInteractive", "-Command",
      "[Console]::Out.Write(('o' * 8192)); [Console]::Error.Write(('e' * 8192))"
    ) 5000 256 256 "relay_uninstall_process_self_test" "Utf8"
  } catch { $overflowRejected = ($_.Exception.Message -ceq "relay_uninstall_process_self_test_output_limit") }
  if (-not $overflowRejected) { Fail "relay_uninstall_process_self_test_output_limit_not_enforced" }
  $wslBytes = (New-Object Text.UnicodeEncoding($false, $false, $true)).GetBytes("MRDRelay`r`n")
  if ((ConvertFrom-BoundedProcessBytes $wslBytes "Utf16Le" "relay_uninstall_process_self_test") -cne
      "MRDRelay`r`n") {
    Fail "relay_uninstall_process_self_test_utf16_invalid"
  }
  foreach ($invalidEncodingCase in @(
      @([byte]0x41),
      @([byte]0x00, [byte]0xD8),
      @([byte]0x41, [byte]0x00, [byte]0x00, [byte]0x00)
    )) {
    $encodingRejected = $false
    try {
      $null = ConvertFrom-BoundedProcessBytes ([byte[]]$invalidEncodingCase) "Utf16Le" `
        "relay_uninstall_process_self_test"
    } catch { $encodingRejected = ($_.Exception.Message -ceq "relay_uninstall_process_self_test_output_invalid") }
    if (-not $encodingRejected) { Fail "relay_uninstall_process_self_test_utf16_malformed_accepted" }
  }
  $invalidUtf8Rejected = $false
  try {
    $null = ConvertFrom-BoundedProcessBytes ([byte[]]@(0xC3, 0x28)) "Utf8" `
      "relay_uninstall_process_self_test"
  } catch { $invalidUtf8Rejected = ($_.Exception.Message -ceq "relay_uninstall_process_self_test_output_invalid") }
  if (-not $invalidUtf8Rejected) { Fail "relay_uninstall_process_self_test_utf8_malformed_accepted" }
  $source = [IO.File]::ReadAllText($PSCommandPath)
  if ([regex]::IsMatch($source, '&\s+\$(?:DockerExecutable|dockerPath|wslPath)\b')) {
    Fail "relay_uninstall_process_self_test_unbounded_target_cli_found"
  }
  foreach ($requiredCall in @(
      '@("--terminate", $WslDistributionName) 30000 8192 8192',
      '@("--list", "--running", "--quiet") 10000 8192 8192',
      '"relay_uninstall_wsl_terminate" "Utf16Le"',
      '"relay_uninstall_wsl_running_query" "Utf16Le"',
      '@("stop", "--time", "30", [string]$identity.container_id) 45000 8192 8192',
      '"relay_uninstall_docker_inspect" "Utf8"',
      '"relay_uninstall_docker_stop" "Utf8"'
    )) {
    if ($source.IndexOf($requiredCall, [StringComparison]::Ordinal) -lt 0) {
      Fail "relay_uninstall_process_self_test_bounded_target_cli_missing"
    }
  }
}

function Set-SystemAdminDirectoryAcl {
  param([Parameter(Mandatory = $true)][string]$Path)
  $null = & icacls.exe $Path "/setowner" "BUILTIN\Administrators"
  if ($LASTEXITCODE -ne 0) { Fail "relay_uninstall_recovery_owner_failed" }
  $null = & icacls.exe $Path "/inheritance:r" "/grant:r" `
    "SYSTEM:(OI)(CI)(F)" "BUILTIN\Administrators:(OI)(CI)(F)"
  if ($LASTEXITCODE -ne 0) { Fail "relay_uninstall_recovery_acl_failed" }
  Assert-ExactSystemAdminBoundaryAcl $Path
}

function Assert-ExactSystemAdminBoundaryAcl {
  param([Parameter(Mandatory = $true)][string]$Path)
  if (-not [IO.Directory]::Exists($Path)) { Fail "relay_uninstall_recovery_boundary_missing" }
  $item = Get-Item -LiteralPath $Path -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail "relay_uninstall_recovery_boundary_reparse_rejected"
  }
  $acl = Get-Acl -LiteralPath $Path
  if (-not $acl.AreAccessRulesProtected -or
      $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @("S-1-5-18", "S-1-5-32-544")) {
    Fail "relay_uninstall_recovery_boundary_owner_invalid"
  }
  $allowed = @("S-1-5-18", "S-1-5-32-544")
  $seen = @{}
  $expectedInheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [Security.AccessControl.InheritanceFlags]::ObjectInherit
  foreach ($entry in $acl.Access) {
    $sid = $entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    if ($entry.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $entry.IsInherited -or $allowed -notcontains $sid -or $seen.ContainsKey($sid) -or
        $entry.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
        $entry.InheritanceFlags -ne $expectedInheritance -or
        $entry.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
      Fail "relay_uninstall_recovery_boundary_acl_invalid"
    }
    $seen[$sid] = $true
  }
  if ($seen.Count -ne 2) { Fail "relay_uninstall_recovery_boundary_acl_invalid" }
}

function Assert-DisjointManagedRoots {
  param([Parameter(Mandatory = $true)][string[]]$Roots)
  for ($leftIndex = 0; $leftIndex -lt $Roots.Count; $leftIndex++) {
    $left = $Roots[$leftIndex].TrimEnd([IO.Path]::DirectorySeparatorChar)
    for ($rightIndex = $leftIndex + 1; $rightIndex -lt $Roots.Count; $rightIndex++) {
      $right = $Roots[$rightIndex].TrimEnd([IO.Path]::DirectorySeparatorChar)
      if ($left -ieq $right -or
          $left.StartsWith($right + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
          $right.StartsWith($left + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        Fail "relay_uninstall_root_overlap_rejected"
      }
    }
  }
}

function Test-RecoveryRootDisposition {
  param(
    [Parameter(Mandatory = $true)][string]$Candidate,
    [Parameter(Mandatory = $true)][string]$TrustedParent,
    [Parameter(Mandatory = $true)][bool]$RootExists,
    [Parameter(Mandatory = $true)][bool]$ParentTrusted,
    [Parameter(Mandatory = $true)][bool]$RootTrusted,
    [Parameter(Mandatory = $true)][bool]$MarkerValid
  )
  if ([IO.Path]::GetDirectoryName($Candidate) -ine $TrustedParent -or -not $ParentTrusted) { return $false }
  return -not $RootExists -or ($RootTrusted -and $MarkerValid)
}

function Assert-ExactSystemAdminFileAcl {
  param([Parameter(Mandatory = $true)][string]$Path)
  $item = Get-Item -LiteralPath $Path -Force
  $acl = Get-Acl -LiteralPath $Path
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
      $item.Length -le 0 -or $item.Length -gt 4096 -or -not $acl.AreAccessRulesProtected -or
      $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne "S-1-5-32-544") {
    Fail "relay_uninstall_recovery_marker_acl_invalid"
  }
  $allowed = @("S-1-5-18", "S-1-5-32-544")
  $seen = @{}
  foreach ($entry in $acl.Access) {
    $sid = $entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    if ($entry.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $entry.IsInherited -or $allowed -notcontains $sid -or $seen.ContainsKey($sid) -or
        $entry.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
        $entry.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
        $entry.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
      Fail "relay_uninstall_recovery_marker_acl_invalid"
    }
    $seen[$sid] = $true
  }
  if ($seen.Count -ne 2) { Fail "relay_uninstall_recovery_marker_acl_invalid" }
}

function Assert-RecoveryRootMarker {
  param([Parameter(Mandatory = $true)][string]$Path)
  $markerPath = [IO.Path]::Combine($Path, $RecoveryRootMarkerName)
  if (-not [IO.File]::Exists($markerPath)) { Fail "relay_uninstall_recovery_marker_missing" }
  Assert-ExactSystemAdminFileAcl $markerPath
  $raw = Get-Content -LiteralPath $markerPath -Raw
  if ([Text.Encoding]::UTF8.GetByteCount($raw) -gt 4096 -or
      [regex]::Matches($raw, '"[A-Za-z0-9_]+"\s*:').Count -ne 5) {
    Fail "relay_uninstall_recovery_marker_schema_invalid"
  }
  try { $marker = $raw | ConvertFrom-Json } catch { Fail "relay_uninstall_recovery_marker_schema_invalid" }
  $rootOwnerSid = (Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier]).Value
  $actualKeys = @($marker.PSObject.Properties.Name | Sort-Object)
  $expectedKeys = @("canonical_path", "owner_sid", "product", "purpose", "schema_version" | Sort-Object)
  if (($actualKeys -join "`n") -cne ($expectedKeys -join "`n") -or
      $marker.schema_version -ne 1 -or $marker.product -cne "mini-remote-desktop" -or
      $marker.purpose -cne "mrd-relay-recovery-root" -or
      $marker.owner_sid -cne "S-1-5-32-544" -or $marker.owner_sid -cne $rootOwnerSid -or
      [string]$marker.canonical_path -ine $Path) {
    Fail "relay_uninstall_recovery_marker_schema_invalid"
  }
}

function Set-SystemAdminFileAcl {
  param([Parameter(Mandatory = $true)][string]$Path)
  $null = & icacls.exe $Path "/setowner" "BUILTIN\Administrators"
  if ($LASTEXITCODE -ne 0) { Fail "relay_uninstall_recovery_marker_owner_failed" }
  $null = & icacls.exe $Path "/inheritance:r" "/grant:r" "SYSTEM:(F)" "BUILTIN\Administrators:(F)"
  if ($LASTEXITCODE -ne 0) { Fail "relay_uninstall_recovery_marker_acl_failed" }
  Assert-ExactSystemAdminFileAcl $Path
}

function Initialize-OrValidateRecoveryRoot {
  param([Parameter(Mandatory = $true)][string]$Path)
  $parent = [IO.Path]::GetDirectoryName($Path)
  Assert-ExactSystemAdminBoundaryAcl $parent
  if ([IO.Directory]::Exists($Path)) {
    Assert-ExactSystemAdminBoundaryAcl $Path
    Assert-RecoveryRootMarker $Path
    return
  }
  [void][IO.Directory]::CreateDirectory($Path)
  Set-SystemAdminDirectoryAcl $Path
  $markerPath = [IO.Path]::Combine($Path, $RecoveryRootMarkerName)
  $temporary = $markerPath + "." + [Guid]::NewGuid().ToString("N") + ".pending"
  $marker = [ordered]@{
    schema_version = 1; product = "mini-remote-desktop"; purpose = "mrd-relay-recovery-root"
    canonical_path = $Path; owner_sid = "S-1-5-32-544"
  }
  [IO.File]::WriteAllText(
    $temporary, ($marker | ConvertTo-Json -Compress) + "`n", (New-Object Text.UTF8Encoding($false)))
  Set-SystemAdminFileAcl $temporary
  Move-Item -LiteralPath $temporary -Destination $markerPath
  Assert-RecoveryRootMarker $Path
}

function Open-ExclusiveFileLock {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$BusyReason
  )
  try {
    return [IO.File]::Open($Path, [IO.FileMode]::Open,
      [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  } catch [IO.IOException] {
    Fail $BusyReason
  } catch [UnauthorizedAccessException] {
    Fail "relay_uninstall_deploy_lock_acl_invalid"
  }
}

function Get-DeploymentLockPath {
  $machineRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
  if ([string]::IsNullOrWhiteSpace($machineRoot)) {
    Fail "relay_uninstall_common_application_data_unavailable"
  }
  $canonicalRoot = [IO.Path]::GetFullPath($machineRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
  $boundary = [IO.Path]::Combine($canonicalRoot, "MRD")
  if ($boundary -ine $DefaultManagedBoundary) { Fail "relay_uninstall_deploy_lock_path_invalid" }
  return [IO.Path]::Combine($boundary, $DeploymentLockName)
}

function Initialize-DeploymentLockFileIfMissing {
  param([Parameter(Mandatory = $true)][string]$Path)
  if (-not [IO.File]::Exists($Path)) {
    $temporary = $Path + "." + [Guid]::NewGuid().ToString("N") + ".pending"
    [IO.File]::WriteAllText($temporary, $DeploymentLockContent,
      (New-Object Text.UTF8Encoding($false)))
    Set-SystemAdminFileAcl $temporary
    try {
      [IO.File]::Move($temporary, $Path)
    } catch [IO.IOException] {
      if (-not [IO.File]::Exists($Path)) { Fail "relay_uninstall_deploy_lock_initialization_failed" }
    } finally {
      if ([IO.File]::Exists($temporary)) {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
      }
    }
  }
}

function Assert-DeploymentLockFile {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][IO.FileStream]$Stream
  )
  Assert-ExactSystemAdminFileAcl $Path
  if ($Stream.Length -gt 4096) { Fail "relay_uninstall_deploy_lock_schema_invalid" }
  $bytes = New-Object byte[] ([int]$Stream.Length)
  $Stream.Position = 0
  $offset = 0
  while ($offset -lt $bytes.Length) {
    $read = $Stream.Read($bytes, $offset, $bytes.Length - $offset)
    if ($read -le 0) { Fail "relay_uninstall_deploy_lock_schema_invalid" }
    $offset += $read
  }
  try { $raw = (New-Object Text.UTF8Encoding($false, $true)).GetString($bytes) } catch {
    Fail "relay_uninstall_deploy_lock_schema_invalid"
  } finally {
    if ($bytes.Length -gt 0) { [Array]::Clear($bytes, 0, $bytes.Length) }
  }
  if ($raw -cne $DeploymentLockContent) {
    Fail "relay_uninstall_deploy_lock_schema_invalid"
  }
}

function Enter-DeploymentLock {
  $path = Get-DeploymentLockPath
  $parent = [IO.Path]::GetDirectoryName($path)
  Assert-ExactSystemAdminBoundaryAcl $parent
  Initialize-DeploymentLockFileIfMissing $path
  $item = Get-Item -LiteralPath $path -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail "relay_uninstall_deploy_lock_reparse_rejected"
  }
  $deploymentLock = Open-ExclusiveFileLock $path "relay_uninstall_deploy_lock_busy"
  try {
    Assert-DeploymentLockFile $path $deploymentLock
    return $deploymentLock
  } catch {
    $deploymentLock.Dispose()
    throw
  }
}

function Assert-UninstallWalAcl {
  param([Parameter(Mandatory = $true)][string]$Path)
  $item = Get-Item -LiteralPath $Path -Force
  $acl = Get-Acl -LiteralPath $Path
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
      $item.Length -le 0 -or $item.Length -gt 131072 -or -not $acl.AreAccessRulesProtected -or
      $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne "S-1-5-32-544") {
    Fail "relay_uninstall_wal_acl_invalid"
  }
  $allowed = @("S-1-5-18", "S-1-5-32-544")
  $seen = @{}
  foreach ($entry in $acl.Access) {
    $sid = $entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    if ($entry.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $entry.IsInherited -or $allowed -notcontains $sid -or $seen.ContainsKey($sid) -or
        $entry.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
        $entry.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
        $entry.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
      Fail "relay_uninstall_wal_acl_invalid"
    }
    $seen[$sid] = $true
  }
  if ($seen.Count -ne 2) { Fail "relay_uninstall_wal_acl_invalid" }
}

function Write-UninstallWal {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)]$State
  )
  $encoded = ($State | ConvertTo-Json -Depth 12 -Compress) + "`n"
  if ([Text.Encoding]::UTF8.GetByteCount($encoded) -gt 131072) {
    Fail "relay_uninstall_wal_too_large"
  }
  $temporary = $Path + "." + [Guid]::NewGuid().ToString("N") + ".pending"
  [IO.File]::WriteAllText($temporary, $encoded, (New-Object Text.UTF8Encoding($false)))
  $null = & icacls.exe $temporary "/setowner" "BUILTIN\Administrators"
  if ($LASTEXITCODE -ne 0) { Fail "relay_uninstall_wal_owner_failed" }
  $null = & icacls.exe $temporary "/inheritance:r" "/grant:r" `
    "SYSTEM:(F)" "BUILTIN\Administrators:(F)"
  if ($LASTEXITCODE -ne 0) { Fail "relay_uninstall_wal_acl_failed" }
  Assert-UninstallWalAcl $temporary
  if ([IO.File]::Exists($Path)) {
    [IO.File]::Replace($temporary, $Path, $null, $true)
  } else {
    [IO.File]::Move($temporary, $Path)
  }
  Assert-UninstallWalAcl $Path
}

function Assert-ExactJsonKeys {
  param(
    [Parameter(Mandatory = $true)]$Value,
    [Parameter(Mandatory = $true)][string[]]$Expected
  )
  $actual = @($Value.PSObject.Properties.Name | Sort-Object)
  if (($actual -join "`n") -cne (($Expected | Sort-Object) -join "`n")) {
    Fail "relay_uninstall_wal_schema_invalid"
  }
}

function Test-UninstallWalPhase {
  param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Phase)
  return $Phase -in @(
    "pre-mutation-checkpoint", "drain-fenced", "target-stopped", "firewall-removed",
    "program-archived", "data-archived", "archived", "rollback-complete"
  ) -or $Phase -match '^scm-delete:(mrd-relay-agent|mrd-relay-coturn-control|mrd-coturn-native)$'
}

function Read-And-ValidateUninstallWal {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$ExpectedRecoveryRoot,
    [Parameter(Mandatory = $true)][string]$ExpectedInstallRoot,
    [Parameter(Mandatory = $true)][string]$ExpectedDataRoot
  )
  Assert-UninstallWalAcl $Path
  $raw = Get-Content -LiteralPath $Path -Raw
  if ([Text.Encoding]::UTF8.GetByteCount($raw) -gt 131072) { Fail "relay_uninstall_wal_schema_invalid" }
  try { $wal = $raw | ConvertFrom-Json } catch { Fail "relay_uninstall_wal_schema_invalid" }
  Assert-ExactJsonKeys $wal @(
    "schema_version", "phase", "archived_at_utc", "target", "install_root", "data_root",
    "archive_directory", "install_root_existed", "data_root_existed", "service_states",
    "firewall_rules", "deleted_services", "moved_roots", "drain_fence", "control_pipe",
    "docker_container_preserved_stopped", "wsl_distribution_preserved", "recovery"
  )
  $archiveDirectory = Get-SafeFullPath ([IO.Path]::GetDirectoryName($Path)) -MustExist
  $archiveParent = Get-SafeFullPath ([IO.Path]::GetDirectoryName($archiveDirectory)) -MustExist
  if ($wal.schema_version -ne 1 -or [string]$wal.archive_directory -ine $archiveDirectory -or
      $archiveParent -ine $ExpectedRecoveryRoot -or
      [IO.Path]::GetFileName($archiveDirectory) -notmatch '^uninstall-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}$' -or
      [string]$wal.install_root -ine $ExpectedInstallRoot -or
      [string]$wal.data_root -ine $ExpectedDataRoot -or
      [string]$wal.target -notin @("Native", "Docker", "Wsl2") -or
      [string]$wal.control_pipe -cne $ControlPipeName -or
      $wal.install_root_existed -isnot [bool] -or $wal.data_root_existed -isnot [bool]) {
    Fail "relay_uninstall_wal_path_binding_invalid"
  }
  if (-not (Test-UninstallWalPhase ([string]$wal.phase))) { Fail "relay_uninstall_wal_schema_invalid" }
  Assert-ExactJsonKeys $wal.drain_fence @("target", "generation", "applied_secret_version")
  $expectedDrainTarget = switch ([string]$wal.target) {
    "Native" { "windows-service" }; "Docker" { "docker" }; "Wsl2" { "wsl2" }
  }
  if ([string]$wal.drain_fence.target -cne $expectedDrainTarget -or
      [int64]$wal.drain_fence.generation -le 0 -or
      [int64]$wal.drain_fence.applied_secret_version -le 0) {
    Fail "relay_uninstall_wal_schema_invalid"
  }
  $serviceNames = @($AgentServiceName, $BrokerServiceName, $NativeCoturnServiceName)
  Assert-ExactJsonKeys $wal.service_states $serviceNames
  foreach ($name in $serviceNames) {
    $state = Get-ServiceStateEntry $wal.service_states $name
    Assert-ExactJsonKeys $state @("existed", "was_running", "snapshot")
    if ($state.existed -isnot [bool] -or $state.was_running -isnot [bool]) {
      Fail "relay_uninstall_wal_schema_invalid"
    }
    if ([bool]$state.existed) {
      if ($null -eq $state.snapshot) { Fail "relay_uninstall_wal_schema_invalid" }
      Assert-ExactJsonKeys $state.snapshot @(
        "schema_version", "service_name", "binary_path", "start", "account", "dependencies",
        "sid_type", "failure_flag", "failure_reset_seconds", "failure_command",
        "failure_reboot_message", "failure_actions"
      )
      if ([string]$state.snapshot.service_name -cne $name) { Fail "relay_uninstall_wal_schema_invalid" }
      if (@($state.snapshot.failure_actions).Count -lt 1 -or @($state.snapshot.failure_actions).Count -gt 3) {
        Fail "relay_uninstall_wal_schema_invalid"
      }
      foreach ($action in @($state.snapshot.failure_actions)) {
        Assert-ExactJsonKeys $action @("action", "delay_ms")
        if ([string]$action.action -notin @("restart", "run", "reboot", "none") -or
            [int64]$action.delay_ms -lt 0) { Fail "relay_uninstall_wal_schema_invalid" }
      }
    } elseif ($null -ne $state.snapshot -or [bool]$state.was_running) {
      Fail "relay_uninstall_wal_schema_invalid"
    }
  }
  $deleted = @($wal.deleted_services)
  if ($deleted.Count -ne @($deleted | Select-Object -Unique).Count -or
      @($deleted | Where-Object { $_ -notin $serviceNames }).Count -ne 0) {
    Fail "relay_uninstall_wal_schema_invalid"
  }
  $moved = @($wal.moved_roots)
  if ($moved.Count -ne @($moved | Select-Object -Unique).Count -or
      @($moved | Where-Object { $_ -notin @("program", "data") }).Count -ne 0) {
    Fail "relay_uninstall_wal_schema_invalid"
  }
  if (@($wal.firewall_rules).Count -gt 32) { Fail "relay_uninstall_wal_schema_invalid" }
  $firewallNames = New-Object Collections.ArrayList
  foreach ($rule in @($wal.firewall_rules)) {
    Assert-ExactJsonKeys $rule @("display_name", "enabled", "direction", "action", "profile", "protocol", "local_port")
    if ([string]$rule.display_name -notin $FirewallRuleNames -or
        $firewallNames -contains [string]$rule.display_name) { Fail "relay_uninstall_wal_schema_invalid" }
    [void]$firewallNames.Add([string]$rule.display_name)
  }
  return $wal
}

function Find-IncompleteUninstallWal {
  param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$ExpectedInstallRoot,
    [Parameter(Mandatory = $true)][string]$ExpectedDataRoot
  )
  $found = New-Object Collections.ArrayList
  foreach ($directory in @(Get-ChildItem -LiteralPath $Root -Directory -Force)) {
    if ($directory.Name -notmatch '^uninstall-') { continue }
    if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      Fail "relay_uninstall_wal_reparse_rejected"
    }
    Assert-ExactSystemAdminBoundaryAcl $directory.FullName
    $path = [IO.Path]::Combine($directory.FullName, "RECOVERY.json")
    if (-not [IO.File]::Exists($path)) { Fail "relay_uninstall_wal_missing" }
    $wal = Read-And-ValidateUninstallWal $path $Root $ExpectedInstallRoot $ExpectedDataRoot
    if ([string]$wal.phase -notin @("archived", "rollback-complete")) {
      [void]$found.Add([pscustomobject]@{ Wal = $wal; Path = $path; ArchiveDirectory = $directory.FullName })
    }
  }
  if ($found.Count -gt 1) { Fail "relay_uninstall_multiple_incomplete_wal" }
  if ($found.Count -eq 1) { return $found[0] }
  return $null
}

function Restore-FirewallRules {
  param([Parameter(Mandatory = $true)]$Rules)
  foreach ($ruleName in $FirewallRuleNames) {
    foreach ($rule in @(Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
      Remove-NetFirewallRule -InputObject $rule
    }
  }
  foreach ($rule in @($Rules)) {
    $parameters = @{
      DisplayName = [string]$rule.display_name
      Enabled = [string]$rule.enabled
      Direction = [string]$rule.direction
      Action = [string]$rule.action
      Profile = [string]$rule.profile
      Protocol = [string]$rule.protocol
      LocalPort = [string]$rule.local_port
    }
    $null = New-NetFirewallRule @parameters
  }
}

function Restore-UninstallCheckpoint {
  param(
    [Parameter(Mandatory = $true)]$Wal,
    [Parameter(Mandatory = $true)][string]$WalPath,
    [Parameter(Mandatory = $true)][string]$ArchiveDirectory,
    [Parameter(Mandatory = $true)][string]$ProgramRoot,
    [Parameter(Mandatory = $true)][string]$RelayDataRoot
  )
  Stop-ExactService $AgentServiceName
  Stop-ExactService $BrokerServiceName
  Stop-ExactService $NativeCoturnServiceName

  foreach ($root in @(
      @("program", $ProgramRoot, [bool]$Wal.install_root_existed),
      @("data", $RelayDataRoot, [bool]$Wal.data_root_existed)
    )) {
    $archived = [IO.Path]::Combine($ArchiveDirectory, [string]$root[0])
    if ([IO.Directory]::Exists($archived)) {
      if ([IO.Directory]::Exists([string]$root[1])) { Fail "relay_uninstall_rollback_root_collision" }
      Move-Item -LiteralPath $archived -Destination ([string]$root[1])
    } elseif ([bool]$root[2] -and -not [IO.Directory]::Exists([string]$root[1])) {
      Fail "relay_uninstall_rollback_root_missing"
    }
  }

  Restore-FirewallRules $Wal.firewall_rules
  foreach ($name in @($NativeCoturnServiceName, $BrokerServiceName, $AgentServiceName)) {
    $state = Get-ServiceStateEntry $Wal.service_states $name
    if ([bool]$state.existed) {
      if ($null -eq $state.snapshot) { Fail "relay_uninstall_scm_snapshot_incomplete" }
      Restore-ExactScmSnapshot $state.snapshot
    } else {
      Remove-ExactScmRegistration $name
      if (Test-ServiceExists $name) { Fail "relay_uninstall_service_absence_readback_failed" }
    }
  }
  foreach ($name in @($NativeCoturnServiceName, $BrokerServiceName, $AgentServiceName)) {
    $state = Get-ServiceStateEntry $Wal.service_states $name
    if ([bool]$state.was_running) {
      $null = Invoke-Sc @("start", $name)
      Wait-ServiceRunning $name
    } elseif (Test-ServiceRunning $name) {
      Fail "relay_uninstall_scm_stopped_state_restore_failed"
    }
  }
  $Wal.phase = "rollback-complete"
  Write-UninstallWal $WalPath $Wal
}

function Assert-RecoveryRootPolicySelfTest {
  $defaultRecovery = [IO.Path]::Combine($DefaultManagedBoundary, "RelayAgentRecovery")
  if (Test-RecoveryRootDisposition "C:\Windows" $DefaultManagedBoundary $true $true $true $true) {
    Fail "relay_uninstall_recovery_self_test_windows_accepted"
  }
  if (Test-RecoveryRootDisposition $env:ProgramFiles $DefaultManagedBoundary $true $true $true $true) {
    Fail "relay_uninstall_recovery_self_test_business_directory_accepted"
  }
  if (-not (Test-RecoveryRootDisposition $defaultRecovery $DefaultManagedBoundary $false $true $false $false)) {
    Fail "relay_uninstall_recovery_self_test_new_root_rejected"
  }
  if (-not (Test-RecoveryRootDisposition $defaultRecovery $DefaultManagedBoundary $true $true $true $true)) {
    Fail "relay_uninstall_recovery_self_test_existing_root_rejected"
  }
  if (Test-RecoveryRootDisposition $defaultRecovery $DefaultManagedBoundary $true $true $true $false) {
    Fail "relay_uninstall_recovery_self_test_forged_marker_accepted"
  }
  $overlapRejected = $false
  try { Assert-DisjointManagedRoots @("C:\MRD", "C:\MRD\data", "D:\recovery") } catch { $overlapRejected = $true }
  if (-not $overlapRejected) { Fail "relay_uninstall_recovery_self_test_nested_roots_accepted" }
}

function Test-ExactDockerProductionSpec {
  param($Container, $ExpectedMounts, [int]$ExpectedTlsPort)
  try {
    $labels = @($Container.Config.Labels.PSObject.Properties)
    if ($Container.Path -cne $DockerExpectedPath -or @($Container.Args).Count -ne 2 -or
        [string]$Container.Args[0] -cne $DockerExpectedArgs[0] -or
        [string]$Container.Args[1] -cne $DockerExpectedArgs[1] -or
        [string]$Container.Config.User -cne "65534:65534" -or
        $Container.HostConfig.Privileged -ne $false -or @($Container.HostConfig.CapAdd).Count -ne 0 -or
        @($Container.HostConfig.CapDrop).Count -ne 1 -or [string]$Container.HostConfig.CapDrop[0] -cne "ALL" -or
        $Container.HostConfig.NetworkMode -cne $DockerExpectedNetworkMode -or
        [string]$Container.HostConfig.PidMode -cne "" -or
        [string]$Container.HostConfig.IpcMode -cne "private" -or
        [string]$Container.HostConfig.UsernsMode -cne "" -or
        ($null -ne $Container.HostConfig.Devices -and @($Container.HostConfig.Devices).Count -ne 0) -or
        $Container.HostConfig.PublishAllPorts -ne $false -or
        @($Container.HostConfig.SecurityOpt).Count -ne 1 -or
        [string]$Container.HostConfig.SecurityOpt[0] -cne $DockerExpectedSecurityOpt -or
        $Container.HostConfig.ReadonlyRootfs -ne $true -or $Container.HostConfig.RestartPolicy.Name -cne "no" -or
        $labels.Count -ne 1 -or $labels[0].Name -cne "io.mrd.relay.managed" -or
        [string]$labels[0].Value -cne "true" -or @($Container.Mounts).Count -ne @($ExpectedMounts).Count) {
      return $false
    }
    foreach ($expectedMount in @($ExpectedMounts)) {
      if (@($Container.Mounts | Where-Object {
            $_.Type -ceq "bind" -and [string]$_.Source -ieq [string]$expectedMount.source -and
            $_.Destination -ceq [string]$expectedMount.destination -and $_.RW -eq $false
          }).Count -ne 1) { return $false }
    }
    $expectedPorts = @{}
    foreach ($tuple in @(
        @("3478/udp", "", "3478"), @("3478/tcp", "", "3478"),
        @("$ExpectedTlsPort/tcp", "", "$ExpectedTlsPort"), @("9641/tcp", "127.0.0.1", "9641")
      )) { $expectedPorts[$tuple[0]] = @($tuple[1], $tuple[2]) }
    foreach ($protocol in @("tcp", "udp")) {
      foreach ($port in 49160..49260) { $expectedPorts["$port/$protocol"] = @("", "$port") }
    }
    $actualPorts = @($Container.HostConfig.PortBindings.PSObject.Properties)
    if ($actualPorts.Count -ne $expectedPorts.Count) { return $false }
    foreach ($property in $actualPorts) {
      if (-not $expectedPorts.ContainsKey($property.Name) -or @($property.Value).Count -ne 1 -or
          [string]$property.Value[0].HostIp -cne $expectedPorts[$property.Name][0] -or
          [string]$property.Value[0].HostPort -cne $expectedPorts[$property.Name][1]) { return $false }
    }
    return $true
  } catch { return $false }
}

function New-DockerProductionSpecFixture {
  param($ExpectedMounts, [int]$TlsPort = 5349)
  $bindings = [ordered]@{}
  foreach ($tuple in @(
      @("3478/udp", "", "3478"), @("3478/tcp", "", "3478"),
      @("$TlsPort/tcp", "", "$TlsPort"), @("9641/tcp", "127.0.0.1", "9641")
    )) { $bindings[$tuple[0]] = @([pscustomobject]@{ HostIp = $tuple[1]; HostPort = $tuple[2] }) }
  foreach ($protocol in @("tcp", "udp")) {
    foreach ($port in 49160..49260) {
      $bindings["$port/$protocol"] = @([pscustomobject]@{ HostIp = ""; HostPort = "$port" })
    }
  }
  return [pscustomobject]@{
    Path = $DockerExpectedPath; Args = @($DockerExpectedArgs)
    Config = [pscustomobject]@{
      User = "65534:65534"
      Labels = [pscustomobject]@{ 'io.mrd.relay.managed' = "true" }
    }
    HostConfig = [pscustomobject]@{
      Privileged = $false; CapAdd = @(); CapDrop = @("ALL"); NetworkMode = $DockerExpectedNetworkMode
      PidMode = ""; IpcMode = "private"; UsernsMode = ""; Devices = @(); PublishAllPorts = $false
      SecurityOpt = @($DockerExpectedSecurityOpt); ReadonlyRootfs = $true
      RestartPolicy = [pscustomobject]@{ Name = "no" }; PortBindings = [pscustomobject]$bindings
    }
    Mounts = @($ExpectedMounts | ForEach-Object {
        [pscustomobject]@{ Type = "bind"; Source = $_.source; Destination = $_.destination; RW = $false }
      })
  }
}

function Assert-DockerProductionSpecSelfTest {
  $mounts = @(
    [pscustomobject]@{ source = "C:\MRD\docker-envelope"; destination = "/run/mrd/turnserver.conf" },
    [pscustomobject]@{ source = "C:\MRD\tls"; destination = "/run/mrd/tls" }
  )
  $good = New-DockerProductionSpecFixture $mounts
  if (-not (Test-ExactDockerProductionSpec $good $mounts 5349)) { Fail "relay_uninstall_docker_spec_self_test_good_rejected" }
  $commandOverride = New-DockerProductionSpecFixture $mounts
  $commandOverride.Path = "/bin/sh"
  if (Test-ExactDockerProductionSpec $commandOverride $mounts 5349) {
    Fail "relay_uninstall_docker_spec_self_test_command_override_accepted"
  }
  $extraCapability = New-DockerProductionSpecFixture $mounts
  $extraCapability.HostConfig.CapDrop = @("ALL", "NET_RAW")
  if (Test-ExactDockerProductionSpec $extraCapability $mounts 5349) {
    Fail "relay_uninstall_docker_spec_self_test_extra_capability_accepted"
  }
  $rootUser = New-DockerProductionSpecFixture $mounts
  $rootUser.Config.User = ""
  if (Test-ExactDockerProductionSpec $rootUser $mounts 5349) {
    Fail "relay_uninstall_docker_spec_self_test_root_user_accepted"
  }
  $hostPid = New-DockerProductionSpecFixture $mounts
  $hostPid.HostConfig.PidMode = "host"
  if (Test-ExactDockerProductionSpec $hostPid $mounts 5349) {
    Fail "relay_uninstall_docker_spec_self_test_host_pid_accepted"
  }
  $device = New-DockerProductionSpecFixture $mounts
  $device.HostConfig.Devices = @([pscustomobject]@{ PathOnHost = "C:\\device" })
  if (Test-ExactDockerProductionSpec $device $mounts 5349) {
    Fail "relay_uninstall_docker_spec_self_test_device_accepted"
  }
  $nullDevices = New-DockerProductionSpecFixture $mounts
  $nullDevices.HostConfig.Devices = $null
  if (-not (Test-ExactDockerProductionSpec $nullDevices $mounts 5349)) {
    Fail "relay_uninstall_docker_spec_self_test_null_devices_rejected"
  }
  foreach ($unsafeRoot in @("C:\MRD,Relay", "C:\MRD=Relay")) {
    $rejected = $false
    try { Assert-DockerMountSafeDataRoot $unsafeRoot } catch { $rejected = $true }
    if (-not $rejected) { Fail "relay_uninstall_docker_mount_root_self_test_unsafe_accepted" }
  }
  if (-not (Test-RunningWslDistribution @("Ubuntu", "MRDRelay") "MRDRelay")) {
    Fail "relay_uninstall_wsl_running_self_test_missed"
  }
  if (Test-RunningWslDistribution @("Ubuntu", "MRDRelay-old") "MRDRelay") {
    Fail "relay_uninstall_wsl_running_self_test_false_match"
  }
}

function Assert-BrokerProtectedFileAcl {
  param([Parameter(Mandatory = $true)][string]$Path)
  $acl = Get-Acl -LiteralPath $Path
  if (-not $acl.AreAccessRulesProtected) { Fail "relay_uninstall_drain_marker_acl_invalid" }
  $allowed = @("S-1-5-18", "S-1-5-32-544")
  $brokerAccount = New-Object Security.Principal.NTAccount("NT SERVICE\$BrokerServiceName")
  $brokerSid = $brokerAccount.Translate([Security.Principal.SecurityIdentifier]).Value
  $allowed += $brokerSid
  $seen = @{}
  foreach ($entry in $acl.Access) {
    if ($entry.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $entry.IsInherited -or
        $entry.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
        $entry.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or
        $entry.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) {
      Fail "relay_uninstall_drain_marker_acl_invalid"
    }
    $sid = $entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    if ($allowed -notcontains $sid) { Fail "relay_uninstall_drain_marker_acl_invalid" }
    if ($seen.ContainsKey($sid)) { Fail "relay_uninstall_drain_marker_acl_invalid" }
    $seen[$sid] = $true
  }
  if ($seen.Count -ne 3) { Fail "relay_uninstall_drain_marker_acl_invalid" }
  foreach ($sid in $allowed) {
    if (-not $seen.ContainsKey($sid)) { Fail "relay_uninstall_drain_marker_acl_missing" }
  }
  $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if ($ownerSid -notin @("S-1-5-18", "S-1-5-32-544")) {
    Fail "relay_uninstall_drain_marker_owner_invalid"
  }
}

function Get-ChallengeHash {
  param([Parameter(Mandatory = $true)][string]$Challenge)
  $bytes = New-Object byte[] 32
  for ($index = 0; $index -lt 32; $index++) {
    $bytes[$index] = [Convert]::ToByte($Challenge.Substring($index * 2, 2), 16)
  }
  $sha = [Security.Cryptography.SHA256]::Create()
  try {
    return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
  } finally {
    $sha.Dispose()
    [Array]::Clear($bytes, 0, $bytes.Length)
  }
}

function Get-CompletedDrainProof {
  param([Parameter(Mandatory = $true)][string]$SelectedTarget)
  $agent = Get-SafeFullPath ([IO.Path]::Combine($InstallRoot, "mrd-relay-agent.exe"))
  $config = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, "config", "agent.json"))
  if (-not [IO.File]::Exists($agent) -or -not [IO.File]::Exists($config)) {
    Fail "relay_uninstall_drain_proof_binary_or_config_missing"
  }
  if ((Get-FileHash -LiteralPath $agent -Algorithm SHA256).Hash -ine [string]$manifest.agent_sha256) {
    Fail "relay_uninstall_agent_hash_mismatch"
  }
  $signature = Get-AuthenticodeSignature -LiteralPath $agent
  if ($signature.Status -ne "Valid") { Fail "relay_uninstall_agent_signature_invalid" }
  $random = New-Object byte[] 32
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($random) } finally { $rng.Dispose() }
  $challenge = (($random | ForEach-Object { $_.ToString("x2") }) -join "")
  [Array]::Clear($random, 0, $random.Length)
  $lines = @(& $agent drain-proof --config $config --challenge $challenge 2>$null)
  if ($LASTEXITCODE -ne 0 -or $lines.Count -ne 1 -or
      [Text.Encoding]::UTF8.GetByteCount([string]$lines[0]) -gt 8192) {
    Fail "relay_uninstall_requires_completed_drain"
  }
  $json = [string]$lines[0]
  try { $proof = $json | ConvertFrom-Json } catch { Fail "relay_uninstall_drain_proof_json_invalid" }
  $expectedKeys = @(
    "schema_version", "scope", "target", "generation", "applied_secret_version",
    "draining", "active_allocations", "drain_completed", "challenge_sha256", "proof_sha256"
  )
  $actualKeys = @($proof.PSObject.Properties.Name | Sort-Object)
  if (($actualKeys -join "`n") -cne (($expectedKeys | Sort-Object) -join "`n") -or
      [regex]::Matches($json, '"[A-Za-z0-9_]+"\s*:').Count -ne $expectedKeys.Count) {
    Fail "relay_uninstall_drain_proof_schema_invalid"
  }
  $expectedTarget = switch ($SelectedTarget) {
    "Native" { "windows-service" }
    "Docker" { "docker" }
    "Wsl2" { "wsl2" }
    default { Fail "relay_uninstall_target_invalid" }
  }
  if ($proof.schema_version -ne 1 -or $proof.scope -cne "local" -or
      $proof.target -cne $expectedTarget -or [int64]$proof.generation -le 0 -or
      [int64]$proof.applied_secret_version -le 0 -or $proof.draining -ne $true -or
      [int64]$proof.active_allocations -ne 0 -or $proof.drain_completed -ne $true -or
      $proof.challenge_sha256 -cne (Get-ChallengeHash $challenge) -or
      [string]$proof.proof_sha256 -notmatch '^[0-9a-f]{64}$') {
    Fail "relay_uninstall_drain_proof_invalid"
  }
  return $proof
}

function Assert-SameDrainFence {
  param(
    [Parameter(Mandatory = $true)]$FirstProof,
    [Parameter(Mandatory = $true)]$SecondProof
  )
  if ($FirstProof.target -cne $SecondProof.target -or
      [int64]$FirstProof.generation -ne [int64]$SecondProof.generation -or
      [int64]$FirstProof.applied_secret_version -ne [int64]$SecondProof.applied_secret_version -or
      $SecondProof.draining -ne $true -or $SecondProof.drain_completed -ne $true -or
      [int64]$SecondProof.active_allocations -ne 0) {
    Fail "relay_uninstall_drain_fence_changed"
  }
}

function Assert-TargetQuiescent {
  param([Parameter(Mandatory = $true)][string]$SelectedTarget)
  switch ($SelectedTarget) {
    "Native" {
      if (Test-ServiceExists $NativeCoturnServiceName) {
        $query = @(& sc.exe query $NativeCoturnServiceName 2>&1)
        if (($query -join "`n") -notmatch 'STATE\s*:\s*1\s+STOPPED') {
          Fail "relay_uninstall_requires_completed_drain"
        }
      }
    }
    "Docker" {
      $DockerExecutable = Get-SafeFullPath $script:DockerExecutable
      if (-not [IO.File]::Exists($DockerExecutable)) { Fail "relay_uninstall_docker_unavailable" }
      if ((Get-FileHash -LiteralPath $DockerExecutable -Algorithm SHA256).Hash -ine
          [string]$manifest.target_manager_sha256 -or
          (Get-AuthenticodeSignature -LiteralPath $DockerExecutable).Status -ne "Valid") {
        Fail "relay_uninstall_docker_binary_identity_invalid"
      }
      $targetPath = [IO.Path]::Combine($DataRoot, "broker", "target.json")
      $identityPath = [IO.Path]::Combine($DataRoot, "broker", "docker-identity.json")
      if (-not [IO.File]::Exists($targetPath) -or -not [IO.File]::Exists($identityPath)) {
        Fail "relay_uninstall_docker_identity_missing"
      }
      Assert-BrokerProtectedFileAcl $targetPath
      Assert-BrokerProtectedFileAcl $identityPath
      $targetConfig = Get-Content -LiteralPath $targetPath -Raw | ConvertFrom-Json
      $identity = Get-Content -LiteralPath $identityPath -Raw | ConvertFrom-Json
      if ($targetConfig.target -cne "Docker" -or
          $targetConfig.expected_container_id_state_path -cne $identityPath -or
          $identity.schema_version -ne 1 -or $identity.target -cne "docker" -or
          [int64]$identity.generation -le 0 -or
          [string]$identity.container_id -notmatch '^[0-9a-f]{64}$' -or
          [string]$identity.image_id -notmatch '^sha256:[0-9a-f]{64}$' -or
          $identity.image_reference -cne $targetConfig.image) {
        Fail "relay_uninstall_docker_identity_invalid"
      }
      $inspectResult = Invoke-BoundedNativeProcess $DockerExecutable `
        @("inspect", [string]$identity.container_id) 30000 65536 8192 `
        "relay_uninstall_docker_inspect" "Utf8"
      if ($inspectResult.ExitCode -ne 0) { Fail "relay_uninstall_docker_bound_container_missing" }
      try { $containers = @($inspectResult.Stdout | ConvertFrom-Json) } catch {
        Fail "relay_uninstall_docker_bound_container_missing"
      }
      if ($containers.Count -ne 1) { Fail "relay_uninstall_docker_container_ambiguous" }
      $container = $containers[0]
      if ($container.Id -cne $identity.container_id -or
          $container.Image -cne $identity.image_id -or
          $container.Config.Image -cne $identity.image_reference -or
          $container.Name -cne "/$DockerContainerName" -or
          $container.Config.Labels.'io.mrd.relay.managed' -cne "true") {
        Fail "relay_uninstall_docker_ownership_invalid"
      }
      if ($container.HostConfig.RestartPolicy.Name -cne "no") {
        Fail "relay_uninstall_docker_restart_policy_invalid"
      }
      if (-not (Test-ExactDockerProductionSpec $container $targetConfig.bind_mounts ([int]$targetConfig.tls_port))) {
        Fail "relay_uninstall_docker_production_spec_invalid"
      }
    }
    "Wsl2" {
      $targetPath = [IO.Path]::Combine($DataRoot, "broker", "target.json")
      if (-not [IO.File]::Exists($targetPath)) { Fail "relay_uninstall_wsl_target_missing" }
      Assert-BrokerProtectedFileAcl $targetPath
      $targetConfig = Get-Content -LiteralPath $targetPath -Raw | ConvertFrom-Json
      if ($targetConfig.target -cne "Wsl2" -or
          $targetConfig.distribution -cne $WslDistributionName -or
          $targetConfig.owner -cne "LocalSystem" -or
          $targetConfig.networking_mode -cne "mirrored") {
        Fail "relay_uninstall_wsl_target_invalid"
      }
    }
    default { Fail "relay_uninstall_target_invalid" }
  }
}

function Stop-VerifiedWslDistribution {
  param(
    [Parameter(Mandatory = $true)]$TargetConfiguration,
    [Parameter(Mandatory = $true)]$InstallManifest
  )
  Assert-WslLocalSystemContext "Wsl2"
  $wslPath = Get-SafeFullPath ([string]$TargetConfiguration.wsl_executable) -MustExist -Leaf
  if ((Get-FileHash -LiteralPath $wslPath -Algorithm SHA256).Hash -ine
      [string]$InstallManifest.target_manager_sha256 -or
      (Get-AuthenticodeSignature -LiteralPath $wslPath).Status -ne "Valid") {
    Fail "relay_uninstall_wsl_binary_identity_invalid"
  }
  $terminateResult = Invoke-BoundedNativeProcess $wslPath `
    @("--terminate", $WslDistributionName) 30000 8192 8192 `
    "relay_uninstall_wsl_terminate" "Utf16Le"
  if ($terminateResult.ExitCode -ne 0) {
    Fail "relay_uninstall_wsl_terminate_failed"
  }
  $runningResult = Invoke-BoundedNativeProcess $wslPath `
    @("--list", "--running", "--quiet") 10000 8192 8192 `
    "relay_uninstall_wsl_running_query" "Utf16Le"
  if ($runningResult.ExitCode -ne 0) {
    Fail "relay_uninstall_wsl_running_query_failed"
  }
  if (Test-RunningWslDistribution @([regex]::Split($runningResult.Stdout, '\r?\n')) $WslDistributionName) {
    Fail "relay_uninstall_wsl_still_running"
  }
}

function Stop-CurrentTargetForUninstall {
  param([Parameter(Mandatory = $true)][ValidateSet("Native", "Docker", "Wsl2")][string]$SelectedTarget)
  switch ($SelectedTarget) {
    "Native" {
      Stop-ExactService $NativeCoturnServiceName
      if (Test-ServiceRunning $NativeCoturnServiceName) {
        Fail "relay_uninstall_target_stop_readback_failed"
      }
    }
    "Docker" {
      Assert-TargetQuiescent "Docker"
      $targetPath = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, "broker", "target.json")) -MustExist -Leaf
      $identityPath = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, "broker", "docker-identity.json")) -MustExist -Leaf
      $targetConfig = Get-Content -LiteralPath $targetPath -Raw | ConvertFrom-Json
      $identity = Get-Content -LiteralPath $identityPath -Raw | ConvertFrom-Json
      $dockerPath = Get-SafeFullPath ([string]$targetConfig.docker_executable) -MustExist -Leaf
      if ($dockerPath -ine (Get-SafeFullPath $script:DockerExecutable -MustExist -Leaf) -or
          (Get-FileHash -LiteralPath $dockerPath -Algorithm SHA256).Hash -ine [string]$manifest.target_manager_sha256 -or
          (Get-AuthenticodeSignature -LiteralPath $dockerPath).Status -ne "Valid") {
        Fail "relay_uninstall_docker_binary_identity_invalid"
      }
      $beforeResult = Invoke-BoundedNativeProcess $dockerPath `
        @("inspect", [string]$identity.container_id) 30000 65536 8192 `
        "relay_uninstall_docker_inspect" "Utf8"
      if ($beforeResult.ExitCode -ne 0) {
        Fail "relay_uninstall_docker_bound_container_missing"
      }
      try { $before = @($beforeResult.Stdout | ConvertFrom-Json) } catch {
        Fail "relay_uninstall_docker_bound_container_missing"
      }
      if ($before.Count -ne 1 -or $before[0].Id -cne [string]$identity.container_id -or
          -not (Test-ExactDockerProductionSpec $before[0] $targetConfig.bind_mounts ([int]$targetConfig.tls_port))) {
        Fail "relay_uninstall_docker_production_spec_invalid"
      }
      if ($before[0].State.Running -eq $true) {
        $stopResult = Invoke-BoundedNativeProcess $dockerPath `
          @("stop", "--time", "30", [string]$identity.container_id) 45000 8192 8192 `
          "relay_uninstall_docker_stop" "Utf8"
        if ($stopResult.ExitCode -ne 0) {
          Fail "relay_uninstall_target_stop_failed"
        }
      }
      $afterResult = Invoke-BoundedNativeProcess $dockerPath `
        @("inspect", [string]$identity.container_id) 30000 65536 8192 `
        "relay_uninstall_docker_inspect" "Utf8"
      if ($afterResult.ExitCode -ne 0) {
        Fail "relay_uninstall_target_stop_readback_failed"
      }
      try { $after = @($afterResult.Stdout | ConvertFrom-Json) } catch {
        Fail "relay_uninstall_target_stop_readback_failed"
      }
      if ($after.Count -ne 1 -or $after[0].Id -cne [string]$identity.container_id -or
          $after[0].State.Running -ne $false -or
          -not (Test-ExactDockerProductionSpec $after[0] $targetConfig.bind_mounts ([int]$targetConfig.tls_port))) {
        Fail "relay_uninstall_target_stop_readback_failed"
      }
    }
    "Wsl2" {
      Assert-TargetQuiescent "Wsl2"
      $targetPath = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, "broker", "target.json")) -MustExist -Leaf
      $targetConfiguration = Get-Content -LiteralPath $targetPath -Raw | ConvertFrom-Json
      Stop-VerifiedWslDistribution $targetConfiguration $manifest
    }
  }
}

if ($SelfTest) {
  if ($WhatIfPreference) { Fail "relay_uninstall_self_test_whatif_rejected" }
  Assert-RecoveryRootPolicySelfTest
  Assert-DockerProductionSpecSelfTest
  Assert-UninstallRollbackPlanSelfTest
  Assert-WslExecutionIdentitySelfTest
  Assert-TransactionLockSelfTest
  Assert-BoundedNativeProcessSelfTest
  Write-Output "relay_uninstall_self_test_passed"
  exit 0
}
Assert-Administrator
$InstallRoot = (Get-SafeFullPath $InstallRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
$DataRoot = (Get-SafeFullPath $DataRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
$RecoveryRoot = (Get-SafeFullPath $RecoveryRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
Assert-DisjointManagedRoots @($InstallRoot, $DataRoot, $RecoveryRoot)

$manifestPath = [IO.Path]::Combine($DataRoot, "install-manifest.json")
if (-not $PSCmdlet.ShouldProcess(
    $RecoveryRoot,
    "Acquire exclusive MRD relay uninstall transaction; recover an incomplete WAL or archive the installation")) {
  return
}

$deploymentLock = $null
try {
  $deploymentLock = Enter-DeploymentLock
  $recoveryRootExistedBeforeLock = [IO.Directory]::Exists($RecoveryRoot)
  if (-not $recoveryRootExistedBeforeLock) {
    # An absent recovery root cannot contain a WAL. Resolve the live target
    # under the machine lock before creating that root, so WSL never performs
    # even recovery-directory mutation under a non-LocalSystem token.
    if (-not [IO.File]::Exists($manifestPath)) { Fail "relay_uninstall_manifest_missing" }
    $lockedManifestItem = Get-Item -LiteralPath $manifestPath -Force
    if (($lockedManifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      Fail "relay_uninstall_manifest_reparse_rejected"
    }
    try { $lockedManifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json } catch {
      Fail "relay_uninstall_manifest_invalid"
    }
    $lockedManifestTarget = [string]$lockedManifest.target
    if ($lockedManifestTarget -notin @("Native", "Docker", "Wsl2")) {
      Fail "relay_uninstall_manifest_invalid"
    }
    if ([string]::IsNullOrEmpty($Target)) { $Target = $lockedManifestTarget }
    if ($Target -cne $lockedManifestTarget) { Fail "relay_uninstall_target_mismatch" }
  }
  if (-not [string]::IsNullOrEmpty($Target)) { Assert-WslLocalSystemContext $Target }
  Initialize-OrValidateRecoveryRoot $RecoveryRoot
  $incompleteWal = Find-IncompleteUninstallWal $RecoveryRoot $InstallRoot $DataRoot
  if ($null -ne $incompleteWal) {
    Assert-WslLocalSystemContext ([string]$incompleteWal.Wal.target)
    try {
      Restore-UninstallCheckpoint $incompleteWal.Wal $incompleteWal.Path `
        $incompleteWal.ArchiveDirectory $InstallRoot $DataRoot
    } catch {
      throw "relay_uninstall_scm_rollback_failed"
    }
    Write-Output ("relay_uninstall_incomplete_wal_recovered Recovery=" + $incompleteWal.ArchiveDirectory)
    return
  }

  if (-not [IO.File]::Exists($manifestPath)) { Fail "relay_uninstall_manifest_missing" }
  $manifestItem = Get-Item -LiteralPath $manifestPath -Force
  if (($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail "relay_uninstall_manifest_reparse_rejected"
  }
  try { $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json } catch {
    Fail "relay_uninstall_manifest_invalid"
  }
  if ([string]$manifest.target -notin @("Native", "Docker", "Wsl2")) {
    Fail "relay_uninstall_manifest_invalid"
  }
  if ([string]::IsNullOrEmpty($Target)) { $Target = [string]$manifest.target }
  if ($Target -ne [string]$manifest.target) { Fail "relay_uninstall_target_mismatch" }
  Assert-WslLocalSystemContext $Target
  if ($Target -ceq "Docker") { Assert-DockerMountSafeDataRoot $DataRoot }

  $firstDrainProof = Get-CompletedDrainProof $Target
  Assert-TargetQuiescent $Target

$serviceStates = [ordered]@{}
foreach ($name in @($AgentServiceName, $BrokerServiceName, $NativeCoturnServiceName)) {
  $exists = Test-ServiceExists $name
  $serviceStates[$name] = [ordered]@{
    existed = $exists
    was_running = if ($exists) { Test-ServiceRunning $name } else { $false }
    snapshot = if ($exists) { Get-ExactScmSnapshot $name } else { $null }
  }
}
$previousFirewallRules = New-Object Collections.ArrayList
foreach ($ruleName in $FirewallRuleNames) {
  foreach ($rule in @(Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
    $portFilter = $rule | Get-NetFirewallPortFilter
    [void]$previousFirewallRules.Add([ordered]@{
      display_name = [string]$rule.DisplayName
      enabled = [string]$rule.Enabled
      direction = [string]$rule.Direction
      action = [string]$rule.Action
      profile = [string]$rule.Profile
      protocol = [string]$portFilter.Protocol
      local_port = [string]$portFilter.LocalPort
    })
  }
}

$archiveDirectory = [IO.Path]::Combine(
  $RecoveryRoot,
  "uninstall-" + [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ") + "-" + [Guid]::NewGuid().ToString("N")
)
[void][IO.Directory]::CreateDirectory($archiveDirectory)
Set-SystemAdminDirectoryAcl $archiveDirectory
$recoveryManifestPath = [IO.Path]::Combine($archiveDirectory, "RECOVERY.json")
$utf8NoBom = New-Object Text.UTF8Encoding($false)
$uninstallWal = [ordered]@{
  schema_version = 1
  phase = "pre-mutation-checkpoint"
  archived_at_utc = [DateTime]::UtcNow.ToString("o")
  target = $Target
  install_root = $InstallRoot
  data_root = $DataRoot
  archive_directory = $archiveDirectory
  install_root_existed = [IO.Directory]::Exists($InstallRoot)
  data_root_existed = [IO.Directory]::Exists($DataRoot)
  service_states = $serviceStates
  firewall_rules = @($previousFirewallRules)
  deleted_services = @()
  moved_roots = @()
  drain_fence = [ordered]@{
    target = [string]$firstDrainProof.target
    generation = [int64]$firstDrainProof.generation
    applied_secret_version = [int64]$firstDrainProof.applied_secret_version
  }
  control_pipe = $ControlPipeName
  docker_container_preserved_stopped = ($Target -eq "Docker")
  wsl_distribution_preserved = if ($Target -eq "Wsl2") { $WslDistributionName } else { $null }
  recovery = "Restore only exact archived roots, SCM definitions, and firewall entries; verify before start."
}
Write-UninstallWal $recoveryManifestPath $uninstallWal

try {
  Stop-ExactService $AgentServiceName
  $secondDrainProof = Get-CompletedDrainProof $Target
  Assert-SameDrainFence $firstDrainProof $secondDrainProof
  $uninstallWal.phase = "drain-fenced"
  Write-UninstallWal $recoveryManifestPath $uninstallWal
  Stop-ExactService $BrokerServiceName
  Stop-CurrentTargetForUninstall $Target
  $uninstallWal.phase = "target-stopped"
  Write-UninstallWal $recoveryManifestPath $uninstallWal

  foreach ($name in @($AgentServiceName, $BrokerServiceName, $NativeCoturnServiceName)) {
    Remove-ExactScmRegistration $name
    $uninstallWal.deleted_services = @($uninstallWal.deleted_services) + @($name)
    $uninstallWal.phase = "scm-delete:$name"
    Write-UninstallWal $recoveryManifestPath $uninstallWal
  }

  foreach ($ruleName in $FirewallRuleNames) {
    $rules = @(Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)
    foreach ($rule in $rules) { Remove-NetFirewallRule -InputObject $rule }
    if (@(Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue).Count -ne 0) {
      Fail "relay_uninstall_firewall_rule_removal_failed"
    }
  }
  $uninstallWal.phase = "firewall-removed"
  Write-UninstallWal $recoveryManifestPath $uninstallWal

  if ([IO.Directory]::Exists($InstallRoot)) {
    Move-Item -LiteralPath $InstallRoot -Destination ([IO.Path]::Combine($archiveDirectory, "program"))
    $uninstallWal.moved_roots = @($uninstallWal.moved_roots) + @("program")
    $uninstallWal.phase = "program-archived"
    Write-UninstallWal $recoveryManifestPath $uninstallWal
  }
  if ([IO.Directory]::Exists($DataRoot)) {
    Move-Item -LiteralPath $DataRoot -Destination ([IO.Path]::Combine($archiveDirectory, "data"))
    $uninstallWal.moved_roots = @($uninstallWal.moved_roots) + @("data")
    $uninstallWal.phase = "data-archived"
    Write-UninstallWal $recoveryManifestPath $uninstallWal
  }

  $uninstallWal.phase = "archived"
  Write-UninstallWal $recoveryManifestPath $uninstallWal
  Write-Output ("relay_uninstall_archived Recovery=" + $archiveDirectory)
} catch {
  $originalFailure = $_
  try {
    Restore-UninstallCheckpoint $uninstallWal $recoveryManifestPath $archiveDirectory `
      $InstallRoot $DataRoot
  } catch {
    throw "relay_uninstall_scm_rollback_failed"
  }
  throw $originalFailure
}
} finally {
  if ($null -ne $deploymentLock) { $deploymentLock.Dispose() }
}
