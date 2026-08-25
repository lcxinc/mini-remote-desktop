[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High", DefaultParameterSetName = "Install")]
param(
  [Parameter(Mandatory = $true, ParameterSetName = "Install")]
  [ValidateSet("Native", "Docker", "Wsl2")]
  [string]$Target,
  [Parameter(Mandatory = $true, ParameterSetName = "Install")][string]$AgentBinary,
  [Parameter(Mandatory = $true, ParameterSetName = "Install")][string]$AgentSha256,
  [Parameter(Mandatory = $true, ParameterSetName = "Install")][string]$BrokerBinary,
  [Parameter(Mandatory = $true, ParameterSetName = "Install")][string]$BrokerSha256,
  [Parameter(Mandatory = $true, ParameterSetName = "Install")][string]$OpenSslExecutable,
  [Parameter(Mandatory = $true, ParameterSetName = "Install")][string]$OpenSslSha256,
  [Parameter(Mandatory = $true, ParameterSetName = "Install")][string]$AgentConfig,
  [Parameter(Mandatory = $true, ParameterSetName = "Install")][string]$EnrollmentTokenFile,
  [Parameter(Mandatory = $true, ParameterSetName = "Install")][string]$TurnSecretFile,
  [Parameter(Mandatory = $true, ParameterSetName = "Install")][string]$TrustedCaFile,
  [Parameter(Mandatory = $true, ParameterSetName = "Install")][string]$TlsCertificateFile,
  [Parameter(Mandatory = $true, ParameterSetName = "Install")][string]$TlsPrivateKeyFile,
  [Parameter(Mandatory = $true, ParameterSetName = "Install")][string]$Realm,
  [Parameter(Mandatory = $true, ParameterSetName = "Install")][string]$ServerName,
  [Parameter(Mandatory = $true, ParameterSetName = "Install")][string]$ExternalIp,
  [string]$RelayIp,
  [ValidateSet(5349, 443)][int]$TlsPort = 5349,
  [string]$InstallRoot = "$env:ProgramFiles\MRD Relay",
  [string]$DataRoot = "$env:ProgramData\MRD\RelayAgent",
  [string]$RecoveryRoot = "$env:ProgramData\MRD\RelayAgentRecovery",
  [string]$VerifiedNativeDrainWrapper,
  [string]$VerifiedNativeDrainWrapperSha256,
  [string]$NativeCoturnBinary,
  [string]$NativeCoturnSha256,
  [string]$DockerExecutable = "$env:ProgramFiles\Docker\Docker\resources\bin\docker.exe",
  [string]$DockerExecutableSha256,
  [string]$WslExecutableSha256,
  [string]$WslExecutable = "$env:SystemRoot\System32\wsl.exe",
  [Parameter(Mandatory = $true, ParameterSetName = "SelfTest")][switch]$SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$AgentServiceName = "mrd-relay-agent"
$BrokerServiceName = "mrd-relay-coturn-control"
$NativeCoturnServiceName = "mrd-coturn-native"
$ControlPipeName = "\\.\pipe\mrd-relay-coturn-control"
$DockerContainerName = "mrd-coturn"
$WslDistributionName = "MRDRelay"
$DockerImage = "coturn/coturn:4.17.2@sha256:aa68aab64a3b929d57fc2924c98ea447bf996cf8dade2508e7b71eaf23f1f14e"
$DockerExpectedPath = "/usr/bin/turnserver"
$DockerExpectedArgs = @("--config", "/run/mrd/turnserver.conf")
$DockerExpectedNetworkMode = "bridge"
$DockerExpectedSecurityOpt = "no-new-privileges:true"
$RecoveryRootMarkerName = ".mrd-relay-recovery-root.json"
$DeploymentLockContent = "MRD relay deployment lock v1`n"
$ProgramDataSystemRoot = [IO.Path]::GetFullPath($env:ProgramData).TrimEnd([IO.Path]::DirectorySeparatorChar)
$DefaultManagedBoundary = [IO.Path]::Combine($ProgramDataSystemRoot, "MRD")
$SystemManagedAncestorAllowlist = @(
  $ProgramDataSystemRoot,
  [IO.Path]::GetPathRoot($ProgramDataSystemRoot)
)
$ExpectedSourceConfigKeys = @(
  "backend_url", "node_id", "region", "failure_domain", "endpoints",
  "max_allocations", "max_egress_bps", "metrics_url",
  "heartbeat_interval_seconds", "backend_backoff_cap_seconds"
)

function Fail {
  param([Parameter(Mandatory = $true)][string]$Reason)
  throw $Reason
}

function Get-DeploymentLockPath {
  $machineDataRoot = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::CommonApplicationData)
  if ([string]::IsNullOrWhiteSpace($machineDataRoot)) {
    Fail "relay_install_transaction_lock_path_invalid"
  }
  $canonicalRoot = [IO.Path]::GetFullPath($machineDataRoot).TrimEnd(
    [IO.Path]::DirectorySeparatorChar)
  return [IO.Path]::Combine($canonicalRoot, "MRD", ".mrd-relay-deploy.lock")
}

function Initialize-MachineDeploymentLockBoundary {
  $lockPath = Get-DeploymentLockPath
  $boundary = [IO.Path]::GetDirectoryName($lockPath)
  $machineDataRoot = [IO.Path]::GetDirectoryName($boundary)
  $null = Get-SafeFullPath $machineDataRoot -MustExist
  if (-not [IO.Directory]::Exists($boundary)) {
    $temporary = $boundary + "." + [Guid]::NewGuid().ToString("N") + ".pending"
    try {
      [void][IO.Directory]::CreateDirectory($temporary)
      $temporaryItem = Get-Item -LiteralPath $temporary -Force
      if (($temporaryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail "relay_install_transaction_lock_boundary_reparse_rejected"
      }
      Set-SystemAdminDirectoryAcl $temporary
      $protectedTemporary = Get-Item -LiteralPath $temporary -Force
      if ($protectedTemporary.GetFileSystemInfos().Count -ne 0) {
        Fail "relay_install_transaction_lock_boundary_contaminated"
      }
      try {
        [IO.Directory]::Move($temporary, $boundary)
      } catch [IO.IOException] {
        # Another product transaction may have won the fixed-boundary race.
        # Validate its exact ACL below; never re-own an existing directory.
        if (-not [IO.Directory]::Exists($boundary)) {
          Fail "relay_install_transaction_lock_boundary_create_failed"
        }
      }
    } finally {
      if ([IO.Directory]::Exists($temporary)) {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
      }
    }
  }
  if (-not [IO.Directory]::Exists($boundary)) {
    Fail "relay_install_transaction_lock_boundary_create_failed"
  }
  $item = Get-Item -LiteralPath $boundary -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail "relay_install_transaction_lock_boundary_reparse_rejected"
  }
  Assert-ExactSystemAdminBoundaryAcl $boundary
  return $boundary
}

function Initialize-DeploymentLockFileIfMissing {
  param([Parameter(Mandatory = $true)][string]$Path)
  if ([IO.Directory]::Exists($Path)) { Fail "relay_install_transaction_lock_path_invalid" }
  if (-not [IO.File]::Exists($Path)) {
    $created = $false
    for ($attempt = 0; $attempt -lt 3 -and -not $created; $attempt++) {
      $temporary = $Path + "." + [Guid]::NewGuid().ToString("N") + ".pending"
      try {
        [IO.File]::WriteAllText(
          $temporary, $DeploymentLockContent, (New-Object Text.UTF8Encoding($false)))
        Set-SystemAdminFileAcl $temporary
        try {
          Move-Item -LiteralPath $temporary -Destination $Path -ErrorAction Stop
          $created = $true
        } catch {
          if (-not [IO.File]::Exists($Path)) {
            if ($attempt -eq 2) { Fail "relay_install_transaction_lock_create_failed" }
            continue
          }
          $created = $true
        }
      } finally {
        if ([IO.File]::Exists($temporary)) {
          Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
      }
    }
  }
  $canonical = Get-SafeFullPath $Path -MustExist -Leaf
  if ($canonical -cne $Path) { Fail "relay_install_transaction_lock_path_invalid" }
  Assert-ExactSystemAdminFileAcl $canonical
}

function Open-ExclusiveDeploymentFileLock {
  param([Parameter(Mandatory = $true)][string]$Path)
  try {
    return [IO.File]::Open(
      $Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  } catch [IO.IOException] {
    Fail "relay_install_transaction_busy"
  } catch [UnauthorizedAccessException] {
    Fail "relay_install_transaction_lock_acl_invalid"
  }
}

function Assert-DeploymentLockStreamContent {
  param([Parameter(Mandatory = $true)][IO.FileStream]$Stream)
  $expected = [Text.Encoding]::UTF8.GetBytes($DeploymentLockContent)
  if ($Stream.Length -ne $expected.Length) { Fail "relay_install_transaction_lock_schema_invalid" }
  $actual = New-Object byte[] ([int]$Stream.Length)
  try {
    $Stream.Position = 0
    $offset = 0
    while ($offset -lt $actual.Length) {
      $read = $Stream.Read($actual, $offset, $actual.Length - $offset)
      if ($read -le 0) { Fail "relay_install_transaction_lock_schema_invalid" }
      $offset += $read
    }
    for ($index = 0; $index -lt $expected.Length; $index++) {
      if ($actual[$index] -ne $expected[$index]) {
        Fail "relay_install_transaction_lock_schema_invalid"
      }
    }
  } finally {
    if ($actual.Length -gt 0) { [Array]::Clear($actual, 0, $actual.Length) }
    if ($expected.Length -gt 0) { [Array]::Clear($expected, 0, $expected.Length) }
  }
}

function Enter-DeploymentTransactionLock {
  $path = Get-DeploymentLockPath
  $boundary = [IO.Path]::GetDirectoryName($path)
  Assert-ExactSystemAdminBoundaryAcl $boundary
  Initialize-DeploymentLockFileIfMissing $path
  $stream = Open-ExclusiveDeploymentFileLock $path
  try {
    Assert-ExactSystemAdminFileAcl $path
    Assert-DeploymentLockStreamContent $stream
    return $stream
  } catch {
    $stream.Dispose()
    throw
  }
}

function Test-IsLocalSystemSid {
  param([AllowEmptyString()][string]$IdentitySid)
  return ($IdentitySid -ceq "S-1-5-18")
}

function Assert-CurrentProcessIsLocalSystem {
  try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity -or $null -eq $identity.User -or
        -not (Test-IsLocalSystemSid $identity.User.Value)) {
      Fail "relay_install_wsl_requires_local_system"
    }
  } catch {
    if ($_.Exception.Message -eq "relay_install_wsl_requires_local_system") { throw }
    Fail "relay_install_wsl_identity_unavailable"
  }
}

function ConvertTo-NativeCommandLineArgument {
  param([AllowEmptyString()][string]$Argument)
  if ($null -eq $Argument -or $Argument.Length -gt 4096 -or
      $Argument -match '[\x00-\x1f\x7f]') {
    Fail "relay_install_external_process_argument_invalid"
  }
  if ($Argument.Length -gt 0 -and $Argument -notmatch '[\s"]') { return $Argument }
  $builder = New-Object Text.StringBuilder
  [void]$builder.Append('"')
  $backslashes = 0
  foreach ($character in $Argument.ToCharArray()) {
    if ($character -eq [char]92) {
      $backslashes++
      continue
    }
    if ($character -eq [char]34) {
      [void]$builder.Append(('\' * (($backslashes * 2) + 1)))
      [void]$builder.Append('"')
      $backslashes = 0
      continue
    }
    if ($backslashes -gt 0) {
      [void]$builder.Append(('\' * $backslashes))
      $backslashes = 0
    }
    [void]$builder.Append($character)
  }
  if ($backslashes -gt 0) { [void]$builder.Append(('\' * ($backslashes * 2))) }
  [void]$builder.Append('"')
  return $builder.ToString()
}

function Read-StrictNativeCapture {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][ValidateSet("Utf8", "Utf16Le")][string]$OutputEncoding
  )
  $safePath = Get-SafeFullPath $Path -MustExist -Leaf
  $bytes = [IO.File]::ReadAllBytes($safePath)
  try {
    if ($OutputEncoding -ceq "Utf16Le" -and ($bytes.Length % 2) -ne 0) {
      Fail "relay_install_external_process_output_encoding_invalid"
    }
    $decoder = if ($OutputEncoding -ceq "Utf16Le") {
      New-Object Text.UnicodeEncoding($false, $false, $true)
    } else {
      New-Object Text.UTF8Encoding($false, $true)
    }
    try { $text = $decoder.GetString($bytes) } catch [Text.DecoderFallbackException] {
      Fail "relay_install_external_process_output_encoding_invalid"
    }
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
    if ($text.IndexOf([char]0) -ge 0 -or $text.IndexOf([char]0xFFFD) -ge 0) {
      Fail "relay_install_external_process_output_encoding_invalid"
    }
    return $text
  } finally {
    if ($bytes.Length -gt 0) { [Array]::Clear($bytes, 0, $bytes.Length) }
  }
}

function Invoke-BoundedNativeProcess {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string[]]$Arguments,
    [Parameter(Mandatory = $true)][ValidateRange(1, 120000)][int]$TimeoutMilliseconds,
    [Parameter(Mandatory = $true)][ValidateRange(1, 1048576)][int]$MaxOutputBytes,
    [Parameter(Mandatory = $true)][ValidateSet("Utf8", "Utf16Le")][string]$OutputEncoding,
    [Parameter(Mandatory = $true)][string]$CaptureRoot
  )
  $safePath = Get-SafeFullPath $Path -MustExist -Leaf
  $safeCaptureRoot = Get-SafeFullPath $CaptureRoot -MustExist
  if (-not [IO.Directory]::Exists($safeCaptureRoot) -or
      ((Get-Item -LiteralPath $safeCaptureRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail "relay_install_external_process_capture_root_invalid"
  }
  if ($Arguments.Count -gt 32) { Fail "relay_install_external_process_argument_invalid" }
  $encodedArguments = @($Arguments | ForEach-Object { ConvertTo-NativeCommandLineArgument ([string]$_) })
  $commandLine = $encodedArguments -join ' '
  if ($commandLine.Length -gt 16384) { Fail "relay_install_external_process_argument_invalid" }
  $captureId = [Guid]::NewGuid().ToString("N")
  $stdoutPath = [IO.Path]::Combine($safeCaptureRoot, ".$captureId.stdout")
  $stderrPath = [IO.Path]::Combine($safeCaptureRoot, ".$captureId.stderr")
  $process = $null
  try {
    $process = Start-Process -FilePath $safePath -ArgumentList $commandLine -NoNewWindow -PassThru `
      -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    if ($null -eq $process) { Fail "relay_install_external_process_start_failed" }
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    while (-not $process.HasExited) {
      $capturedBytes = 0L
      if ([IO.File]::Exists($stdoutPath)) { $capturedBytes += (Get-Item -LiteralPath $stdoutPath -Force).Length }
      if ([IO.File]::Exists($stderrPath)) { $capturedBytes += (Get-Item -LiteralPath $stderrPath -Force).Length }
      if ($capturedBytes -gt $MaxOutputBytes) {
        try { $process.Kill() } catch { Fail "relay_install_external_process_output_kill_failed" }
        if (-not $process.WaitForExit(5000)) { Fail "relay_install_external_process_output_kill_failed" }
        Fail "relay_install_external_process_output_too_large"
      }
      if ([DateTime]::UtcNow -ge $deadline) {
        try { $process.Kill() } catch { Fail "relay_install_external_process_timeout_kill_failed" }
        if (-not $process.WaitForExit(5000)) { Fail "relay_install_external_process_timeout_kill_failed" }
        Fail "relay_install_external_process_timeout"
      }
      Start-Sleep -Milliseconds 25
    }
    $process.WaitForExit()
    $capturedBytes = 0L
    if ([IO.File]::Exists($stdoutPath)) { $capturedBytes += (Get-Item -LiteralPath $stdoutPath -Force).Length }
    if ([IO.File]::Exists($stderrPath)) { $capturedBytes += (Get-Item -LiteralPath $stderrPath -Force).Length }
    if ($capturedBytes -gt $MaxOutputBytes) {
      Fail "relay_install_external_process_output_too_large"
    }
    $stdout = if ([IO.File]::Exists($stdoutPath)) {
      Read-StrictNativeCapture $stdoutPath $OutputEncoding
    } else { "" }
    $stderr = if ([IO.File]::Exists($stderrPath)) {
      Read-StrictNativeCapture $stderrPath $OutputEncoding
    } else { "" }
    return [pscustomobject]@{
      ExitCode = [int]$process.ExitCode
      StdOut = $stdout
      StdErr = $stderr
    }
  } finally {
    if ($null -ne $process) { $process.Dispose() }
    foreach ($capturePath in @($stdoutPath, $stderrPath)) {
      if ([IO.File]::Exists($capturePath)) { Remove-Item -LiteralPath $capturePath -Force }
    }
  }
}

function Get-UpgradeMutationPlan {
  return @(
    "phase:before-stop-agent", "stop-agent",
    "phase:before-second-proof", "second-proof",
    "phase:before-stop-broker", "stop-broker",
    "phase:before-stop-target", "stop-target",
    "phase:before-move-roots", "move-roots"
  )
}

function Test-UpgradePhaseAllowsRootSwap {
  param([Parameter(Mandatory = $true)][string]$Phase)
  $known = @(
    "checkpointed", "before-stop-agent", "before-second-proof", "before-stop-broker",
    "before-stop-target", "before-move-roots", "moving-program-root", "program-root-moved",
    "moving-data-root", "data-root-moved", "installing", "verifying", "rollback-roots",
    "complete"
  )
  if ($known -cnotcontains $Phase) { Fail "relay_install_upgrade_phase_invalid" }
  return ($Phase -cin @(
      "moving-program-root", "program-root-moved", "moving-data-root", "data-root-moved",
      "installing", "verifying", "rollback-roots"
    ))
}

function Assert-DockerMountSafeDataRoot {
  param([Parameter(Mandatory = $true)][string]$Path)
  if ($Path.IndexOf(',') -ge 0 -or $Path.IndexOf('=') -ge 0) {
    Fail "relay_install_docker_data_root_mount_syntax_invalid"
  }
}

function Get-DockerEnvelopePlaceholderBytes {
  $text = "# MRD broker placeholder v1; no TURN listener`nno-udp`nno-tcp`nno-tls`nno-dtls`n"
  return [Text.Encoding]::UTF8.GetBytes($text)
}

function Assert-DockerEnvelopePlaceholderSelfTest {
  $bytes = @(Get-DockerEnvelopePlaceholderBytes)
  $hex = (($bytes | ForEach-Object { ([byte]$_).ToString("x2") }) -join "")
  $expectedHex = "23204d52442062726f6b657220706c616365686f6c6465722076313b206e6f205455524e206c697374656e65720a6e6f2d7564700a6e6f2d7463700a6e6f2d746c730a6e6f2d64746c730a"
  if ($hex -cne $expectedHex -or $bytes -contains 13 -or
      ($bytes.Count -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)) {
    Fail "relay_install_docker_envelope_placeholder_mismatch"
  }
}

function Initialize-DockerEnvelope {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$BrokerSid,
    [Parameter(Mandatory = $true)][bool]$IsUpgrade
  )
  $safePath = Get-SafeFullPath $Path
  if ($IsUpgrade) {
    $safePath = Get-SafeFullPath $safePath -MustExist -Leaf
    Set-ExactServiceStoreAcl $safePath $BrokerSid
    Assert-BrokerOwnedFileAcl $safePath
    return
  }
  if ([IO.File]::Exists($safePath) -or [IO.Directory]::Exists($safePath)) {
    Fail "relay_install_docker_envelope_existing_fresh_rejected"
  }
  $temporary = $safePath + "." + [Guid]::NewGuid().ToString("N") + ".pending"
  try {
    [IO.File]::WriteAllBytes($temporary, [byte[]](Get-DockerEnvelopePlaceholderBytes))
    Move-Item -LiteralPath $temporary -Destination $safePath
    Set-ExactServiceStoreAcl $safePath $BrokerSid
    Assert-BrokerOwnedFileAcl $safePath
    $actualHex = (([IO.File]::ReadAllBytes($safePath) | ForEach-Object { $_.ToString("x2") }) -join "")
    $expectedHex = ((Get-DockerEnvelopePlaceholderBytes | ForEach-Object { $_.ToString("x2") }) -join "")
    if ($actualHex -cne $expectedHex) { Fail "relay_install_docker_envelope_placeholder_mismatch" }
  } finally {
    if ([IO.File]::Exists($temporary)) { Remove-Item -LiteralPath $temporary -Force }
  }
}

function Test-WslInstallDisposition {
  param([Parameter(Mandatory = $true)][string]$SelectedTarget, [bool]$IsUpgrade)
  return ($SelectedTarget -cne "Wsl2" -or $IsUpgrade)
}

function Test-IpAddress {
  param([Parameter(Mandatory = $true)][string]$Value)
  $parsed = $null
  return [Net.IPAddress]::TryParse($Value, [ref]$parsed)
}

function Test-GlobalIpAddress {
  param([Parameter(Mandatory = $true)][string]$Value)
  $address = $null
  if (-not [Net.IPAddress]::TryParse($Value, [ref]$address)) { return $false }
  $bytes = $address.GetAddressBytes()
  if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
    $first = [int]$bytes[0]
    $second = [int]$bytes[1]
    $third = [int]$bytes[2]
    $fourth = [int]$bytes[3]
    if ($first -eq 0 -or $first -eq 10 -or $first -eq 127 -or $first -ge 224 -or
        ($first -eq 100 -and $second -ge 64 -and $second -le 127) -or
        ($first -eq 169 -and $second -eq 254) -or
        ($first -eq 172 -and $second -ge 16 -and $second -le 31) -or
        ($first -eq 192 -and $second -eq 168) -or
        ($first -eq 192 -and $second -eq 0 -and $third -eq 0 -and $fourth -notin @(9, 10)) -or
        ($first -eq 192 -and $second -eq 0 -and $third -eq 2) -or
        ($first -eq 192 -and $second -eq 88 -and $third -eq 99) -or
        ($first -eq 198 -and $second -in @(18, 19)) -or
        ($first -eq 198 -and $second -eq 51 -and $third -eq 100) -or
        ($first -eq 203 -and $second -eq 0 -and $third -eq 113)) {
      return $false
    }
    return $true
  }
  if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6 -or
      $address.IsIPv4MappedToIPv6) {
    return $false
  }
  $isWellKnownNat64 = $bytes[0] -eq 0x00 -and $bytes[1] -eq 0x64 -and
    $bytes[2] -eq 0xff -and $bytes[3] -eq 0x9b
  for ($index = 4; $isWellKnownNat64 -and $index -lt 12; $index++) {
    if ($bytes[$index] -ne 0) { $isWellKnownNat64 = $false }
  }
  if ($isWellKnownNat64) {
    $embedded = New-Object Net.IPAddress (,[byte[]]@($bytes[12], $bytes[13], $bytes[14], $bytes[15]))
    return Test-GlobalIpAddress $embedded.ToString()
  }
  $firstSegment = ([int]$bytes[0] -shl 8) -bor [int]$bytes[1]
  $secondSegment = ([int]$bytes[2] -shl 8) -bor [int]$bytes[3]
  $thirdSegment = ([int]$bytes[4] -shl 8) -bor [int]$bytes[5]
  $tailIsOneToThree = $bytes[15] -in @(1, 2, 3)
  for ($index = 4; $tailIsOneToThree -and $index -lt 15; $index++) {
    if ($bytes[$index] -ne 0) { $tailIsOneToThree = $false }
  }
  $ietfException = ($secondSegment -eq 0x0001 -and $tailIsOneToThree) -or
    $secondSegment -eq 0x0003 -or
    ($secondSegment -eq 0x0004 -and $thirdSegment -eq 0x0112) -or
    (($secondSegment -band 0xfff0) -in @(0x0020, 0x0030))
  return $firstSegment -ge 0x2000 -and $firstSegment -le 0x3fff -and
    -not ($firstSegment -eq 0x2001 -and $secondSegment -le 0x01ff -and -not $ietfException) -and
    -not ($firstSegment -eq 0x2001 -and $secondSegment -eq 0x0db8) -and
    $firstSegment -ne 0x2002 -and
    -not ($firstSegment -eq 0x3fff -and ($secondSegment -band 0xf000) -eq 0)
}

function Assert-PublicIpClassifierVectors {
  $vectorPath = Get-SafeFullPath ([IO.Path]::Combine($PSScriptRoot, "..", "public-ip-test-vectors.json")) -MustExist -Leaf
  try { $vectors = Get-Content -LiteralPath $vectorPath -Raw | ConvertFrom-Json } catch {
    Fail "relay_install_public_ip_vectors_invalid"
  }
  $keys = @($vectors.PSObject.Properties.Name | Sort-Object)
  if (($keys -join "`n") -cne ((@(
        "schema_version", "accepted", "rejected", "accepted_mappings", "rejected_mappings"
      ) | Sort-Object) -join "`n") -or
      $vectors.schema_version -ne 1) {
    Fail "relay_install_public_ip_vectors_invalid"
  }
  foreach ($value in @($vectors.accepted)) {
    if ($value -isnot [string] -or -not (Test-GlobalIpAddress $value)) {
      Fail "relay_install_public_ip_classifier_drift"
    }
  }
  foreach ($value in @($vectors.rejected)) {
    if ($value -isnot [string] -or (Test-GlobalIpAddress $value)) {
      Fail "relay_install_public_ip_classifier_drift"
    }
  }
  foreach ($mapping in @($vectors.accepted_mappings)) {
    $mappingKeys = @($mapping.PSObject.Properties.Name | Sort-Object)
    if (($mappingKeys -join "`n") -cne "external_ip`nrelay_ip" -or
        $null -ne (Get-RelayMappingFailure ([string]$mapping.external_ip) ([string]$mapping.relay_ip))) {
      Fail "relay_install_public_ip_mapping_classifier_drift"
    }
  }
  foreach ($mapping in @($vectors.rejected_mappings)) {
    $mappingKeys = @($mapping.PSObject.Properties.Name | Sort-Object)
    if (($mappingKeys -join "`n") -cne "external_ip`nrelay_ip" -or
        $null -eq (Get-RelayMappingFailure ([string]$mapping.external_ip) ([string]$mapping.relay_ip))) {
      Fail "relay_install_public_ip_mapping_classifier_drift"
    }
  }
  if ((Get-ExpectedListeningIp "198.20.0.10/10.0.0.10") -cne "0.0.0.0") {
    Fail "relay_install_listener_self_test_ipv4_mismatch"
  }
  if ((Get-ExpectedListeningIp "2606:4700:4700::1111/fd00::10") -cne "::") {
    Fail "relay_install_listener_self_test_ipv6_mismatch"
  }
}

function Get-RelayMappingFailure {
  param(
    [Parameter(Mandatory = $true)][string]$ExternalAddress,
    [AllowEmptyString()][string]$RelayAddress
  )
  $externalParts = @($ExternalAddress.Split('/'))
  if (($externalParts.Count -ne 1 -and $externalParts.Count -ne 2) -or
      [string]::IsNullOrEmpty($externalParts[0]) -or
      -not (Test-GlobalIpAddress $externalParts[0])) {
    return "relay_install_external_ip_invalid"
  }
  $publicIp = $null
  if (-not [Net.IPAddress]::TryParse($externalParts[0], [ref]$publicIp)) {
    return "relay_install_external_ip_invalid"
  }
  $privateIp = $null
  if ($externalParts.Count -eq 2) {
    if ([string]::IsNullOrEmpty($externalParts[1]) -or
        -not [Net.IPAddress]::TryParse($externalParts[1], [ref]$privateIp)) {
      return "relay_install_external_ip_invalid"
    }
    if ($privateIp.AddressFamily -ne $publicIp.AddressFamily) {
      return "relay_install_external_ip_family_mismatch"
    }
  }
  $relayIpValue = $null
  if (-not [string]::IsNullOrEmpty($RelayAddress)) {
    if (-not [Net.IPAddress]::TryParse($RelayAddress, [ref]$relayIpValue)) {
      return "relay_install_relay_ip_invalid"
    }
    if ($relayIpValue.AddressFamily -ne $publicIp.AddressFamily) {
      return "relay_install_relay_ip_family_mismatch"
    }
  }
  if ($externalParts.Count -eq 2 -and
      ([string]::IsNullOrEmpty($RelayAddress) -or $RelayAddress -cne $externalParts[1])) {
    return "relay_install_external_relay_mapping_mismatch"
  }
  return $null
}

function Get-ExpectedListeningIp {
  param([Parameter(Mandatory = $true)][string]$ExternalAddress)
  $publicText = $ExternalAddress.Split('/', 2)[0]
  $publicAddress = $null
  if (-not [Net.IPAddress]::TryParse($publicText, [ref]$publicAddress)) {
    Fail "relay_install_external_ip_invalid"
  }
  if ($publicAddress.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
    return "0.0.0.0"
  }
  if ($publicAddress.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
    return "::"
  }
  Fail "relay_install_external_ip_invalid"
}

function Assert-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail "relay_install_requires_administrator"
  }
}

function Get-SafeFullPath {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [switch]$MustExist,
    [switch]$Leaf
  )
  if (-not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith("\\")) {
    Fail "relay_install_unsafe_path"
  }
  $full = [IO.Path]::GetFullPath($Path)
  if ($full.StartsWith("\\?\") -or $full.StartsWith("\\.\") -or
      ($full.Length -gt 2 -and $full.Substring(2).Contains(":"))) {
    Fail "relay_install_device_or_ads_path_rejected"
  }
  if ($MustExist -and -not ([IO.File]::Exists($full) -or [IO.Directory]::Exists($full))) {
    Fail "relay_install_source_missing"
  }
  if ($Leaf -and -not [IO.File]::Exists($full)) {
    Fail "relay_install_source_not_file"
  }
  $cursor = $full
  if ([IO.File]::Exists($cursor)) {
    $cursor = [IO.Path]::GetDirectoryName($cursor)
  }
  while (-not [string]::IsNullOrEmpty($cursor)) {
    if ([IO.Directory]::Exists($cursor)) {
      $item = Get-Item -LiteralPath $cursor -Force
      if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail "relay_install_reparse_ancestor_rejected"
      }
    }
    $parent = [IO.Directory]::GetParent($cursor)
    if ($null -eq $parent) { break }
    $cursor = $parent.FullName
  }
  if ([IO.File]::Exists($full)) {
    $leafItem = Get-Item -LiteralPath $full -Force
    if (($leafItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      Fail "relay_install_reparse_leaf_rejected"
    }
  }
  return $full
}

function Assert-ProtectedSource {
  param([Parameter(Mandatory = $true)][string]$Path)
  $acl = Get-Acl -LiteralPath $Path
  if (-not $acl.AreAccessRulesProtected) { Fail "relay_install_private_source_inheritance_invalid" }
  $allowed = @("S-1-5-18", "S-1-5-32-544")
  $seen = @{}
  foreach ($entry in $acl.Access) {
    if ($entry.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
      Fail "relay_install_private_source_acl_invalid"
    }
    $sid = $entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    if ($allowed -notcontains $sid) { Fail "relay_install_private_source_acl_invalid" }
    $seen[$sid] = $true
  }
  foreach ($sid in $allowed) {
    if (-not $seen.ContainsKey($sid)) { Fail "relay_install_private_source_acl_missing" }
  }
  $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if ($allowed -notcontains $ownerSid) { Fail "relay_install_private_source_owner_invalid" }
}

function Test-AncestorAccessRuleAllowed {
  param(
    [Parameter(Mandatory = $true)]$Entry,
    [Parameter(Mandatory = $true)][bool]$SystemManagedAncestor,
    [Parameter(Mandatory = $true)][string[]]$TrustedWriters
  )
  if ($Entry.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
    return $true
  }
  # InheritOnly ACEs do not authorize an operation on this ancestor. Protected
  # MRD boundaries stop their propagation, and each existing level is checked.
  if (($Entry.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) {
    return $true
  }
  # DELETE_CHILD on an ancestor can remove an existing protected child.
  $alwaysForbidden = [Security.AccessControl.FileSystemRights]::Delete -bor
    [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [Security.AccessControl.FileSystemRights]::TakeOwnership
  if (($Entry.FileSystemRights -band $alwaysForbidden) -eq 0) { return $true }
  try {
    $sid = $Entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
  } catch {
    return $false
  }
  return $TrustedWriters -contains $sid
}

function Assert-ExactSystemAdminBoundaryAcl {
  param([Parameter(Mandatory = $true)][string]$Path)
  if (-not [IO.Directory]::Exists($Path)) { Fail "relay_install_boundary_missing" }
  $item = Get-Item -LiteralPath $Path -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail "relay_install_boundary_reparse_rejected"
  }
  $acl = Get-Acl -LiteralPath $Path
  if (-not $acl.AreAccessRulesProtected -or
      $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @("S-1-5-18", "S-1-5-32-544")) {
    Fail "relay_install_boundary_owner_or_inheritance_invalid"
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
      Fail "relay_install_boundary_acl_invalid"
    }
    $seen[$sid] = $true
  }
  if ($seen.Count -ne 2) { Fail "relay_install_boundary_acl_count_invalid" }
}

function Assert-DisjointManagedRoots {
  param([Parameter(Mandatory = $true)][string[]]$Roots)
  for ($leftIndex = 0; $leftIndex -lt $Roots.Count; $leftIndex++) {
    $left = $Roots[$leftIndex].TrimEnd([IO.Path]::DirectorySeparatorChar)
    for ($rightIndex = $leftIndex + 1; $rightIndex -lt $Roots.Count; $rightIndex++) {
      $right = $Roots[$rightIndex].TrimEnd([IO.Path]::DirectorySeparatorChar)
      $leftPrefix = $left + [IO.Path]::DirectorySeparatorChar
      $rightPrefix = $right + [IO.Path]::DirectorySeparatorChar
      if ($left -ieq $right -or
          $left.StartsWith($rightPrefix, [StringComparison]::OrdinalIgnoreCase) -or
          $right.StartsWith($leftPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        Fail "relay_install_root_overlap_rejected"
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
  if ([IO.Path]::GetDirectoryName($Candidate) -ine $TrustedParent -or -not $ParentTrusted) {
    return $false
  }
  return -not $RootExists -or ($RootTrusted -and $MarkerValid)
}

function Assert-ExactSystemAdminFileAcl {
  param([Parameter(Mandatory = $true)][string]$Path)
  $item = Get-Item -LiteralPath $Path -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -le 0 -or $item.Length -gt 4096) {
    Fail "relay_install_recovery_marker_file_invalid"
  }
  $acl = Get-Acl -LiteralPath $Path
  if (-not $acl.AreAccessRulesProtected -or
      $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne "S-1-5-32-544") {
    Fail "relay_install_recovery_marker_acl_invalid"
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
      Fail "relay_install_recovery_marker_acl_invalid"
    }
    $seen[$sid] = $true
  }
  if ($seen.Count -ne 2) { Fail "relay_install_recovery_marker_acl_invalid" }
}

function Assert-RecoveryRootMarker {
  param([Parameter(Mandatory = $true)][string]$Path)
  $markerPath = [IO.Path]::Combine($Path, $RecoveryRootMarkerName)
  if (-not [IO.File]::Exists($markerPath)) { Fail "relay_install_recovery_marker_missing" }
  Assert-ExactSystemAdminFileAcl $markerPath
  $raw = Get-Content -LiteralPath $markerPath -Raw
  if ([Text.Encoding]::UTF8.GetByteCount($raw) -gt 4096 -or
      [regex]::Matches($raw, '"[A-Za-z0-9_]+"\s*:').Count -ne 5) {
    Fail "relay_install_recovery_marker_schema_invalid"
  }
  try { $marker = $raw | ConvertFrom-Json } catch { Fail "relay_install_recovery_marker_schema_invalid" }
  $rootOwnerSid = (Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier]).Value
  $actualKeys = @($marker.PSObject.Properties.Name | Sort-Object)
  $expectedKeys = @("canonical_path", "owner_sid", "product", "purpose", "schema_version" | Sort-Object)
  if (($actualKeys -join "`n") -cne ($expectedKeys -join "`n") -or
      $marker.schema_version -ne 1 -or $marker.product -cne "mini-remote-desktop" -or
      $marker.purpose -cne "mrd-relay-recovery-root" -or
      $marker.owner_sid -cne "S-1-5-32-544" -or $marker.owner_sid -cne $rootOwnerSid -or
      [string]$marker.canonical_path -ine $Path) {
    Fail "relay_install_recovery_marker_schema_invalid"
  }
}

function Set-SystemAdminFileAcl {
  param([Parameter(Mandatory = $true)][string]$Path)
  $null = & icacls.exe $Path "/setowner" "BUILTIN\Administrators"
  if ($LASTEXITCODE -ne 0) { Fail "relay_install_recovery_marker_owner_failed" }
  $null = & icacls.exe $Path "/inheritance:r" "/grant:r" `
    "SYSTEM:(F)" "BUILTIN\Administrators:(F)"
  if ($LASTEXITCODE -ne 0) { Fail "relay_install_recovery_marker_acl_failed" }
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
    schema_version = 1
    product = "mini-remote-desktop"
    purpose = "mrd-relay-recovery-root"
    canonical_path = $Path
    owner_sid = "S-1-5-32-544"
  }
  $encoding = New-Object Text.UTF8Encoding($false)
  [IO.File]::WriteAllText($temporary, ($marker | ConvertTo-Json -Compress) + "`n", $encoding)
  Set-SystemAdminFileAcl $temporary
  Move-Item -LiteralPath $temporary -Destination $markerPath
  Assert-RecoveryRootMarker $Path
}

function Assert-RecoveryRootPolicySelfTest {
  $defaultRecovery = [IO.Path]::Combine($DefaultManagedBoundary, "RelayAgentRecovery")
  if (Test-RecoveryRootDisposition "C:\Windows" $DefaultManagedBoundary $true $true $true $true) {
    Fail "relay_install_recovery_self_test_windows_accepted"
  }
  if (Test-RecoveryRootDisposition $env:ProgramFiles $DefaultManagedBoundary $true $true $true $true) {
    Fail "relay_install_recovery_self_test_business_directory_accepted"
  }
  if (-not (Test-RecoveryRootDisposition $defaultRecovery $DefaultManagedBoundary $false $true $false $false)) {
    Fail "relay_install_recovery_self_test_new_root_rejected"
  }
  if (-not (Test-RecoveryRootDisposition $defaultRecovery $DefaultManagedBoundary $true $true $true $true)) {
    Fail "relay_install_recovery_self_test_existing_root_rejected"
  }
  if (Test-RecoveryRootDisposition $defaultRecovery $DefaultManagedBoundary $true $true $true $false) {
    Fail "relay_install_recovery_self_test_forged_marker_accepted"
  }
  $overlapRejected = $false
  try { Assert-DisjointManagedRoots @("C:\MRD", "C:\MRD\data", "D:\recovery") } catch { $overlapRejected = $true }
  if (-not $overlapRejected) { Fail "relay_install_recovery_self_test_nested_roots_accepted" }
}

function Assert-AncestorAclRuleSelfTest {
  $untrusted = New-Object Security.Principal.SecurityIdentifier("S-1-5-11")
  $trusted = New-Object Security.Principal.SecurityIdentifier("S-1-5-18")
  $allow = [Security.AccessControl.AccessControlType]::Allow
  $noneInheritance = [Security.AccessControl.InheritanceFlags]::None
  $nonePropagation = [Security.AccessControl.PropagationFlags]::None
  $trustedInstaller = New-Object Security.Principal.NTAccount("NT SERVICE\TrustedInstaller")
  $trustedWriters = @(
    "S-1-5-18", "S-1-5-32-544",
    $trustedInstaller.Translate([Security.Principal.SecurityIdentifier]).Value
  )
  $readRule = [Security.AccessControl.FileSystemAccessRule]::new(
    $untrusted, [Security.AccessControl.FileSystemRights]::ReadAndExecute,
    $noneInheritance, $nonePropagation, $allow)
  if (-not (Test-AncestorAccessRuleAllowed $readRule $false $trustedWriters)) {
    Fail "relay_install_acl_self_test_read_rejected"
  }
  $createRule = [Security.AccessControl.FileSystemAccessRule]::new(
    $untrusted,
    ([Security.AccessControl.FileSystemRights]::WriteData -bor
      [Security.AccessControl.FileSystemRights]::AppendData),
    $noneInheritance, $nonePropagation, $allow)
  if (-not (Test-AncestorAccessRuleAllowed $createRule $true $trustedWriters)) {
    Fail "relay_install_acl_self_test_system_create_rejected"
  }
  if (-not (Test-AncestorAccessRuleAllowed $createRule $false $trustedWriters)) {
    Fail "relay_install_acl_self_test_custom_create_rejected"
  }
  $propagatingCreateRule = [Security.AccessControl.FileSystemAccessRule]::new(
    $untrusted, [Security.AccessControl.FileSystemRights]::WriteData,
    [Security.AccessControl.InheritanceFlags]::ContainerInherit,
    $nonePropagation, $allow)
  if (-not (Test-AncestorAccessRuleAllowed $propagatingCreateRule $true $trustedWriters)) {
    Fail "relay_install_acl_self_test_propagating_create_rejected"
  }
  $inheritOnlyDeleteRule = [Security.AccessControl.FileSystemAccessRule]::new(
    $untrusted, [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,
    [Security.AccessControl.InheritanceFlags]::ContainerInherit,
    [Security.AccessControl.PropagationFlags]::InheritOnly, $allow)
  if (-not (Test-AncestorAccessRuleAllowed $inheritOnlyDeleteRule $true $trustedWriters)) {
    Fail "relay_install_acl_self_test_inherit_only_delete_rejected"
  }
  $deleteRule = [Security.AccessControl.FileSystemAccessRule]::new(
    $untrusted, [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,
    $noneInheritance, $nonePropagation, $allow)
  if (Test-AncestorAccessRuleAllowed $deleteRule $true $trustedWriters) {
    Fail "relay_install_acl_self_test_effective_delete_accepted"
  }
  $trustedRule = [Security.AccessControl.FileSystemAccessRule]::new(
    $trusted, [Security.AccessControl.FileSystemRights]::FullControl,
    [Security.AccessControl.InheritanceFlags]::ContainerInherit,
    $nonePropagation, $allow)
  if (-not (Test-AncestorAccessRuleAllowed $trustedRule $false $trustedWriters)) {
    Fail "relay_install_acl_self_test_trusted_writer_rejected"
  }
  foreach ($standardAncestor in @(
      [IO.Path]::GetPathRoot($env:ProgramData), $env:ProgramData, $env:ProgramFiles
    )) {
    $systemManaged = $standardAncestor -ieq [IO.Path]::GetPathRoot($env:ProgramData) -or
      $standardAncestor -ieq $env:ProgramData
    foreach ($entry in (Get-Acl -LiteralPath $standardAncestor).Access) {
      if (-not (Test-AncestorAccessRuleAllowed $entry $systemManaged $trustedWriters)) {
        Fail "relay_install_acl_self_test_standard_ancestor_rejected"
      }
    }
  }
}

function Assert-TrustedDestinationAncestors {
  param([Parameter(Mandatory = $true)][string]$Path)
  # Get-SafeFullPath already rejects every reparse ancestor. A missing managed
  # root is created by this elevated process and immediately receives a
  # protected ACL; an existing managed root must already have trusted writers.
  $allowedWriters = @("S-1-5-18", "S-1-5-32-544")
  $trustedInstaller = New-Object Security.Principal.NTAccount("NT SERVICE\TrustedInstaller")
  $allowedWriters += $trustedInstaller.Translate([Security.Principal.SecurityIdentifier]).Value
  $cursor = $Path
  while (-not [string]::IsNullOrEmpty($cursor)) {
    if ([IO.Directory]::Exists($cursor)) {
      $acl = Get-Acl -LiteralPath $cursor
      $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
      if ($allowedWriters -notcontains $owner) { Fail "relay_install_destination_owner_invalid" }
      $isSystemManagedAncestor = @($SystemManagedAncestorAllowlist | Where-Object { $_ -ieq $cursor }).Count -eq 1
      foreach ($entry in $acl.Access) {
        if (-not (Test-AncestorAccessRuleAllowed $entry $isSystemManagedAncestor $allowedWriters)) {
          Fail "relay_install_destination_writer_invalid"
        }
      }
    }
    $parent = [IO.Directory]::GetParent($cursor)
    if ($null -eq $parent) { break }
    $cursor = $parent.FullName
  }
}

function Assert-DestinationParentPlan {
  param([Parameter(Mandatory = $true)][string]$Path)
  $parent = [IO.Path]::GetDirectoryName($Path)
  if ([IO.Directory]::Exists($parent)) { return }
  if ($parent -ine $DefaultManagedBoundary) {
    Fail "relay_install_destination_parent_missing"
  }
}

function Initialize-DefaultManagedBoundary {
  $needsBoundary = ([IO.Path]::GetDirectoryName($DataRoot) -ieq $DefaultManagedBoundary) -or
    ([IO.Path]::GetDirectoryName($RecoveryRoot) -ieq $DefaultManagedBoundary)
  if ($needsBoundary -and -not [IO.Directory]::Exists($DefaultManagedBoundary)) {
    [void][IO.Directory]::CreateDirectory($DefaultManagedBoundary)
    $boundaryItem = Get-Item -LiteralPath $DefaultManagedBoundary -Force
    if (($boundaryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      Fail "relay_install_destination_reparse_rejected"
    }
    Set-SystemAdminDirectoryAcl $DefaultManagedBoundary
  }
  if ($needsBoundary) {
    Assert-ExactSystemAdminBoundaryAcl $DefaultManagedBoundary
    Assert-TrustedDestinationAncestors $DefaultManagedBoundary
  }
}

function Assert-SignedHash {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$ExpectedSha256,
    [Parameter(Mandatory = $true)][string]$ReasonPrefix
  )
  if ($ExpectedSha256 -notmatch '^[0-9A-Fa-f]{64}$') { Fail ($ReasonPrefix + "_hash_invalid") }
  $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
  if ($actual -ine $ExpectedSha256) { Fail ($ReasonPrefix + "_hash_mismatch") }
  $signature = Get-AuthenticodeSignature -LiteralPath $Path
  if ($signature.Status -ne "Valid") { Fail ($ReasonPrefix + "_signature_invalid") }
}

function Invoke-Sc {
  param([Parameter(Mandatory = $true)][string[]]$Arguments)
  $result = @(& sc.exe @Arguments 2>&1)
  if ($LASTEXITCODE -ne 0) { Fail "relay_install_scm_operation_failed" }
  return $result
}

function Initialize-ScmUnicodeApi {
  if ($null -ne ('MrdRelay.InstallScmNative' -as [type])) { return }
  $source = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace MrdRelay {
  public static class InstallScmNative {
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
    Fail "relay_install_scm_unicode_api_unavailable"
  }
}

function Get-ScmUnicodeConfiguration {
  param([Parameter(Mandatory = $true)][string]$ServiceName)
  Initialize-ScmUnicodeApi
  try { $native = [MrdRelay.InstallScmNative]::GetConfiguration($ServiceName) } catch {
    Fail "relay_install_scm_snapshot_incomplete"
  }
  $start = switch ([uint32]$native.StartType) {
    0 { "boot" }
    1 { "system" }
    2 { if ([bool]$native.DelayedAutoStart) { "delayed-auto" } else { "auto" } }
    3 { "demand" }
    4 { "disabled" }
    default { Fail "relay_install_scm_snapshot_incomplete" }
  }
  if ([uint32]$native.StartType -ne 2 -and [bool]$native.DelayedAutoStart) {
    Fail "relay_install_scm_snapshot_incomplete"
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
  return ($Value.Length -ge 1 -and $Value.Length -le 256 -and
    $Value -ceq $Value.Trim() -and $Value -cne "+" -and
    $Value -notmatch '[\x00-\x1f\x7f/\\"]')
}

function ConvertTo-CanonicalScBaseConfiguration {
  param([Parameter(Mandatory = $true)]$Configuration)
  $propertyNames = @($Configuration.PSObject.Properties.Name | Sort-Object)
  if (($propertyNames -join "`n") -cne ((@("account", "binary_path", "start") | Sort-Object) -join "`n")) {
    Fail "relay_install_scm_base_configuration_invalid"
  }
  $binaryPath = [string]$Configuration.binary_path
  $account = [string]$Configuration.account
  $start = [string]$Configuration.start
  if ($binaryPath.Length -lt 1 -or $binaryPath.Length -gt 32768 -or
      $account.Length -lt 1 -or $account.Length -gt 256 -or
      $binaryPath -match '[\x00-\x1f\x7f]' -or $account -match '[\x00-\x1f\x7f]' -or
      $start -notin @("boot", "system", "auto", "delayed-auto", "demand", "disabled")) {
    Fail "relay_install_scm_base_configuration_invalid"
  }
  return [ordered]@{ binary_path = $binaryPath; account = $account; start = $start }
}

function ConvertTo-CanonicalScDependencies {
  param([AllowEmptyCollection()][object[]]$Dependencies)
  $values = @($Dependencies)
  if ($values.Count -gt 64) { Fail "relay_install_scm_dependency_count_invalid" }
  $seen = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  $canonical = New-Object Collections.ArrayList
  foreach ($candidate in $values) {
    if ($null -eq $candidate) { Fail "relay_install_scm_dependency_invalid" }
    $value = [string]$candidate
    if (-not (Test-ScDependencyToken $value)) {
      Fail "relay_install_scm_dependency_invalid"
    }
    if (-not $seen.Add($value)) { Fail "relay_install_scm_dependency_duplicate" }
    [void]$canonical.Add($value)
  }
  return @($canonical)
}

function Get-ScDependenciesFromQc {
  param([Parameter(Mandatory = $true)][string]$Qc)
  $lines = [regex]::Split($Qc, '\r?\n')
  $headerIndexes = New-Object Collections.ArrayList
  $rawDependencies = New-Object Collections.ArrayList
  for ($index = 0; $index -lt $lines.Count; $index++) {
    $header = [regex]::Match($lines[$index], '^[ \t]*DEPENDENCIES[ \t]*:[ \t]*(.*?)[ \t]*$')
    if (-not $header.Success) { continue }
    [void]$headerIndexes.Add($index)
  }
  if ($headerIndexes.Count -ne 1) { Fail "relay_install_scm_snapshot_incomplete" }
  $headerIndex = [int]$headerIndexes[0]
  $header = [regex]::Match(
    $lines[$headerIndex], '^[ \t]*DEPENDENCIES[ \t]*:[ \t]*(.*?)[ \t]*$')
  $first = $header.Groups[1].Value
  if (-not [string]::IsNullOrEmpty($first)) { [void]$rawDependencies.Add($first) }
  $consumedContinuations = @{}
  for ($index = $headerIndex + 1; $index -lt $lines.Count; $index++) {
    $line = $lines[$index]
    $continuation = [regex]::Match($line, '^[ \t]+:[ \t]*(.*?)[ \t]*$')
    if ($continuation.Success) {
      if ([string]::IsNullOrEmpty($first) -or [string]::IsNullOrEmpty($continuation.Groups[1].Value)) {
        Fail "relay_install_scm_snapshot_incomplete"
      }
      [void]$rawDependencies.Add($continuation.Groups[1].Value)
      if ($rawDependencies.Count -gt 64) { Fail "relay_install_scm_dependency_count_invalid" }
      $consumedContinuations[$index] = $true
      continue
    }
    if ($line -match '^[ \t]*[A-Z][A-Z0-9_ ]{0,63}[ \t]*:') { break }
    if (-not [string]::IsNullOrWhiteSpace($line)) {
      Fail "relay_install_scm_snapshot_incomplete"
    }
    break
  }
  for ($index = 0; $index -lt $lines.Count; $index++) {
    if (-not $consumedContinuations.ContainsKey($index) -and $lines[$index] -match '^[ \t]+:') {
      Fail "relay_install_scm_snapshot_incomplete"
    }
  }
  return @(ConvertTo-CanonicalScDependencies @($rawDependencies))
}

function Format-ScDependencyValue {
  param([AllowEmptyCollection()][object[]]$Dependencies)
  $canonical = @(ConvertTo-CanonicalScDependencies $Dependencies)
  if ($canonical.Count -eq 0) { return "/" }
  return ($canonical -join "/")
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
      Fail "relay_install_scm_snapshot_incomplete"
    }
  }
  $binaryMatch = [regex]::Match($Qc, '(?im)^\s*BINARY_PATH_NAME\s*:\s*(.+?)\s*$')
  $startMatch = [regex]::Match($Qc, '(?im)^\s*START_TYPE\s*:\s*[0-9]+\s+(BOOT_START|SYSTEM_START|AUTO_START|DEMAND_START|DISABLED)(?:\s+\((DELAYED)\))?\s*$')
  $accountMatch = [regex]::Match($Qc, '(?im)^\s*SERVICE_START_NAME\s*:\s*(.+?)\s*$')
  $transcriptDependencies = @(Get-ScDependenciesFromQc $Qc)
  if ($UseExactDependencies) {
    $dependencies = @(ConvertTo-CanonicalScDependencies $ExactDependencies)
    if ($dependencies.Count -ne $transcriptDependencies.Count) {
      Fail "relay_install_scm_snapshot_incomplete"
    }
  } else {
    $dependencies = @($transcriptDependencies)
  }
  $exactBase = $null
  if ($UseExactBaseConfiguration) {
    if ($null -eq $ExactBaseConfiguration) { Fail "relay_install_scm_base_configuration_invalid" }
    $exactBase = ConvertTo-CanonicalScBaseConfiguration $ExactBaseConfiguration
  }
  $resetMatch = [regex]::Match($Failure, '(?im)^\s*RESET_PERIOD[^:]*:\s*(INFINITE|[0-9]+)\s*$')
  $commandMatch = [regex]::Match($Failure, '(?im)^\s*COMMAND_LINE\s*:\s*(.*?)\s*$')
  $rebootMatch = [regex]::Match($Failure, '(?im)^\s*REBOOT_MESSAGE\s*:\s*(.*?)\s*$')
  $flagMatches = [regex]::Matches(
    $FailureFlag,
    '(?im)^[^:\r\n]{1,256}:\s*(TRUE|FALSE|[01])\s*$'
  )
  $sidMatch = [regex]::Match($SidType, '(?im):\s*(NONE|UNRESTRICTED|RESTRICTED)\s*$')
  if (-not $binaryMatch.Success -or -not $startMatch.Success -or -not $accountMatch.Success -or
      -not $resetMatch.Success -or -not $commandMatch.Success -or
      -not $rebootMatch.Success -or $flagMatches.Count -ne 1 -or -not $sidMatch.Success) {
    Fail "relay_install_scm_snapshot_incomplete"
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
  if ($actions.Count -eq 0 -or $actions.Count -gt 3) { Fail "relay_install_scm_snapshot_incomplete" }
  $startValue = switch ($startMatch.Groups[1].Value) {
    "BOOT_START" { "boot" }; "SYSTEM_START" { "system" }
    "AUTO_START" { if ($startMatch.Groups[2].Success) { "delayed-auto" } else { "auto" } }
    "DEMAND_START" { "demand" }; "DISABLED" { "disabled" }
  }
  $binaryPathValue = $binaryMatch.Groups[1].Value
  $accountValue = $accountMatch.Groups[1].Value
  if ($UseExactBaseConfiguration) {
    $binaryPathValue = [string]$exactBase.binary_path
    $accountValue = [string]$exactBase.account
    $startValue = [string]$exactBase.start
  }
  $flagToken = $flagMatches[0].Groups[1].Value.ToUpperInvariant()
  $normalizedFailureFlag = if ($flagToken -ceq "TRUE" -or $flagToken -ceq "1") { 1 } else { 0 }
  return [ordered]@{
    schema_version = 1; service_name = $ServiceName
    binary_path = $binaryPathValue; start = $startValue
    account = $accountValue; dependencies = $dependencies
    sid_type = $sidMatch.Groups[1].Value.ToLowerInvariant()
    failure_flag = $normalizedFailureFlag
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
    if ($LASTEXITCODE -ne 0) { Fail "relay_install_scm_snapshot_incomplete" }
    $text = $lines -join "`n"
    if ([Text.Encoding]::UTF8.GetByteCount($text) -gt 16384) { Fail "relay_install_scm_snapshot_incomplete" }
    $outputs[$query] = $text
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
  $expectedJson = $Expected | ConvertTo-Json -Depth 8 -Compress
  $actualJson = $Actual | ConvertTo-Json -Depth 8 -Compress
  if ($expectedJson -cne $actualJson) { Fail "relay_install_scm_rollback_readback_mismatch" }
}

function Restore-ExactScmSnapshot {
  param([Parameter(Mandatory = $true)]$Snapshot)
  $name = [string]$Snapshot.service_name
  if (-not (Test-ServiceExists $name)) { Fail "relay_install_rollback_scm_service_missing" }
  $dependencyValue = Format-ScDependencyValue $Snapshot.dependencies
  $null = Invoke-Sc @(
    "config", $name, "binPath=", [string]$Snapshot.binary_path,
    "start=", [string]$Snapshot.start, "obj=", [string]$Snapshot.account,
    "depend=", $dependencyValue
  )
  $null = Invoke-Sc @("sidtype", $name, [string]$Snapshot.sid_type)
  $actionParts = @($Snapshot.failure_actions | ForEach-Object { "$($_.action)/$($_.delay_ms)" })
  $null = Invoke-Sc @(
    "failure", $name, "reset=", [string]$Snapshot.failure_reset_seconds,
    "reboot=", [string]$Snapshot.failure_reboot_message,
    "command=", [string]$Snapshot.failure_command,
    "actions=", ($actionParts -join "/")
  )
  $null = Invoke-Sc @("failureflag", $name, [string]$Snapshot.failure_flag)
  $readBack = Get-ExactScmSnapshot $name
  Assert-ExactScmSnapshotEqual $Snapshot $readBack
}

function Assert-ScmSnapshotSelfTest {
  $qc = @'
SERVICE_NAME: mrd-relay-agent
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START  (DELAYED)
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\MRD\mrd-relay-agent.exe" run --config "C:\MRD\agent.json"
        DEPENDENCIES       : RPCSS
                           : BrokerInfrastructure
                           : MRD 依赖 $Svc
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
  $snapshot = ConvertFrom-ScServiceTranscript "mrd-relay-agent" $qc $failure `
    "FAILURE_ACTIONS_ON_NONCRASH_FAILURES: 0" "SERVICE_SID_TYPE: RESTRICTED"
  if (@($snapshot.dependencies).Count -ne 3 -or
      [string]$snapshot.dependencies[0] -cne "RPCSS" -or
      [string]$snapshot.dependencies[1] -cne "BrokerInfrastructure" -or
      [string]$snapshot.dependencies[2] -cne 'MRD 依赖 $Svc') {
    Fail "relay_install_scm_self_test_multiline_dependencies_lost"
  }
  if ((Format-ScDependencyValue $snapshot.dependencies) -cne 'RPCSS/BrokerInfrastructure/MRD 依赖 $Svc') {
    Fail "relay_install_scm_self_test_dependency_format_invalid"
  }
  if ((Format-ScDependencyValue @()) -cne "/") {
    Fail "relay_install_scm_self_test_empty_dependency_format_invalid"
  }
  $dependencyBlockPattern = '(?m)^[ \t]*DEPENDENCIES[^\r\n]*\r?\n[ \t]*:[ \t]*BrokerInfrastructure[ \t]*\r?\n[ \t]*:[ \t]*MRD 依赖 \$Svc[ \t]*\r?\n'
  $manyDependencyLines = @("        DEPENDENCIES       : Dep01")
  foreach ($number in 2..65) { $manyDependencyLines += ("                           : Dep{0:D2}" -f $number) }
  $invalidDependencyCases = @(
    [ordered]@{
      reason = "duplicate"
      qc = [regex]::Replace(
        $qc, $dependencyBlockPattern,
        "        DEPENDENCIES       : RPCSS`n                           : rpcss`n")
      values = @("RPCSS", "rpcss")
    },
    [ordered]@{
      reason = "control"
      qc = [regex]::Replace(
        $qc, $dependencyBlockPattern,
        "        DEPENDENCIES       : RPCSS`n                           : Broker$([char]1)Infrastructure`n")
      values = @("RPCSS", "Broker$([char]1)Infrastructure")
    },
    [ordered]@{
      reason = "slash"
      qc = [regex]::Replace(
        $qc, $dependencyBlockPattern,
        "        DEPENDENCIES       : RPCSS`n                           : Broker/Infrastructure`n")
      values = @("RPCSS", "Broker/Infrastructure")
    },
    [ordered]@{
      reason = "backslash"
      qc = [regex]::Replace(
        $qc, $dependencyBlockPattern,
        "        DEPENDENCIES       : RPCSS`n                           : Broker\Infrastructure`n")
      values = @("RPCSS", "Broker\Infrastructure")
    },
    [ordered]@{
      reason = "quote"
      qc = [regex]::Replace(
        $qc, $dependencyBlockPattern,
        '        DEPENDENCIES       : RPCSS' + "`n" + '                           : Broker"Infrastructure' + "`n")
      values = @("RPCSS", 'Broker"Infrastructure')
    },
    [ordered]@{
      reason = "bare_plus"
      qc = [regex]::Replace(
        $qc, $dependencyBlockPattern,
        "        DEPENDENCIES       : RPCSS`n                           : +`n")
      values = @("RPCSS", "+")
    },
    [ordered]@{
      reason = "count"
      qc = [regex]::Replace($qc, $dependencyBlockPattern, (($manyDependencyLines -join "`n") + "`n"))
      values = @(1..65 | ForEach-Object { "Dep{0:D2}" -f $_ })
    }
  )
  foreach ($invalidCase in $invalidDependencyCases) {
    $parserRejected = $false
    try {
      $null = ConvertFrom-ScServiceTranscript "mrd-relay-agent" $invalidCase.qc $failure `
        "FAILURE_ACTIONS_ON_NONCRASH_FAILURES: 0" "SERVICE_SID_TYPE: RESTRICTED"
    } catch { $parserRejected = $true }
    if (-not $parserRejected) {
      Fail ("relay_install_scm_self_test_dependency_" + $invalidCase.reason + "_accepted")
    }
    $formatterRejected = $false
    try { $null = Format-ScDependencyValue $invalidCase.values } catch { $formatterRejected = $true }
    if (-not $formatterRejected) {
      Fail ("relay_install_scm_self_test_dependency_formatter_" + $invalidCase.reason + "_accepted")
    }
  }
  $trueFlagSnapshot = ConvertFrom-ScServiceTranscript "mrd-relay-agent" $qc $failure `
    "FAILURE_ACTIONS_ON_NONCRASH_FAILURES: TRUE" "SERVICE_SID_TYPE: RESTRICTED"
  $falseFlagSnapshot = ConvertFrom-ScServiceTranscript "mrd-relay-agent" $qc $failure `
    "FAILURE_ACTIONS_ON_NONCRASH_FAILURES: FALSE" "SERVICE_SID_TYPE: RESTRICTED"
  if ([int]$trueFlagSnapshot.failure_flag -ne 1 -or [int]$falseFlagSnapshot.failure_flag -ne 0) {
    Fail "relay_install_scm_self_test_boolean_failureflag_not_normalized"
  }
  $unknownFlagRejected = $false
  try {
    $null = ConvertFrom-ScServiceTranscript "mrd-relay-agent" $qc $failure `
      "FAILURE_ACTIONS_ON_NONCRASH_FAILURES: ENABLED" "SERVICE_SID_TYPE: RESTRICTED"
  } catch { $unknownFlagRejected = $true }
  if (-not $unknownFlagRejected) { Fail "relay_install_scm_self_test_unknown_failureflag_accepted" }
  $expectedWideDependencies = @(
    "RpcSs", "+NetworkProvider", 'MSSQL$SQLEXPRESS', "MRD 辅助服务"
  )
  Initialize-ScmUnicodeApi
  $nul = [char]0
  $multiSzBytes = (New-Object Text.UnicodeEncoding($false, $false, $true)).GetBytes(
    ($expectedWideDependencies -join $nul) + $nul + $nul)
  try {
    $wideDependencies = @([MrdRelay.InstallScmNative]::DecodeMultiSzForContract($multiSzBytes))
  } finally {
    [Array]::Clear($multiSzBytes, 0, $multiSzBytes.Length)
  }
  if (($wideDependencies -join "|") -cne ($expectedWideDependencies -join "|")) {
    Fail "relay_install_scm_self_test_unicode_multi_sz_corrupted"
  }
  $mojibakeQc = [regex]::Replace(
    $qc, $dependencyBlockPattern,
    "        DEPENDENCIES       : RpcSs`n" +
    "                           : +NetworkProvider`n" +
    "                           : MSSQL?SQLEXPRESS`n" +
    "                           : MRD ?????`n")
  $mojibakeQc = $mojibakeQc.Replace(
    '"C:\MRD\mrd-relay-agent.exe" run --config "C:\MRD\agent.json"',
    '"C:\MRD\????.exe" run --config "C:\MRD\????.json"'
  ).Replace('NT AUTHORITY\LocalService', 'NT AUTHORITY\????')
  $expectedWideBaseConfiguration = [pscustomobject]@{
    binary_path = '"C:\MRD\中继代理.exe" run --config "C:\MRD\配置.json"'
    account = 'NT AUTHORITY\本地服务'
    start = 'delayed-auto'
  }
  $wideSnapshot = ConvertFrom-ScServiceTranscript "mrd-relay-agent" $mojibakeQc $failure `
    "FAILURE_ACTIONS_ON_NONCRASH_FAILURES: 0" "SERVICE_SID_TYPE: RESTRICTED" `
    -ExactDependencies $wideDependencies -UseExactDependencies `
    -ExactBaseConfiguration $expectedWideBaseConfiguration -UseExactBaseConfiguration
  if ((@($wideSnapshot.dependencies) -join "|") -cne ($expectedWideDependencies -join "|")) {
    Fail "relay_install_scm_self_test_unicode_authority_not_used"
  }
  if ([string]$wideSnapshot.binary_path -cne [string]$expectedWideBaseConfiguration.binary_path -or
      [string]$wideSnapshot.account -cne [string]$expectedWideBaseConfiguration.account -or
      [string]$wideSnapshot.start -cne [string]$expectedWideBaseConfiguration.start) {
    Fail "relay_install_scm_self_test_unicode_base_configuration_not_used"
  }
  foreach ($dependency in @(Get-ScmUnicodeDependencies "Winmgmt")) {
    if (-not (Test-ScDependencyToken $dependency)) {
      Fail "relay_install_scm_self_test_live_unicode_api_invalid"
    }
  }
  $mutated = $snapshot | ConvertTo-Json -Depth 8 | ConvertFrom-Json
  $mutated.binary_path = '"C:\attacker.exe"'
  $detected = $false
  try { Assert-ExactScmSnapshotEqual $snapshot $mutated } catch { $detected = $true }
  if (-not $detected) { Fail "relay_install_scm_self_test_mutation_not_detected" }
  $restored = ConvertFrom-ScServiceTranscript "mrd-relay-agent" $qc $failure `
    "FAILURE_ACTIONS_ON_NONCRASH_FAILURES: 0" "SERVICE_SID_TYPE: RESTRICTED"
  try { Assert-ExactScmSnapshotEqual $snapshot $restored } catch {
    Fail "relay_install_scm_self_test_restored_mismatch"
  }
}

function Test-ServiceExists {
  param([Parameter(Mandatory = $true)][string]$Name)
  $null = & sc.exe query $Name 2>$null
  return ($LASTEXITCODE -eq 0)
}

function Test-ServiceRunning {
  param([Parameter(Mandatory = $true)][string]$Name)
  if (-not (Test-ServiceExists $Name)) { return $false }
  $query = @(& sc.exe query $Name 2>&1)
  return (($query -join "`n") -match 'STATE\s*:\s*4\s+RUNNING')
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
  Fail "relay_install_service_stop_timeout"
}

function Configure-Service {
  param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string]$CommandLine,
    [Parameter(Mandatory = $true)][string]$Account,
    [string]$Dependency
  )
  if (Test-ServiceExists $Name) {
    $arguments = @("config", $Name, "binPath=", $CommandLine, "start=", "delayed-auto", "obj=", $Account)
    if (-not [string]::IsNullOrEmpty($Dependency)) { $arguments += @("depend=", $Dependency) }
    $null = Invoke-Sc $arguments
  } else {
    $arguments = @("create", $Name, "binPath=", $CommandLine, "start=", "delayed-auto", "obj=", $Account)
    if (-not [string]::IsNullOrEmpty($Dependency)) { $arguments += @("depend=", $Dependency) }
    $null = Invoke-Sc $arguments
  }
  $null = Invoke-Sc @("sidtype", $Name, "restricted")
}

function Set-CrashOnlyRecovery {
  param([Parameter(Mandatory = $true)][string]$Name)
  $null = Invoke-Sc @("failureflag", $Name, "0")
  $null = Invoke-Sc @(
    "failure", $Name, "reset=", "4294967295", "actions=", "restart/5000/restart/30000/none/0"
  )
}

function Get-ServiceSid {
  param(
    [Parameter(Mandatory = $true)][string]$Name
  )
  try {
    $account = New-Object Security.Principal.NTAccount("NT SERVICE\$Name")
    $sid = $account.Translate([Security.Principal.SecurityIdentifier]).Value
  } catch {
    Fail "relay_install_service_sid_resolution_failed"
  }
  if ($sid -notmatch '^S-1-5-80-(?:[0-9]+-){4}[0-9]+$') {
    Fail "relay_install_service_sid_invalid"
  }
  return $sid
}

function Set-ExactServiceStoreAcl {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$ServiceSid
  )
  $null = & icacls.exe $Path "/setowner" "BUILTIN\Administrators"
  if ($LASTEXITCODE -ne 0) { Fail "relay_install_store_owner_failed" }
  $serviceTrustee = "*$ServiceSid"
  $null = & icacls.exe $Path "/inheritance:r" "/grant:r" `
    "SYSTEM:(F)" "BUILTIN\Administrators:(F)" "${serviceTrustee}:(F)"
  if ($LASTEXITCODE -ne 0) { Fail "relay_install_store_acl_failed" }
}

function Set-ExactAgentReadAcl {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$AgentServiceSid,
    [switch]$Directory
  )
  $null = & icacls.exe $Path "/setowner" "BUILTIN\Administrators"
  if ($LASTEXITCODE -ne 0) { Fail "relay_install_read_store_owner_failed" }
  $agentTrustee = "*$AgentServiceSid"
  if ($Directory) {
    $null = & icacls.exe $Path "/inheritance:r" "/grant:r" `
      "SYSTEM:(OI)(CI)(F)" "BUILTIN\Administrators:(OI)(CI)(F)" `
      "${agentTrustee}:(OI)(CI)(RX)"
  } else {
    $null = & icacls.exe $Path "/inheritance:r" "/grant:r" `
      "SYSTEM:(F)" "BUILTIN\Administrators:(F)" "${agentTrustee}:(RX)"
  }
  if ($LASTEXITCODE -ne 0) { Fail "relay_install_read_store_acl_failed" }
}

function Invoke-RustSecretProvisioning {
  param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [Parameter(Mandatory = $true)][string]$Config,
    [Parameter(Mandatory = $true)][ValidateSet("enrollment", "turn")][string]$Purpose,
    [Parameter(Mandatory = $true)][string]$Source
  )
  $startInfo = New-Object Diagnostics.ProcessStartInfo
  $startInfo.FileName = $Binary
  # Windows PowerShell 5.1 has no ArgumentList. This is a direct CreateProcess
  # invocation (UseShellExecute=false); all values are installer-owned,
  # canonical local paths and never contain plaintext credential material.
  $startInfo.Arguments = 'provision-windows --config "' + $Config + '" --purpose ' + $Purpose
  $startInfo.UseShellExecute = $false
  $startInfo.RedirectStandardInput = $true
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  $startInfo.CreateNoWindow = $true
  $process = New-Object Diagnostics.Process
  $process.StartInfo = $startInfo
  $sourceStream = $null
  try {
    if (-not $process.Start()) { Fail "relay_install_provision_start_failed" }
    $sourceStream = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $sourceStream.CopyTo($process.StandardInput.BaseStream)
    $process.StandardInput.Close()
    $stdout = $process.StandardOutput.ReadToEnd()
    $null = $process.StandardError.ReadToEnd()
    if (-not $process.WaitForExit(30000)) {
      $process.Kill()
      Fail "relay_install_provision_timeout"
    }
    $expected = '{"schema_version":1,"status":"provisioned","purpose":"' + $Purpose + '"}'
    if ($process.ExitCode -ne 0 -or $stdout.TrimEnd("`r", "`n") -cne $expected) {
      Fail "relay_install_provision_failed"
    }
  } finally {
    if ($null -ne $sourceStream) { $sourceStream.Dispose() }
    $process.Dispose()
  }
}

function Set-AgentReadableAcl {
  param([Parameter(Mandatory = $true)][string]$Path)
  $null = & icacls.exe $Path "/setowner" "BUILTIN\Administrators"
  if ($LASTEXITCODE -ne 0) { Fail "relay_install_agent_owner_failed" }
  $null = & icacls.exe $Path "/inheritance:r" "/grant:r" `
    "SYSTEM:(F)" "BUILTIN\Administrators:(F)" "NT SERVICE\${AgentServiceName}:(RX)" `
    "NT SERVICE\${BrokerServiceName}:(RX)"
  if ($LASTEXITCODE -ne 0) { Fail "relay_install_agent_acl_failed" }
}

function Set-SystemAdminDirectoryAcl {
  param([Parameter(Mandatory = $true)][string]$Path)
  $null = & icacls.exe $Path "/setowner" "BUILTIN\Administrators"
  if ($LASTEXITCODE -ne 0) { Fail "relay_install_directory_owner_failed" }
  $null = & icacls.exe $Path "/inheritance:r" "/grant:r" `
    "SYSTEM:(OI)(CI)(F)" "BUILTIN\Administrators:(OI)(CI)(F)"
  if ($LASTEXITCODE -ne 0) { Fail "relay_install_directory_acl_failed" }
  Assert-ExactSystemAdminBoundaryAcl $Path
}

function Set-AgentDirectoryAcl {
  param([Parameter(Mandatory = $true)][string]$Path)
  $null = & icacls.exe $Path "/setowner" "BUILTIN\Administrators"
  if ($LASTEXITCODE -ne 0) { Fail "relay_install_agent_directory_owner_failed" }
  $null = & icacls.exe $Path "/inheritance:r" "/grant:r" `
    "SYSTEM:(OI)(CI)(F)" "BUILTIN\Administrators:(OI)(CI)(F)" `
    "NT SERVICE\${AgentServiceName}:(OI)(CI)(RX)" `
    "NT SERVICE\${BrokerServiceName}:(OI)(CI)(RX)"
  if ($LASTEXITCODE -ne 0) { Fail "relay_install_agent_directory_acl_failed" }
}

function Assert-BrokerOwnedFileAcl {
  param([Parameter(Mandatory = $true)][string]$Path)
  $markerPath = Get-SafeFullPath $Path -MustExist -Leaf
  $acl = Get-Acl -LiteralPath $markerPath
  if (-not $acl.AreAccessRulesProtected) { Fail "relay_install_drain_marker_acl_invalid" }
  $brokerAccount = New-Object Security.Principal.NTAccount("NT SERVICE\$BrokerServiceName")
  $brokerSid = $brokerAccount.Translate([Security.Principal.SecurityIdentifier]).Value
  $allowed = @("S-1-5-18", "S-1-5-32-544", $brokerSid)
  $seen = @{}
  foreach ($entry in $acl.Access) {
    if ($entry.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $entry.IsInherited -or
        $entry.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
        $entry.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or
        $entry.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) {
      Fail "relay_install_drain_marker_acl_invalid"
    }
    $sid = $entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    if ($allowed -notcontains $sid) { Fail "relay_install_drain_marker_acl_invalid" }
    if ($seen.ContainsKey($sid)) { Fail "relay_install_drain_marker_acl_invalid" }
    $seen[$sid] = $true
  }
  if ($seen.Count -ne 3) { Fail "relay_install_drain_marker_acl_invalid" }
  foreach ($sid in $allowed) {
    if (-not $seen.ContainsKey($sid)) { Fail "relay_install_drain_marker_acl_missing" }
  }
  $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if ($ownerSid -notin @("S-1-5-18", "S-1-5-32-544")) {
    Fail "relay_install_drain_marker_owner_invalid"
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
  param([Parameter(Mandatory = $true)][string]$ExistingTarget)
  $existingAgent = Get-SafeFullPath ([IO.Path]::Combine($InstallRoot, "mrd-relay-agent.exe")) -MustExist -Leaf
  $existingConfig = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, "config", "agent.json")) -MustExist -Leaf
  $existingManifestPath = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, "install-manifest.json")) -MustExist -Leaf
  $existingManifest = Get-Content -LiteralPath $existingManifestPath -Raw | ConvertFrom-Json
  Assert-SignedHash $existingAgent ([string]$existingManifest.agent_sha256) "relay_install_existing_agent"
  $random = New-Object byte[] 32
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($random) } finally { $rng.Dispose() }
  $challenge = (($random | ForEach-Object { $_.ToString("x2") }) -join "")
  [Array]::Clear($random, 0, $random.Length)
  $lines = @(& $existingAgent drain-proof --config $existingConfig --challenge $challenge 2>$null)
  if ($LASTEXITCODE -ne 0 -or $lines.Count -ne 1 -or
      [Text.Encoding]::UTF8.GetByteCount([string]$lines[0]) -gt 8192) {
    Fail "relay_install_upgrade_requires_broker_drain_proof"
  }
  $json = [string]$lines[0]
  try { $proof = $json | ConvertFrom-Json } catch { Fail "relay_install_drain_proof_json_invalid" }
  $expectedKeys = @(
    "schema_version", "scope", "target", "generation", "applied_secret_version",
    "draining", "active_allocations", "drain_completed", "challenge_sha256", "proof_sha256"
  )
  $actualKeys = @($proof.PSObject.Properties.Name | Sort-Object)
  if (($actualKeys -join "`n") -cne (($expectedKeys | Sort-Object) -join "`n") -or
      [regex]::Matches($json, '"[A-Za-z0-9_]+"\s*:').Count -ne $expectedKeys.Count) {
    Fail "relay_install_drain_proof_schema_invalid"
  }
  $expectedTarget = switch ($ExistingTarget) {
    "Native" { "windows-service" }
    "Docker" { "docker" }
    "Wsl2" { "wsl2" }
    default { Fail "relay_install_existing_target_invalid" }
  }
  if ($proof.schema_version -ne 1 -or $proof.scope -cne "local" -or
      $proof.target -cne $expectedTarget -or [int64]$proof.generation -le 0 -or
      [int64]$proof.applied_secret_version -le 0 -or $proof.draining -ne $true -or
      [int64]$proof.active_allocations -ne 0 -or $proof.drain_completed -ne $true -or
      $proof.challenge_sha256 -cne (Get-ChallengeHash $challenge) -or
      [string]$proof.proof_sha256 -notmatch '^[0-9a-f]{64}$') {
    Fail "relay_install_drain_proof_invalid"
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
    Fail "relay_install_drain_fence_changed"
  }
}

function Test-ExactDockerProductionSpec {
  param(
    [Parameter(Mandatory = $true)]$Container,
    [Parameter(Mandatory = $true)]$ExpectedMounts,
    [Parameter(Mandatory = $true)][int]$ExpectedTlsPort
  )
  try {
    $labelProperties = @($Container.Config.Labels.PSObject.Properties)
    if ($Container.Path -cne $DockerExpectedPath -or
        @($Container.Args).Count -ne 2 -or
        [string]$Container.Args[0] -cne $DockerExpectedArgs[0] -or
        [string]$Container.Args[1] -cne $DockerExpectedArgs[1] -or
        [string]$Container.Config.User -cne "65534:65534" -or
        $Container.HostConfig.Privileged -ne $false -or
        @($Container.HostConfig.CapAdd).Count -ne 0 -or
        @($Container.HostConfig.CapDrop).Count -ne 1 -or
        [string]$Container.HostConfig.CapDrop[0] -cne "ALL" -or
        $Container.HostConfig.NetworkMode -cne $DockerExpectedNetworkMode -or
        [string]$Container.HostConfig.PidMode -cne "" -or
        [string]$Container.HostConfig.IpcMode -cne "private" -or
        [string]$Container.HostConfig.UsernsMode -cne "" -or
        ($null -ne $Container.HostConfig.Devices -and @($Container.HostConfig.Devices).Count -ne 0) -or
        $Container.HostConfig.PublishAllPorts -ne $false -or
        @($Container.HostConfig.SecurityOpt).Count -ne 1 -or
        [string]$Container.HostConfig.SecurityOpt[0] -cne $DockerExpectedSecurityOpt -or
        $Container.HostConfig.ReadonlyRootfs -ne $true -or
        $Container.HostConfig.RestartPolicy.Name -cne "no" -or
        $labelProperties.Count -ne 1 -or
        $labelProperties[0].Name -cne "io.mrd.relay.managed" -or
        [string]$labelProperties[0].Value -cne "true") {
      return $false
    }
    if (@($Container.Mounts).Count -ne @($ExpectedMounts).Count) { return $false }
    foreach ($expectedMount in @($ExpectedMounts)) {
      $matches = @($Container.Mounts | Where-Object {
          $_.Type -ceq "bind" -and [string]$_.Source -ieq [string]$expectedMount.source -and
          $_.Destination -ceq [string]$expectedMount.destination -and $_.RW -eq $false
        })
      if ($matches.Count -ne 1) { return $false }
    }
    $expectedPorts = @{}
    foreach ($tuple in @(
        @("3478/udp", "", "3478"), @("3478/tcp", "", "3478"),
        @("$ExpectedTlsPort/tcp", "", "$ExpectedTlsPort"),
        @("9641/tcp", "127.0.0.1", "9641")
      )) { $expectedPorts[$tuple[0]] = @($tuple[1], $tuple[2]) }
    foreach ($protocol in @("tcp", "udp")) {
      foreach ($port in 49160..49260) { $expectedPorts["$port/$protocol"] = @("", "$port") }
    }
    $actualPortProperties = @($Container.HostConfig.PortBindings.PSObject.Properties)
    if ($actualPortProperties.Count -ne $expectedPorts.Count) { return $false }
    foreach ($property in $actualPortProperties) {
      if (-not $expectedPorts.ContainsKey($property.Name) -or @($property.Value).Count -ne 1 -or
          [string]$property.Value[0].HostIp -cne $expectedPorts[$property.Name][0] -or
          [string]$property.Value[0].HostPort -cne $expectedPorts[$property.Name][1]) {
        return $false
      }
    }
    return $true
  } catch {
    return $false
  }
}

function New-DockerProductionSpecFixture {
  param([Parameter(Mandatory = $true)]$ExpectedMounts, [int]$TlsPort = 5349)
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
  $mounts = @($ExpectedMounts | ForEach-Object {
      [pscustomobject]@{ Type = "bind"; Source = $_.source; Destination = $_.destination; RW = $false }
    })
  return [pscustomobject]@{
    Path = $DockerExpectedPath
    Args = @($DockerExpectedArgs)
    Config = [pscustomobject]@{
      User = "65534:65534"
      Labels = [pscustomobject]@{ 'io.mrd.relay.managed' = "true" }
    }
    HostConfig = [pscustomobject]@{
      Privileged = $false; CapAdd = @(); CapDrop = @("ALL")
      PidMode = ""; IpcMode = "private"; UsernsMode = ""; Devices = @(); PublishAllPorts = $false
      NetworkMode = $DockerExpectedNetworkMode; SecurityOpt = @($DockerExpectedSecurityOpt)
      ReadonlyRootfs = $true; RestartPolicy = [pscustomobject]@{ Name = "no" }
      PortBindings = [pscustomobject]$bindings
    }
    Mounts = $mounts
  }
}

function Assert-DockerProductionSpecSelfTest {
  $mounts = @(
    [pscustomobject]@{ source = "C:\MRD\docker-envelope"; destination = "/run/mrd/turnserver.conf" },
    [pscustomobject]@{ source = "C:\MRD\tls"; destination = "/run/mrd/tls" }
  )
  $good = New-DockerProductionSpecFixture $mounts
  if (-not (Test-ExactDockerProductionSpec $good $mounts 5349)) {
    Fail "relay_install_docker_spec_self_test_good_rejected"
  }
  $commandOverride = New-DockerProductionSpecFixture $mounts
  $commandOverride.Path = "/bin/sh"
  if (Test-ExactDockerProductionSpec $commandOverride $mounts 5349) {
    Fail "relay_install_docker_spec_self_test_command_override_accepted"
  }
  $extraCapability = New-DockerProductionSpecFixture $mounts
  $extraCapability.HostConfig.CapAdd = @("NET_ADMIN")
  if (Test-ExactDockerProductionSpec $extraCapability $mounts 5349) {
    Fail "relay_install_docker_spec_self_test_extra_capability_accepted"
  }
  $rootUser = New-DockerProductionSpecFixture $mounts
  $rootUser.Config.User = ""
  if (Test-ExactDockerProductionSpec $rootUser $mounts 5349) {
    Fail "relay_install_docker_spec_self_test_root_user_accepted"
  }
  $hostPid = New-DockerProductionSpecFixture $mounts
  $hostPid.HostConfig.PidMode = "host"
  if (Test-ExactDockerProductionSpec $hostPid $mounts 5349) {
    Fail "relay_install_docker_spec_self_test_host_pid_accepted"
  }
  $device = New-DockerProductionSpecFixture $mounts
  $device.HostConfig.Devices = @([pscustomobject]@{ PathOnHost = "C:\\\\device" })
  if (Test-ExactDockerProductionSpec $device $mounts 5349) {
    Fail "relay_install_docker_spec_self_test_device_accepted"
  }
  $nullDevices = New-DockerProductionSpecFixture $mounts
  $nullDevices.HostConfig.Devices = $null
  if (-not (Test-ExactDockerProductionSpec $nullDevices $mounts 5349)) {
    Fail "relay_install_docker_spec_self_test_null_devices_rejected"
  }
  foreach ($unsafeRoot in @("C:\MRD,Relay", "C:\MRD=Relay")) {
    $rejected = $false
    try { Assert-DockerMountSafeDataRoot $unsafeRoot } catch { $rejected = $true }
    if (-not $rejected) { Fail "relay_install_docker_mount_root_self_test_unsafe_accepted" }
  }
}

function Assert-TargetQuiescentForUpgrade {
  param(
    [Parameter(Mandatory = $true)][string]$ExistingTarget,
    [Parameter(Mandatory = $true)]$ExistingConfiguration
  )
  switch ($ExistingTarget) {
    "Native" {
      if (Test-ServiceExists $NativeCoturnServiceName) {
        $query = @(& sc.exe query $NativeCoturnServiceName 2>&1)
        if (($query -join "`n") -notmatch 'STATE\s*:\s*1\s+STOPPED') {
          Fail "relay_install_upgrade_requires_completed_drain"
        }
      }
    }
    "Docker" {
      if (-not [IO.File]::Exists($DockerExecutable)) { Fail "relay_install_docker_unavailable" }
      $identityPath = Get-SafeFullPath ([string]$ExistingConfiguration.expected_container_id_state_path) -MustExist -Leaf
      if ($identityPath -cne [IO.Path]::Combine($DataRoot, "broker", "docker-identity.json")) {
        Fail "relay_install_docker_identity_path_invalid"
      }
      Assert-BrokerOwnedFileAcl $identityPath
      $identity = Get-Content -LiteralPath $identityPath -Raw | ConvertFrom-Json
      $identityKeys = @($identity.PSObject.Properties.Name | Sort-Object)
      $expectedIdentityKeys = @(
        "container_id", "generation", "image_id", "image_reference", "schema_version", "target"
      ) | Sort-Object
      if (($identityKeys -join "`n") -cne ($expectedIdentityKeys -join "`n") -or
          $identity.schema_version -ne 1 -or $identity.target -cne "docker" -or
          [int64]$identity.generation -le 0 -or
          [string]$identity.container_id -notmatch '^[0-9a-f]{64}$' -or
          [string]$identity.image_id -notmatch '^sha256:[0-9a-f]{64}$' -or
          $identity.image_reference -cne $DockerImage) {
        Fail "relay_install_docker_identity_invalid"
      }
      $inspectResult = Invoke-BoundedNativeProcess $DockerExecutable `
        @("inspect", [string]$identity.container_id) 30000 65536 "Utf8" ([IO.Path]::Combine($DataRoot, "broker"))
      if ($inspectResult.ExitCode -ne 0) { Fail "relay_install_docker_bound_container_missing" }
      $containers = @(($inspectResult.StdOut | ConvertFrom-Json))
      if ($containers.Count -ne 1) { Fail "relay_install_docker_container_ambiguous" }
      $container = $containers[0]
      if ($container.Id -cne $identity.container_id -or
          $container.Image -cne $identity.image_id -or
          $container.Config.Image -cne $DockerImage -or
          $container.Name -cne "/$DockerContainerName" -or
          $container.Config.Labels.'io.mrd.relay.managed' -cne "true") {
        Fail "relay_install_docker_ownership_invalid"
      }
      if (-not (Test-ExactDockerProductionSpec $container $ExistingConfiguration.bind_mounts ([int]$ExistingConfiguration.tls_port))) {
        Fail "relay_install_docker_production_spec_invalid"
      }
      if ($container.State.Running -eq $true) { Fail "relay_install_upgrade_requires_completed_drain" }
      if ($container.HostConfig.RestartPolicy.Name -cne "no") { Fail "relay_install_docker_restart_policy_invalid" }
    }
    "Wsl2" {
      if ($ExistingConfiguration.distribution -cne $WslDistributionName -or
          $ExistingConfiguration.owner -cne "LocalSystem" -or
          $ExistingConfiguration.networking_mode -cne "mirrored") {
        Fail "relay_install_existing_wsl_target_invalid"
      }
    }
    default { Fail "relay_install_existing_target_invalid" }
  }
}

function Test-RunningWslDistribution {
  param(
    [Parameter(Mandatory = $true)]$Lines,
    [Parameter(Mandatory = $true)][string]$Distribution
  )
  foreach ($line in @($Lines)) {
    if ([string]$line -ceq $Distribution) { return $true }
  }
  return $false
}

function Get-RollbackTargetStopPlan {
  param([Parameter(Mandatory = $true)][ValidateSet("Native", "Docker", "Wsl2")][string]$CurrentTarget)
  return @(
    "StopAgent", "StopBroker", "StopExact$CurrentTarget", "VerifyExact$CurrentTarget`Stopped", "MoveRoots"
  )
}

function Assert-RollbackTargetStopPlanSelfTest {
  foreach ($candidate in @("Native", "Docker", "Wsl2")) {
    $plan = @(Get-RollbackTargetStopPlan $candidate)
    $stopIndex = [Array]::IndexOf($plan, "StopExact$candidate")
    $verifyIndex = [Array]::IndexOf($plan, "VerifyExact$candidate`Stopped")
    $moveIndex = [Array]::IndexOf($plan, "MoveRoots")
    if ($stopIndex -lt 0 -or $verifyIndex -le $stopIndex -or $moveIndex -le $verifyIndex) {
      Fail "relay_install_rollback_target_stop_plan_invalid"
    }
  }
}

function Assert-WslSystemContextSelfTest {
  if (-not (Test-IsLocalSystemSid "S-1-5-18")) {
    Fail "relay_install_wsl_system_context_self_test_rejected_system"
  }
  foreach ($untrustedSid in @("S-1-5-19", "S-1-5-20", "S-1-5-32-544", "s-1-5-18", "")) {
    if (Test-IsLocalSystemSid $untrustedSid) {
      Fail "relay_install_wsl_system_context_self_test_accepted_non_system"
    }
  }
}

function Assert-UpgradePhaseSelfTest {
  $plan = @(Get-UpgradeMutationPlan)
  $expected = @(
    "phase:before-stop-agent", "stop-agent",
    "phase:before-second-proof", "second-proof",
    "phase:before-stop-broker", "stop-broker",
    "phase:before-stop-target", "stop-target",
    "phase:before-move-roots", "move-roots"
  )
  if (($plan -join "`n") -cne ($expected -join "`n")) {
    Fail "relay_install_upgrade_phase_self_test_order_invalid"
  }
  foreach ($phase in @(
      "checkpointed", "before-stop-agent", "before-second-proof",
      "before-stop-broker", "before-stop-target", "before-move-roots"
    )) {
    if (Test-UpgradePhaseAllowsRootSwap $phase) {
      Fail "relay_install_upgrade_phase_self_test_early_root_swap_allowed"
    }
  }
  if (-not (Test-UpgradePhaseAllowsRootSwap "moving-program-root")) {
    Fail "relay_install_upgrade_phase_self_test_root_swap_rejected"
  }
  $unknownRejected = $false
  try { $null = Test-UpgradePhaseAllowsRootSwap "unknown" } catch { $unknownRejected = $true }
  if (-not $unknownRejected) { Fail "relay_install_upgrade_phase_self_test_unknown_accepted" }
}

function Assert-BoundedNativeProcessSelfTest {
  foreach ($unsafeArgument in @("line`nbreak", "nul$([char]0)byte", ("x" * 4097))) {
    $rejected = $false
    try { $null = ConvertTo-NativeCommandLineArgument $unsafeArgument } catch { $rejected = $true }
    if (-not $rejected) { Fail "relay_install_bounded_process_self_test_unsafe_argument_accepted" }
  }
  $captureRoot = [IO.Path]::Combine([IO.Path]::GetTempPath(), "mrd-relay-process-self-test-" + [Guid]::NewGuid().ToString("N"))
  [void][IO.Directory]::CreateDirectory($captureRoot)
  $utf16Fixture = [IO.Path]::Combine($captureRoot, "utf16le.fixture")
  $oddUtf16Fixture = [IO.Path]::Combine($captureRoot, "utf16le-odd.fixture")
  $nulUtf8Fixture = [IO.Path]::Combine($captureRoot, "utf8-nul.fixture")
  try {
    [IO.File]::WriteAllBytes(
      $utf16Fixture,
      (New-Object Text.UnicodeEncoding($false, $false, $true)).GetBytes("MRDRelay`r`n"))
    if ((Read-StrictNativeCapture $utf16Fixture "Utf16Le") -cne "MRDRelay`r`n") {
      Fail "relay_install_bounded_process_self_test_utf16le_decode_invalid"
    }
    [IO.File]::WriteAllBytes($oddUtf16Fixture, [byte[]]@(0x41, 0x00, 0x42))
    $oddRejected = $false
    try { $null = Read-StrictNativeCapture $oddUtf16Fixture "Utf16Le" } catch { $oddRejected = $true }
    if (-not $oddRejected) { Fail "relay_install_bounded_process_self_test_odd_utf16le_accepted" }
    [IO.File]::WriteAllBytes($nulUtf8Fixture, [byte[]]@(0x41, 0x00, 0x42))
    $nulRejected = $false
    try { $null = Read-StrictNativeCapture $nulUtf8Fixture "Utf8" } catch { $nulRejected = $true }
    if (-not $nulRejected) { Fail "relay_install_bounded_process_self_test_utf8_nul_accepted" }
    $hostExecutable = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $success = Invoke-BoundedNativeProcess $hostExecutable @(
      "-NoProfile", "-NonInteractive", "-Command",
      '[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false); [Console]::Out.Write("bounded-ok")'
    ) 5000 1024 "Utf8" $captureRoot
    if ($success.ExitCode -ne 0 -or $success.StdOut -cne "bounded-ok" -or $success.StdErr.Length -ne 0) {
      Fail "relay_install_bounded_process_self_test_success_invalid"
    }
    $timedOut = $false
    try {
      $null = Invoke-BoundedNativeProcess $hostExecutable @(
        "-NoProfile", "-NonInteractive", "-Command",
        '[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false); Start-Sleep -Seconds 2'
      ) 100 1024 "Utf8" $captureRoot
    } catch {
      if ($_.Exception.Message -eq "relay_install_external_process_timeout") { $timedOut = $true }
    }
    if (-not $timedOut) { Fail "relay_install_bounded_process_self_test_timeout_not_rejected" }
    $oversized = $false
    try {
      $null = Invoke-BoundedNativeProcess $hostExecutable @(
        "-NoProfile", "-NonInteractive", "-Command",
        '[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false); [Console]::Out.Write(("x" * 2048))'
      ) 5000 128 "Utf8" $captureRoot
    } catch {
      if ($_.Exception.Message -eq "relay_install_external_process_output_too_large") { $oversized = $true }
    }
    if (-not $oversized) { Fail "relay_install_bounded_process_self_test_oversize_not_rejected" }
  } finally {
    foreach ($fixturePath in @($utf16Fixture, $oddUtf16Fixture, $nulUtf8Fixture)) {
      if ([IO.File]::Exists($fixturePath)) { Remove-Item -LiteralPath $fixturePath -Force }
    }
    if ([IO.Directory]::Exists($captureRoot)) { Remove-Item -LiteralPath $captureRoot -Force }
  }
}

function Assert-DeploymentLockSelfTest {
  $expectedRoot = [IO.Path]::GetFullPath(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
  ).TrimEnd([IO.Path]::DirectorySeparatorChar)
  $expectedPath = [IO.Path]::Combine($expectedRoot, "MRD", ".mrd-relay-deploy.lock")
  $savedProgramData = $env:ProgramData
  try {
    $env:ProgramData = "C:\attacker-controlled-programdata"
    if ((Get-DeploymentLockPath) -cne $expectedPath) {
      Fail "relay_install_lock_self_test_environment_path_accepted"
    }
  } finally {
    $env:ProgramData = $savedProgramData
  }

  $directory = [IO.Path]::Combine([IO.Path]::GetTempPath(), "mrd-install-lock-" + [Guid]::NewGuid().ToString("N"))
  [void][IO.Directory]::CreateDirectory($directory)
  $lockPath = [IO.Path]::Combine($directory, "deployment.lock")
  $readyPath = [IO.Path]::Combine($directory, "ready")
  $holderPath = [IO.Path]::Combine($directory, "hold-lock.ps1")
  [IO.File]::WriteAllText($lockPath, "MRD relay deployment lock v1`n", (New-Object Text.UTF8Encoding($false)))
  $holderScript = @'
param([string]$LockPath, [string]$ReadyPath)
$stream = [IO.File]::Open($LockPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
try {
  [IO.File]::WriteAllText($ReadyPath, "ready")
  Start-Sleep -Seconds 30
} finally {
  $stream.Dispose()
}
'@
  [IO.File]::WriteAllText($holderPath, $holderScript, (New-Object Text.UTF8Encoding($false)))
  $hostExecutable = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
  $holderArguments = @(
    "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $holderPath,
    "-LockPath", $lockPath, "-ReadyPath", $readyPath
  )
  $startInfo = New-Object Diagnostics.ProcessStartInfo
  $startInfo.FileName = $hostExecutable
  $startInfo.Arguments = (@($holderArguments | ForEach-Object {
        ConvertTo-NativeCommandLineArgument ([string]$_)
      }) -join " ")
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $holder = New-Object Diagnostics.Process
  $holder.StartInfo = $startInfo
  $holderStarted = $false
  $reacquired = $null
  try {
    $holderStarted = $holder.Start()
    if (-not $holderStarted) { Fail "relay_install_lock_self_test_holder_failed" }
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    while (-not [IO.File]::Exists($readyPath) -and $deadline.ElapsedMilliseconds -lt 5000 -and
        -not $holder.HasExited) {
      Start-Sleep -Milliseconds 10
    }
    if (-not [IO.File]::Exists($readyPath) -or $holder.HasExited) {
      Fail "relay_install_lock_self_test_holder_failed"
    }
    $busyRejected = $false
    try {
      $second = Open-ExclusiveDeploymentFileLock $lockPath.ToUpperInvariant()
      $second.Dispose()
    } catch {
      $busyRejected = ($_.Exception.Message -ceq "relay_install_transaction_busy")
    }
    if (-not $busyRejected) { Fail "relay_install_lock_self_test_parallel_writer_accepted" }
    $holder.Kill()
    if (-not $holder.WaitForExit(5000)) { Fail "relay_install_lock_self_test_holder_kill_failed" }
    $reacquired = Open-ExclusiveDeploymentFileLock $lockPath
    Assert-DeploymentLockStreamContent $reacquired
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

  $source = [IO.File]::ReadAllText($PSCommandPath)
  $boundaryFunctionStart = $source.IndexOf('function Initialize-MachineDeploymentLockBoundary')
  $boundaryFunctionEnd = $source.IndexOf('function Initialize-DeploymentLockFileIfMissing', $boundaryFunctionStart)
  if ($boundaryFunctionStart -lt 0 -or $boundaryFunctionEnd -le $boundaryFunctionStart) {
    Fail "relay_install_lock_self_test_boundary_function_missing"
  }
  $boundaryFunction = $source.Substring(
    $boundaryFunctionStart, $boundaryFunctionEnd - $boundaryFunctionStart)
  if (-not $boundaryFunction.Contains('[IO.Directory]::Move($temporary, $boundary)') -or
      -not $boundaryFunction.Contains('GetFileSystemInfos().Count') -or
      $boundaryFunction.Contains('Set-SystemAdminDirectoryAcl $boundary')) {
    Fail "relay_install_lock_self_test_existing_boundary_reowned"
  }
  $approvalIndex = $source.LastIndexOf('if (-not $PSCmdlet.ShouldProcess($InstallRoot')
  $boundaryIndex = $source.LastIndexOf('Initialize-MachineDeploymentLockBoundary')
  $enterIndex = $source.LastIndexOf('$deploymentLock = Enter-DeploymentTransactionLock')
  $classificationIndex = $source.LastIndexOf('$existingTargetPath = [IO.Path]::Combine(')
  $snapshotIndex = $source.LastIndexOf('$agentServiceExisted = Test-ServiceExists')
  $checkpointIndex = $source.LastIndexOf('$checkpoint = [ordered]@{')
  $stopIndex = $source.LastIndexOf('Stop-ExactService $AgentServiceName')
  $releaseIndex = $source.LastIndexOf('$deploymentLock.Dispose()')
  if ($approvalIndex -lt 0 -or $boundaryIndex -le $approvalIndex -or
      $enterIndex -le $boundaryIndex -or $classificationIndex -le $enterIndex -or
      $snapshotIndex -le $classificationIndex -or
      $checkpointIndex -le $snapshotIndex -or $stopIndex -le $enterIndex -or
      $releaseIndex -le $stopIndex) {
    Fail "relay_install_lock_self_test_source_order_invalid"
  }
}

function Stop-ChangedTargetForRollback {
  param(
    [Parameter(Mandatory = $true)][ValidateSet("Native", "Docker", "Wsl2")][string]$CurrentTarget,
    [Parameter(Mandatory = $true)][string]$RelayDataRoot
  )
  try {
    switch ($CurrentTarget) {
      "Native" {
        Stop-ExactService $NativeCoturnServiceName
        if (Test-ServiceRunning $NativeCoturnServiceName) {
          Fail "relay_install_rollback_target_still_running"
        }
      }
      "Docker" {
        $targetPath = Get-SafeFullPath ([IO.Path]::Combine($RelayDataRoot, "broker", "target.json")) -MustExist -Leaf
        $identityPath = Get-SafeFullPath ([IO.Path]::Combine($RelayDataRoot, "broker", "docker-identity.json")) -MustExist -Leaf
        $manifestPath = Get-SafeFullPath ([IO.Path]::Combine($RelayDataRoot, "install-manifest.json")) -MustExist -Leaf
        Assert-BrokerOwnedFileAcl $targetPath
        Assert-BrokerOwnedFileAcl $identityPath
        Assert-ExactSystemAdminFileAcl $manifestPath
        $configuration = Get-Content -LiteralPath $targetPath -Raw | ConvertFrom-Json
        $identity = Get-Content -LiteralPath $identityPath -Raw | ConvertFrom-Json
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        if ([string]$configuration.target -cne "Docker" -or [string]$manifest.target -cne "Docker" -or
            [string]$identity.container_id -notmatch '^[0-9a-f]{64}$' -or
            [string]$manifest.target_manager_sha256 -notmatch '^[0-9a-f]{64}$') {
          Fail "relay_install_rollback_docker_identity_invalid"
        }
        $dockerPath = Get-SafeFullPath ([string]$configuration.docker_executable) -MustExist -Leaf
        Assert-SignedHash $dockerPath ([string]$manifest.target_manager_sha256) "relay_install_rollback_docker"
        $inspectResult = Invoke-BoundedNativeProcess $dockerPath `
          @("inspect", [string]$identity.container_id) 30000 65536 "Utf8" ([IO.Path]::Combine($RelayDataRoot, "broker"))
        if ($inspectResult.ExitCode -ne 0) {
          Fail "relay_install_rollback_docker_inspect_failed"
        }
        $containers = @(($inspectResult.StdOut | ConvertFrom-Json))
        if ($containers.Count -ne 1 -or $containers[0].Id -cne [string]$identity.container_id -or
            $containers[0].Image -cne [string]$identity.image_id -or
            $containers[0].Config.Image -cne $DockerImage -or
            $containers[0].Name -cne "/$DockerContainerName" -or
            -not (Test-ExactDockerProductionSpec $containers[0] $configuration.bind_mounts ([int]$configuration.tls_port))) {
          Fail "relay_install_rollback_docker_ownership_invalid"
        }
        if ($containers[0].State.Running -eq $true) {
          $stopResult = Invoke-BoundedNativeProcess $dockerPath `
            @("stop", "--time", "30", [string]$identity.container_id) 40000 8192 "Utf8" ([IO.Path]::Combine($RelayDataRoot, "broker"))
          if ($stopResult.ExitCode -ne 0) {
            Fail "relay_install_rollback_target_stop_failed"
          }
        }
        $readBackResult = Invoke-BoundedNativeProcess $dockerPath `
          @("inspect", [string]$identity.container_id) 30000 65536 "Utf8" ([IO.Path]::Combine($RelayDataRoot, "broker"))
        if ($readBackResult.ExitCode -ne 0) {
          Fail "relay_install_rollback_docker_inspect_failed"
        }
        $readBack = @(($readBackResult.StdOut | ConvertFrom-Json))
        if ($readBack.Count -ne 1 -or $readBack[0].Id -cne [string]$identity.container_id -or
            $readBack[0].State.Running -ne $false -or
            -not (Test-ExactDockerProductionSpec $readBack[0] $configuration.bind_mounts ([int]$configuration.tls_port))) {
          Fail "relay_install_rollback_target_still_running"
        }
      }
      "Wsl2" {
        Assert-CurrentProcessIsLocalSystem
        $targetPath = Get-SafeFullPath ([IO.Path]::Combine($RelayDataRoot, "broker", "target.json")) -MustExist -Leaf
        $manifestPath = Get-SafeFullPath ([IO.Path]::Combine($RelayDataRoot, "install-manifest.json")) -MustExist -Leaf
        Assert-BrokerOwnedFileAcl $targetPath
        Assert-ExactSystemAdminFileAcl $manifestPath
        $configuration = Get-Content -LiteralPath $targetPath -Raw | ConvertFrom-Json
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        if ([string]$configuration.target -cne "Wsl2" -or
            [string]$configuration.distribution -cne $WslDistributionName -or
            [string]$manifest.target -cne "Wsl2" -or
            [string]$manifest.target_manager_sha256 -notmatch '^[0-9a-f]{64}$') {
          Fail "relay_install_rollback_wsl_identity_invalid"
        }
        $wslPath = Get-SafeFullPath ([string]$configuration.wsl_executable) -MustExist -Leaf
        Assert-SignedHash $wslPath ([string]$manifest.target_manager_sha256) "relay_install_rollback_wsl"
        $terminateResult = Invoke-BoundedNativeProcess $wslPath `
          @("--terminate", $WslDistributionName) 30000 8192 "Utf16Le" ([IO.Path]::Combine($RelayDataRoot, "broker"))
        if ($terminateResult.ExitCode -ne 0) {
          Fail "relay_install_rollback_target_stop_failed"
        }
        $runningResult = Invoke-BoundedNativeProcess $wslPath `
          @("--list", "--running", "--quiet") 15000 8192 "Utf16Le" ([IO.Path]::Combine($RelayDataRoot, "broker"))
        if ($runningResult.ExitCode -ne 0 -or
            (Test-RunningWslDistribution @($runningResult.StdOut -split "`r?`n") $WslDistributionName)) {
          Fail "relay_install_rollback_target_still_running"
        }
      }
    }
  } catch {
    if ($_.Exception.Message -match '^relay_install_rollback_target_') { throw }
    Fail "relay_install_rollback_target_stop_failed"
  }
}

function Assert-UpgradeStateAvailable {
  param([Parameter(Mandatory = $true)][string]$ExistingTarget)
  $requiredRelativePaths = @(
    "state\identity.json",
    "state\runtime.json",
    "broker\active-turn-secret.dpapi",
    "broker\control-state.dpapi",
    "broker\control-journal.dpapi"
  )
  if ($ExistingTarget -ceq "Docker") {
    $requiredRelativePaths += "broker\docker-identity.json"
    $requiredRelativePaths += "broker\docker-envelope"
  }
  foreach ($relativePath in $requiredRelativePaths) {
    $path = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, $relativePath)) -MustExist -Leaf
    if ($relativePath -ceq "broker\docker-envelope") {
      Assert-BrokerOwnedFileAcl $path
      continue
    }
    if ((Get-Item -LiteralPath $path -Force).Length -le 0) {
      Fail "relay_install_upgrade_state_invalid"
    }
  }
}

function Preserve-UpgradeState {
  param(
    [Parameter(Mandatory = $true)][string]$BackupDataRoot,
    [Parameter(Mandatory = $true)][string]$DestinationDataRoot,
    [Parameter(Mandatory = $true)][string]$ExistingTarget
  )
  $relativePaths = @(
    "state\identity.json",
    "state\runtime.json",
    "broker\active-turn-secret.dpapi",
    "broker\control-state.dpapi",
    "broker\control-journal.dpapi"
  )
  if ($ExistingTarget -ceq "Docker") {
    $relativePaths += "broker\docker-identity.json"
    $relativePaths += "broker\docker-envelope"
  }
  foreach ($relativePath in $relativePaths) {
    $source = Get-SafeFullPath ([IO.Path]::Combine($BackupDataRoot, $relativePath)) -MustExist -Leaf
    $destination = Get-SafeFullPath ([IO.Path]::Combine($DestinationDataRoot, $relativePath))
    Copy-Item -LiteralPath $source -Destination $destination
  }
}

function Write-ProtectedUpgradeCheckpoint {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][Collections.IDictionary]$Checkpoint
  )
  $safePath = Get-SafeFullPath $Path
  $temporaryPath = $safePath + "." + [Guid]::NewGuid().ToString("N") + ".pending"
  $encoding = New-Object Text.UTF8Encoding($false)
  try {
    [IO.File]::WriteAllText(
      $temporaryPath,
      ($Checkpoint | ConvertTo-Json -Depth 8 -Compress) + "`n",
      $encoding
    )
    $null = & icacls.exe $temporaryPath "/setowner" "BUILTIN\Administrators"
    if ($LASTEXITCODE -ne 0) { Fail "relay_install_recovery_manifest_owner_failed" }
    $null = & icacls.exe $temporaryPath "/inheritance:r" "/grant:r" `
      "SYSTEM:(F)" "BUILTIN\Administrators:(F)"
    if ($LASTEXITCODE -ne 0) { Fail "relay_install_recovery_manifest_acl_failed" }
    if ([IO.File]::Exists($safePath)) {
      [IO.File]::Replace($temporaryPath, $safePath, $null, $true)
    } else {
      Move-Item -LiteralPath $temporaryPath -Destination $safePath
    }
    Assert-ExactSystemAdminFileAcl $safePath
  } finally {
    if ([IO.File]::Exists($temporaryPath)) { Remove-Item -LiteralPath $temporaryPath -Force }
  }
}

function Set-UpgradeTransactionPhase {
  param(
    [Parameter(Mandatory = $true)][Collections.IDictionary]$Checkpoint,
    [Parameter(Mandatory = $true)][string]$CheckpointPath,
    [Parameter(Mandatory = $true)][string]$Phase
  )
  $null = Test-UpgradePhaseAllowsRootSwap $Phase
  $Checkpoint["transaction_phase"] = $Phase
  $Checkpoint["phase_updated_at_utc"] = [DateTime]::UtcNow.ToString("o")
  Write-ProtectedUpgradeCheckpoint $CheckpointPath $Checkpoint
}

function Set-RecordedServiceRunStates {
  param([Parameter(Mandatory = $true)]$ServiceState)
  foreach ($entry in @(
      @($NativeCoturnServiceName, [bool]$ServiceState.native_existed, [bool]$ServiceState.native_running),
      @($BrokerServiceName, [bool]$ServiceState.broker_existed, [bool]$ServiceState.broker_running),
      @($AgentServiceName, [bool]$ServiceState.agent_existed, [bool]$ServiceState.agent_running)
    )) {
    $name = [string]$entry[0]
    $existed = [bool]$entry[1]
    $wasRunning = [bool]$entry[2]
    if (-not $existed) {
      if (Test-ServiceExists $name) { Fail "relay_install_rollback_unexpected_service" }
      continue
    }
    if (-not (Test-ServiceExists $name)) { Fail "relay_install_rollback_service_missing" }
    if (-not $wasRunning) {
      Stop-ExactService $name
      continue
    }
    if (-not (Test-ServiceRunning $name)) { $null = Invoke-Sc @("start", $name) }
    $running = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
      if (Test-ServiceRunning $name) { $running = $true; break }
      Start-Sleep -Milliseconds 500
    }
    if (-not $running) { Fail "relay_install_rollback_service_start_timeout" }
  }
}

function Restore-UpgradeCheckpoint {
  param(
    [Parameter(Mandatory = $true)][string]$CheckpointDirectory,
    [Parameter(Mandatory = $true)][string]$ProgramRoot,
    [Parameter(Mandatory = $true)][string]$RelayDataRoot,
    [Parameter(Mandatory = $true)]$ServiceState,
    [Parameter(Mandatory = $true)]$FirewallRules,
    [Parameter(Mandatory = $true)][string]$TransactionPhase
  )
  $rootRestoreAllowed = Test-UpgradePhaseAllowsRootSwap $TransactionPhase
  Stop-ExactService $AgentServiceName
  Stop-ExactService $BrokerServiceName
  if ([bool]$ServiceState.target_may_have_changed) {
    # A failed fresh/changed target may still own public listeners or Docker
    # bind mounts.  Unknown identity or an unverified stop keeps the protected
    # checkpoint in place and aborts before any root is moved.
    Stop-ChangedTargetForRollback ([string]$ServiceState.target) $RelayDataRoot
  }
  if (-not $rootRestoreAllowed) {
    Set-RecordedServiceRunStates $ServiceState
    return
  }
  $failedRoot = [IO.Path]::Combine($CheckpointDirectory, "failed-" + [Guid]::NewGuid().ToString("N"))
  [void][IO.Directory]::CreateDirectory($failedRoot)
  Set-SystemAdminDirectoryAcl $failedRoot
  $programBackup = [IO.Path]::Combine($CheckpointDirectory, "program")
  $dataBackup = [IO.Path]::Combine($CheckpointDirectory, "data")
  if ([IO.Directory]::Exists($programBackup)) {
    if ([IO.Directory]::Exists($ProgramRoot)) {
      Move-Item -LiteralPath $ProgramRoot -Destination ([IO.Path]::Combine($failedRoot, "program"))
    }
    Move-Item -LiteralPath $programBackup -Destination $ProgramRoot
  } elseif (-not $ServiceState.program_root_existed -and [IO.Directory]::Exists($ProgramRoot)) {
    Move-Item -LiteralPath $ProgramRoot -Destination ([IO.Path]::Combine($failedRoot, "program"))
  }
  if ([IO.Directory]::Exists($dataBackup)) {
    if ([IO.Directory]::Exists($RelayDataRoot)) {
      Move-Item -LiteralPath $RelayDataRoot -Destination ([IO.Path]::Combine($failedRoot, "data"))
    }
    Move-Item -LiteralPath $dataBackup -Destination $RelayDataRoot
  } elseif (-not $ServiceState.data_root_existed -and [IO.Directory]::Exists($RelayDataRoot)) {
    Move-Item -LiteralPath $RelayDataRoot -Destination ([IO.Path]::Combine($failedRoot, "data"))
  }
  foreach ($ruleName in @(
      "MRD Relay TURN UDP 3478", "MRD Relay TURN TCP 3478", "MRD Relay TURN TLS TCP",
      "MRD Relay Range UDP", "MRD Relay Range TCP"
    )) {
    foreach ($rule in @(Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
      Remove-NetFirewallRule -InputObject $rule
    }
  }
  foreach ($rule in @($FirewallRules)) {
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
  foreach ($entry in @(
      @($AgentServiceName, [bool]$ServiceState.agent_existed),
      @($BrokerServiceName, [bool]$ServiceState.broker_existed),
      @($NativeCoturnServiceName, [bool]$ServiceState.native_existed)
    )) {
    if (-not $entry[1] -and (Test-ServiceExists $entry[0])) {
      $null = & sc.exe delete $entry[0] 2>&1
      if ($LASTEXITCODE -ne 0) { Fail "relay_install_rollback_scm_delete_failed" }
    }
  }
  foreach ($serviceName in @($ServiceState.scm_snapshots.Keys)) {
    Restore-ExactScmSnapshot $ServiceState.scm_snapshots[$serviceName]
  }
  if ([bool]$ServiceState.previous_target_existed) {
    Stop-ChangedTargetForRollback ([string]$ServiceState.target) $RelayDataRoot
  }
  Set-RecordedServiceRunStates $ServiceState
}

Assert-PublicIpClassifierVectors
if ($SelfTest) {
  Assert-AncestorAclRuleSelfTest
  Assert-RecoveryRootPolicySelfTest
  Assert-DockerProductionSpecSelfTest
  Assert-DockerEnvelopePlaceholderSelfTest
  Assert-ScmSnapshotSelfTest
  Assert-RollbackTargetStopPlanSelfTest
  Assert-WslSystemContextSelfTest
  Assert-UpgradePhaseSelfTest
  Assert-BoundedNativeProcessSelfTest
  Assert-DeploymentLockSelfTest
  if (Test-WslInstallDisposition "Wsl2" $false) {
    Fail "relay_install_wsl_fresh_self_test_accepted"
  }
  if (-not (Test-WslInstallDisposition "Wsl2" $true)) {
    Fail "relay_install_wsl_upgrade_self_test_rejected"
  }
  Write-Output "relay_install_public_ip_self_test_passed"
  exit 0
}
Assert-Administrator

$AgentBinary = Get-SafeFullPath $AgentBinary -MustExist -Leaf
$BrokerBinary = Get-SafeFullPath $BrokerBinary -MustExist -Leaf
$OpenSslExecutable = Get-SafeFullPath $OpenSslExecutable -MustExist -Leaf
$AgentConfig = Get-SafeFullPath $AgentConfig -MustExist -Leaf
$EnrollmentTokenFile = Get-SafeFullPath $EnrollmentTokenFile -MustExist -Leaf
$TurnSecretFile = Get-SafeFullPath $TurnSecretFile -MustExist -Leaf
$TrustedCaFile = Get-SafeFullPath $TrustedCaFile -MustExist -Leaf
$TlsCertificateFile = Get-SafeFullPath $TlsCertificateFile -MustExist -Leaf
$TlsPrivateKeyFile = Get-SafeFullPath $TlsPrivateKeyFile -MustExist -Leaf
$InstallRoot = Get-SafeFullPath $InstallRoot
$DataRoot = Get-SafeFullPath $DataRoot
$RecoveryRoot = Get-SafeFullPath $RecoveryRoot
Assert-DisjointManagedRoots @($InstallRoot, $DataRoot, $RecoveryRoot)
if ($Target -ceq "Docker") { Assert-DockerMountSafeDataRoot $DataRoot }
foreach ($destination in @($InstallRoot, $DataRoot, $RecoveryRoot)) {
  Assert-DestinationParentPlan $destination
  Assert-TrustedDestinationAncestors $destination
}

if ($Realm -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$' -or
    $ServerName -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$') {
  Fail "relay_install_turn_dns_name_invalid"
}
$mappingFailure = Get-RelayMappingFailure $ExternalIp $RelayIp
if ($null -ne $mappingFailure) { Fail $mappingFailure }
$expectedListeningIp = Get-ExpectedListeningIp $ExternalIp

foreach ($source in @(
    $AgentConfig, $EnrollmentTokenFile, $TurnSecretFile, $TrustedCaFile,
    $TlsCertificateFile, $TlsPrivateKeyFile
  )) {
  Assert-ProtectedSource $source
}
Assert-SignedHash $AgentBinary $AgentSha256 "relay_install_agent"
Assert-SignedHash $BrokerBinary $BrokerSha256 "relay_install_broker"
Assert-SignedHash $OpenSslExecutable $OpenSslSha256 "relay_install_openssl"

$enrollmentBytes = [IO.File]::ReadAllBytes($EnrollmentTokenFile)
try {
  if ($enrollmentBytes.Length -lt 40 -or $enrollmentBytes.Length -gt 512) {
    Fail "relay_install_enrollment_token_size_invalid"
  }
  foreach ($byte in $enrollmentBytes) {
    if ($byte -lt 0x21 -or $byte -gt 0x7e) { Fail "relay_install_enrollment_token_invalid" }
  }
} finally {
  [Array]::Clear($enrollmentBytes, 0, $enrollmentBytes.Length)
}
$turnBytes = [IO.File]::ReadAllBytes($TurnSecretFile)
try {
  if ($turnBytes.Length -ne 43) { Fail "relay_install_turn_secret_invalid" }
  foreach ($byte in $turnBytes) {
    $valid = ($byte -ge 0x41 -and $byte -le 0x5a) -or
      ($byte -ge 0x61 -and $byte -le 0x7a) -or
      ($byte -ge 0x30 -and $byte -le 0x39) -or $byte -eq 0x5f -or $byte -eq 0x2d
    if (-not $valid) { Fail "relay_install_turn_secret_invalid" }
  }
} finally {
  [Array]::Clear($turnBytes, 0, $turnBytes.Length)
}

$certificateCheck = @(& $OpenSslExecutable x509 -in $TlsCertificateFile -noout -checkend 86400 2>&1)
if ($LASTEXITCODE -ne 0) { Fail "relay_install_tls_certificate_invalid_or_expiring" }
$certificatePublicKey = @(& $OpenSslExecutable x509 -in $TlsCertificateFile -pubkey -noout 2>&1)
if ($LASTEXITCODE -ne 0 -or $certificatePublicKey.Count -eq 0) {
  Fail "relay_install_tls_certificate_public_key_invalid"
}
$privatePublicKey = @(& $OpenSslExecutable pkey -in $TlsPrivateKeyFile -passin pass: -pubout 2>&1)
if ($LASTEXITCODE -ne 0 -or $privatePublicKey.Count -eq 0) {
  Fail "relay_install_tls_private_key_invalid_or_encrypted"
}
$normalizedCertificatePublicKey = (($certificatePublicKey | ForEach-Object { $_.Trim() }) -join "`n").Trim()
$normalizedPrivatePublicKey = (($privatePublicKey | ForEach-Object { $_.Trim() }) -join "`n").Trim()
if ($normalizedCertificatePublicKey -cne $normalizedPrivatePublicKey) {
  Fail "relay_install_tls_key_mismatch"
}
Remove-Variable certificateCheck, certificatePublicKey, privatePublicKey, `
  normalizedCertificatePublicKey, normalizedPrivatePublicKey -ErrorAction SilentlyContinue

$sourceConfig = Get-Content -LiteralPath $AgentConfig -Raw | ConvertFrom-Json
$sourceKeys = @($sourceConfig.PSObject.Properties.Name)
foreach ($key in $sourceKeys) {
  if ($ExpectedSourceConfigKeys -notcontains $key) { Fail "relay_install_config_unknown" }
}
if ($sourceKeys.Count -ne $ExpectedSourceConfigKeys.Count) {
  Fail "relay_install_config_missing"
}
foreach ($key in $ExpectedSourceConfigKeys) {
  if ($sourceKeys -notcontains $key) { Fail "relay_install_config_missing" }
}
$maxAllocations = [int64]$sourceConfig.max_allocations
$maxEgressBps = [int64]$sourceConfig.max_egress_bps
if ($maxAllocations -lt 1 -or $maxAllocations -gt 100) { Fail "relay_install_capacity_invalid" }
if ($maxEgressBps -le 0 -or ($maxEgressBps % 8) -ne 0) { Fail "relay_install_bandwidth_not_byte_aligned" }
$coturnCapacityBytesPerSecond = [int64]($maxEgressBps / 8)

$transportSet = @{}
$dockerPublishedPortSet = @{}
$productionDockerPorts = New-Object Collections.ArrayList
foreach ($endpoint in @($sourceConfig.endpoints)) {
  if ($endpoint -isnot [string]) { Fail "relay_install_endpoint_invalid" }
  $match = [regex]::Match(
    $endpoint,
    '^(turn|turns):(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):([0-9]{1,5})(?:\?transport=(udp|tcp))?$'
  )
  if (-not $match.Success) { Fail "relay_install_endpoint_invalid" }
  $scheme = $match.Groups[1].Value
  $endpointHost = $match.Groups[2].Value.Trim('[', ']')
  if ($endpointHost -ine $ServerName) { Fail "relay_install_endpoint_server_name_mismatch" }
  $endpointAddress = $null
  if ([Net.IPAddress]::TryParse($endpointHost, [ref]$endpointAddress)) {
    $publicAddress = $null
    if (-not [Net.IPAddress]::TryParse($ExternalIp.Split('/', 2)[0], [ref]$publicAddress) -or
        $endpointAddress.AddressFamily -ne $publicAddress.AddressFamily) {
      Fail "relay_install_endpoint_listener_family_mismatch"
    }
  }
  $endpointPort = [int]$match.Groups[3].Value
  if ($endpointPort -lt 1 -or $endpointPort -gt 65535) { Fail "relay_install_endpoint_invalid" }
  if (($scheme -ceq "turn" -and $endpointPort -ne 3478) -or
      ($scheme -ceq "turns" -and $endpointPort -ne $TlsPort)) {
    Fail "relay_install_endpoint_listener_port_mismatch"
  }
  $transport = $match.Groups[4].Value
  if ([string]::IsNullOrEmpty($transport)) {
    $transport = if ($scheme -ceq "turns") { "tcp" } else { "udp" }
  }
  if ($scheme -ceq "turns" -and $transport -cne "tcp") {
    Fail "relay_install_endpoint_invalid"
  }
  $capability = if ($scheme -ceq "turns") {
    "turns_tcp"
  } elseif ($transport -ceq "udp") {
    "turn_udp"
  } else {
    "turn_tcp"
  }
  $transportSet[$capability] = $true
  $portKey = "$endpointPort/$transport"
  if (-not $dockerPublishedPortSet.ContainsKey($portKey)) {
    [void]$productionDockerPorts.Add([ordered]@{
      host_port = $endpointPort
      container_port = $endpointPort
      protocol = $transport
    })
    $dockerPublishedPortSet[$portKey] = $true
  }
}
$transportCapabilities = @("turn_udp", "turn_tcp", "turns_tcp" | Where-Object { $transportSet.ContainsKey($_) })
if (($transportCapabilities -join ",") -cne "turn_udp,turn_tcp,turns_tcp") {
  Fail "relay_install_transport_capabilities_incomplete"
}
if ($coturnCapacityBytesPerSecond -lt 25000000) {
  Fail "relay_install_per_allocation_bandwidth_invalid"
}

$turnBaselineSource = Get-SafeFullPath ([IO.Path]::Combine($PSScriptRoot, "..", "turnserver.conf.example")) -MustExist -Leaf
$allowedTurnKeys = @(
  "listening-port", "tls-listening-port", "listening-ip", "fingerprint", "realm",
  "server-name", "use-auth-secret", "static-auth-secret", "rest-api-separator",
  "unauthorized-ratelimit", "unauthorized-ratelimit-rps", "user-quota", "total-quota",
  "max-bps", "bps-capacity", "min-port", "max-port", "stale-nonce",
  "max-allocate-timeout", "max-allocate-lifetime", "cert", "pkey", "no-tlsv1",
  "no-tlsv1_1", "denied-peer-ip", "no-multicast-peers", "no-cli", "no-rfc5780",
  "no-software-attribute", "prometheus", "prometheus-address", "prometheus-port",
  "prometheus-path", "drain-min-allocations", "simple-log", "log-file"
)
$turnSeen = @{}
$deniedPeerCount = 0
$externalPlaceholderCount = 0
$relayPlaceholderCount = 0
$sourceBaselineLines = @(Get-Content -LiteralPath $turnBaselineSource)
foreach ($rawLine in $sourceBaselineLines) {
  $line = $rawLine.Trim()
  if ($line -ceq "# external-ip=CHANGE_ME_PUBLIC_IP/CHANGE_ME_PRIVATE_IP") {
    $externalPlaceholderCount++
    continue
  }
  if ($line -ceq "# relay-ip=CHANGE_ME_PRIVATE_OR_PUBLIC_IP") {
    $relayPlaceholderCount++
    continue
  }
  if ([string]::IsNullOrEmpty($line) -or $line.StartsWith("#")) { continue }
  $turnKey = $line.Split('=', 2)[0]
  if ($allowedTurnKeys -notcontains $turnKey) { Fail "relay_install_turn_baseline_unknown" }
  if ($turnKey -ceq "denied-peer-ip") {
    $deniedPeerCount++
  } elseif ($turnSeen.ContainsKey($turnKey)) {
    Fail "relay_install_turn_baseline_duplicate"
  }
  $turnSeen[$turnKey] = $true
}
foreach ($requiredTurnKey in $allowedTurnKeys) {
  if ($requiredTurnKey -cne "denied-peer-ip" -and -not $turnSeen.ContainsKey($requiredTurnKey)) {
    Fail "relay_install_turn_baseline_missing"
  }
}
if ($deniedPeerCount -ne 12 -or $externalPlaceholderCount -ne 1 -or $relayPlaceholderCount -ne 1) {
  Fail "relay_install_turn_baseline_peer_or_ip_contract_invalid"
}
foreach ($requiredSourceLine in @(
    "tls-listening-port=5349", "realm=CHANGE_ME_RELAY_REALM",
    "server-name=CHANGE_ME_RELAY_FQDN",
    "static-auth-secret=CHANGE_ME_WITH_43_CHAR_BASE64URL_SECRET",
    "unauthorized-ratelimit", "unauthorized-ratelimit-rps=10"
  )) {
  if ($sourceBaselineLines -cnotcontains $requiredSourceLine) {
    Fail "relay_install_turn_baseline_source_contract_invalid"
  }
}
$renderedBaselineLines = New-Object Collections.ArrayList
foreach ($rawLine in $sourceBaselineLines) {
  switch -CaseSensitive ($rawLine) {
    { $_ -ceq "listening-ip=0.0.0.0" } { [void]$renderedBaselineLines.Add("listening-ip=$expectedListeningIp"); continue }
    { $_ -ceq "tls-listening-port=5349" } { [void]$renderedBaselineLines.Add("tls-listening-port=$TlsPort"); continue }
    { $_ -ceq "realm=CHANGE_ME_RELAY_REALM" } { [void]$renderedBaselineLines.Add("realm=$Realm"); continue }
    { $_ -ceq "server-name=CHANGE_ME_RELAY_FQDN" } { [void]$renderedBaselineLines.Add("server-name=$ServerName"); continue }
    { $_ -ceq "static-auth-secret=CHANGE_ME_WITH_43_CHAR_BASE64URL_SECRET" } {
      [void]$renderedBaselineLines.Add("static-auth-secret=__MRD_BROKER_SECRET_V1__")
      continue
    }
    { $_ -ceq "# external-ip=CHANGE_ME_PUBLIC_IP/CHANGE_ME_PRIVATE_IP" } { [void]$renderedBaselineLines.Add("external-ip=$ExternalIp"); continue }
    { $_ -ceq "# relay-ip=CHANGE_ME_PRIVATE_OR_PUBLIC_IP" } {
      if (-not [string]::IsNullOrEmpty($RelayIp)) { [void]$renderedBaselineLines.Add("relay-ip=$RelayIp") }
      continue
    }
    { $_ -like "total-quota=*" } { [void]$renderedBaselineLines.Add("total-quota=$maxAllocations"); continue }
    { $_ -like "bps-capacity=*" } { [void]$renderedBaselineLines.Add("bps-capacity=$coturnCapacityBytesPerSecond"); continue }
    default { [void]$renderedBaselineLines.Add($rawLine) }
  }
}
foreach ($renderedLine in $renderedBaselineLines) {
  if ($renderedLine -like "*CHANGE_ME*") {
    Fail "relay_install_turn_baseline_placeholder"
  }
}
$renderedBaselineText = (($renderedBaselineLines -join "`n") + "`n")

if ($TlsPort -eq 443) {
  $portOwner = @(Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue)
  if ($portOwner.Count -ne 0) { Fail "relay_install_tls_443_conflict" }
}

$targetConfiguration = [ordered]@{
  schema_version = 1
  target = $Target
  control_pipe = $ControlPipeName
  minimum_coturn_version = "4.17.2"
  tls_port = $TlsPort
  relay_port_min = 49160
  relay_port_max = 49260
  max_allocations = $maxAllocations
  max_egress_bps = $maxEgressBps
  coturn_bps_capacity_bytes_per_second = $coturnCapacityBytesPerSecond
  metrics_bind = "127.0.0.1:9641"
  local_acceptance_command = @("preflight", "--config", "ABSOLUTE_CONFIG", "--challenge", "HEX64")
  configured_endpoints = @($sourceConfig.endpoints)
  transport_capabilities = @($transportCapabilities)
}

switch ($Target) {
  "Native" {
    if ([string]::IsNullOrEmpty($VerifiedNativeDrainWrapper) -or
        [string]::IsNullOrEmpty($NativeCoturnBinary)) {
      Fail "relay_install_native_verified_drain_wrapper_required_fail_closed"
    }
    $VerifiedNativeDrainWrapper = Get-SafeFullPath $VerifiedNativeDrainWrapper -MustExist -Leaf
    $NativeCoturnBinary = Get-SafeFullPath $NativeCoturnBinary -MustExist -Leaf
    Assert-SignedHash $VerifiedNativeDrainWrapper $VerifiedNativeDrainWrapperSha256 "relay_install_native_wrapper"
    Assert-SignedHash $NativeCoturnBinary $NativeCoturnSha256 "relay_install_native_coturn"
    $versionOutput = @(& $NativeCoturnBinary --version 2>&1) -join "`n"
    $versionMatch = [regex]::Match($versionOutput, '[0-9]+\.[0-9]+\.[0-9]+')
    if ($LASTEXITCODE -ne 0 -or -not $versionMatch.Success -or
        ([version]$versionMatch.Value) -lt ([version]"4.17.2")) {
      Fail "relay_install_native_coturn_version_too_old"
    }
    $helpOutput = @(& $NativeCoturnBinary --help 2>&1) -join "`n"
    if ($helpOutput -notmatch 'prometheus-address') { Fail "relay_install_native_prometheus_build_missing" }
    $targetConfiguration["VerifiedNativeDrainWrapper"] = $VerifiedNativeDrainWrapper
    $targetConfiguration["native_coturn_binary"] = $NativeCoturnBinary
    $targetConfiguration["native_wrapper_sha256"] = $VerifiedNativeDrainWrapperSha256.ToLowerInvariant()
    $targetConfiguration["native_coturn_sha256"] = $NativeCoturnSha256.ToLowerInvariant()
    $wrapperSignature = Get-AuthenticodeSignature -LiteralPath $VerifiedNativeDrainWrapper
    if ($null -eq $wrapperSignature.SignerCertificate -or
        [string]::IsNullOrEmpty($wrapperSignature.SignerCertificate.Subject)) {
      Fail "relay_install_native_wrapper_signer_missing"
    }
    $targetConfiguration["native_wrapper_signer"] = $wrapperSignature.SignerCertificate.Subject
    $targetConfiguration["RestartPolicy"] = "Restart=no"
  }
  "Docker" {
    $DockerExecutable = Get-SafeFullPath $DockerExecutable -MustExist -Leaf
    if ([string]::IsNullOrEmpty($DockerExecutableSha256)) { Fail "relay_install_docker_hash_required" }
    Assert-SignedHash $DockerExecutable $DockerExecutableSha256 "relay_install_docker"
    $targetManagerHash = $DockerExecutableSha256.ToLowerInvariant()
    $targetConfiguration["docker_executable"] = $DockerExecutable
    $targetConfiguration["container_name"] = $DockerContainerName
    $targetConfiguration["expected_container_id_state_path"] = [IO.Path]::Combine($DataRoot, "broker", "docker-identity.json")
    $targetConfiguration["image"] = $DockerImage
    $targetConfiguration["RestartPolicy"] = "restart=no"
    $targetConfiguration["labels"] = @{ "io.mrd.relay.managed" = "true" }
    $targetConfiguration["read_only_rootfs"] = $true
    $targetConfiguration["bind_mounts"] = @(
      @{ source = [IO.Path]::Combine($DataRoot, "broker", "docker-envelope"); destination = "/run/mrd/turnserver.conf"; read_only = $true },
      @{ source = [IO.Path]::Combine($DataRoot, "tls"); destination = "/run/mrd/tls"; read_only = $true }
    )
    $targetConfiguration["published_ports"] = @(
      "3478:3478/udp", "3478:3478/tcp", "$TlsPort`:$TlsPort/tcp",
      "49160-49260:49160-49260/udp", "49160-49260:49160-49260/tcp",
      "127.0.0.1:9641:9641/tcp"
    )
  }
  "Wsl2" {
    # WSL registrations are per-token.  The broker runs as LocalSystem, so the
    # installer must inspect and terminate the same LocalSystem-owned distro.
    Assert-CurrentProcessIsLocalSystem
    $WslExecutable = Get-SafeFullPath $WslExecutable -MustExist -Leaf
    if ([string]::IsNullOrEmpty($WslExecutableSha256)) { Fail "relay_install_wsl_hash_required" }
    Assert-SignedHash $WslExecutable $WslExecutableSha256 "relay_install_wsl"
    $targetManagerHash = $WslExecutableSha256.ToLowerInvariant()
    $targetConfiguration["wsl_executable"] = $WslExecutable
    $targetConfiguration["distribution"] = $WslDistributionName
    $targetConfiguration["owner"] = "LocalSystem"
    $targetConfiguration["networking_mode"] = "mirrored"
    $targetConfiguration["systemd_required"] = $true
    $targetConfiguration["IPAccounting"] = "yes"
    $targetConfiguration["live_udp_range_probe_required"] = $true
  }
}

if (-not $PSCmdlet.ShouldProcess($InstallRoot, "Install or upgrade MRD relay services")) { return }

Initialize-MachineDeploymentLockBoundary
$deploymentLock = Enter-DeploymentTransactionLock
try {
$existingTargetPath = [IO.Path]::Combine($DataRoot, "broker", "target.json")
$isUpgrade = $false
$existingTarget = $null
$firstDrainProof = $null
if ([IO.File]::Exists($existingTargetPath)) {
  $isUpgrade = $true
  $existingTargetConfiguration = Get-Content -LiteralPath $existingTargetPath -Raw | ConvertFrom-Json
  $existingTarget = [string]$existingTargetConfiguration.target
  if ($existingTarget -cne $Target) {
    Fail "relay_install_target_switch_requires_explicit_migration"
  }
  $existingBaselinePath = Get-SafeFullPath ([string]$existingTargetConfiguration.turnserver_baseline_path) -MustExist -Leaf
  if ($existingBaselinePath -cne [IO.Path]::Combine($DataRoot, "broker", "turnserver.conf.base") -or
      (Get-Content -LiteralPath $existingBaselinePath -Raw) -cne $renderedBaselineText) {
    Fail "relay_install_drained_baseline_change_requires_secret_rotation"
  }
  Assert-UpgradeStateAvailable $existingTarget
  $firstDrainProof = Get-CompletedDrainProof $existingTarget
  Assert-TargetQuiescentForUpgrade $existingTarget $existingTargetConfiguration
} elseif ((Test-ServiceExists $AgentServiceName) -or (Test-ServiceExists $BrokerServiceName) -or
    (Test-ServiceExists $NativeCoturnServiceName) -or [IO.Directory]::Exists($InstallRoot) -or
    [IO.Directory]::Exists($DataRoot)) {
  Fail "relay_install_unmanaged_service_collision"
}
if (-not (Test-WslInstallDisposition $Target $isUpgrade)) {
  # This installer intentionally cannot import a system-owned distro safely.  A
  # separately authenticated provisioning workflow must create and verify it.
  Fail "relay_install_wsl_fresh_requires_verified_provisioning"
}

Initialize-DefaultManagedBoundary
foreach ($destination in @($InstallRoot, $DataRoot, $RecoveryRoot)) {
  $revalidatedDestination = Get-SafeFullPath $destination
  if ($revalidatedDestination -cne $destination) { Fail "relay_install_destination_changed_during_boundary_creation" }
  Assert-TrustedDestinationAncestors $destination
}

$agentServiceExisted = Test-ServiceExists $AgentServiceName
$brokerServiceExisted = Test-ServiceExists $BrokerServiceName
$nativeServiceExisted = Test-ServiceExists $NativeCoturnServiceName
$agentServiceWasRunning = Test-ServiceRunning $AgentServiceName
$brokerServiceWasRunning = Test-ServiceRunning $BrokerServiceName
$nativeServiceWasRunning = Test-ServiceRunning $NativeCoturnServiceName
$scmSnapshots = [ordered]@{}
foreach ($serviceEntry in @(
    @($AgentServiceName, $agentServiceExisted, "NT AUTHORITY\LocalService"),
    @($BrokerServiceName, $brokerServiceExisted, "LocalSystem"),
    @($NativeCoturnServiceName, $nativeServiceExisted, "NT AUTHORITY\LocalService")
  )) {
  if ([bool]$serviceEntry[1]) {
    $snapshot = Get-ExactScmSnapshot ([string]$serviceEntry[0])
    if ([string]$snapshot.account -ine [string]$serviceEntry[2]) {
      Fail "relay_install_scm_snapshot_account_invalid"
    }
    $scmSnapshots[[string]$serviceEntry[0]] = $snapshot
  }
}
$programRootExisted = [IO.Directory]::Exists($InstallRoot)
$dataRootExisted = [IO.Directory]::Exists($DataRoot)
$previousFirewallRules = New-Object Collections.ArrayList
foreach ($ruleName in @(
    "MRD Relay TURN UDP 3478", "MRD Relay TURN TCP 3478", "MRD Relay TURN TLS TCP",
    "MRD Relay Range UDP", "MRD Relay Range TCP"
  )) {
  foreach ($existingRule in @(Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
    $portFilter = $existingRule | Get-NetFirewallPortFilter
    [void]$previousFirewallRules.Add([ordered]@{
      display_name = [string]$existingRule.DisplayName
      enabled = [string]$existingRule.Enabled
      direction = [string]$existingRule.Direction
      action = [string]$existingRule.Action
      profile = [string]$existingRule.Profile
      protocol = [string]$portFilter.Protocol
      local_port = [string]$portFilter.LocalPort
    })
  }
}

Initialize-OrValidateRecoveryRoot $RecoveryRoot
$recoveryDirectory = [IO.Path]::Combine(
  $RecoveryRoot,
  "upgrade-" + [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ") + "-" + [Guid]::NewGuid().ToString("N")
)
[void][IO.Directory]::CreateDirectory($recoveryDirectory)
Set-SystemAdminDirectoryAcl $recoveryDirectory
$checkpoint = [ordered]@{
  schema_version = 1
  created_at_utc = [DateTime]::UtcNow.ToString("o")
  phase_updated_at_utc = [DateTime]::UtcNow.ToString("o")
  transaction_phase = "checkpointed"
  install_root = $InstallRoot
  data_root = $DataRoot
  program_backup = [IO.Path]::Combine($recoveryDirectory, "program")
  data_backup = [IO.Path]::Combine($recoveryDirectory, "data")
  agent_service_existed = $agentServiceExisted
  broker_service_existed = $brokerServiceExisted
  native_service_existed = $nativeServiceExisted
  agent_service_was_running = $agentServiceWasRunning
  broker_service_was_running = $brokerServiceWasRunning
  native_service_was_running = $nativeServiceWasRunning
  scm_snapshots = $scmSnapshots
  program_root_existed = $programRootExisted
  data_root_existed = $dataRootExisted
  firewall_rules = @($previousFirewallRules)
  restore_order = @(
    "Stop only mrd-relay-agent and mrd-relay-coturn-control.",
    "Move any failed new install/data roots to a separate protected quarantine; never delete them.",
    "Move the exact program_backup and data_backup directories back to install_root and data_root.",
    "Restore the listed exact firewall rules and exact SCM definitions, preserving the recorded stopped/running states.",
    "Run verify-relay-node.ps1 before admitting public traffic."
  )
}
$checkpointPath = [IO.Path]::Combine($recoveryDirectory, "UPGRADE-RECOVERY.json")
Write-ProtectedUpgradeCheckpoint $checkpointPath $checkpoint
Write-Output ("relay_install_recovery_checkpoint path=" + $recoveryDirectory)
$restoreServiceState = [ordered]@{
  agent_existed = $agentServiceExisted
  broker_existed = $brokerServiceExisted
  native_existed = $nativeServiceExisted
  agent_running = $agentServiceWasRunning
  broker_running = $brokerServiceWasRunning
  native_running = $nativeServiceWasRunning
  scm_snapshots = $scmSnapshots
  program_root_existed = $programRootExisted
  data_root_existed = $dataRootExisted
  target = $Target
  previous_target_existed = $isUpgrade
  target_may_have_changed = $false
}
$transactionStarted = $true
try {
  if ($Target -ceq "Docker") {
    $imageInspectResult = Invoke-BoundedNativeProcess $DockerExecutable `
      @("image", "inspect", $DockerImage) 30000 65536 "Utf8" $recoveryDirectory
    if ($imageInspectResult.ExitCode -ne 0) { Fail "relay_install_docker_pinned_image_missing" }
  }
  if ($isUpgrade) {
    Set-UpgradeTransactionPhase $checkpoint $checkpointPath "before-stop-agent"
    Stop-ExactService $AgentServiceName
    Set-UpgradeTransactionPhase $checkpoint $checkpointPath "before-second-proof"
    $secondDrainProof = Get-CompletedDrainProof $existingTarget
    Assert-SameDrainFence $firstDrainProof $secondDrainProof
    Set-UpgradeTransactionPhase $checkpoint $checkpointPath "before-stop-broker"
    Stop-ExactService $BrokerServiceName
    Set-UpgradeTransactionPhase $checkpoint $checkpointPath "before-stop-target"
    Stop-ChangedTargetForRollback $existingTarget $DataRoot
  }
  Set-UpgradeTransactionPhase $checkpoint $checkpointPath "before-move-roots"
  if ([IO.Directory]::Exists($InstallRoot)) {
    Set-UpgradeTransactionPhase $checkpoint $checkpointPath "moving-program-root"
    Move-Item -LiteralPath $InstallRoot -Destination ([IO.Path]::Combine($recoveryDirectory, "program"))
    Set-UpgradeTransactionPhase $checkpoint $checkpointPath "program-root-moved"
  }
  if ([IO.Directory]::Exists($DataRoot)) {
    Set-UpgradeTransactionPhase $checkpoint $checkpointPath "moving-data-root"
    Move-Item -LiteralPath $DataRoot -Destination ([IO.Path]::Combine($recoveryDirectory, "data"))
    Set-UpgradeTransactionPhase $checkpoint $checkpointPath "data-root-moved"
  }
  Set-UpgradeTransactionPhase $checkpoint $checkpointPath "installing"

$configDirectory = [IO.Path]::Combine($DataRoot, "config")
$secretDirectory = [IO.Path]::Combine($DataRoot, "secrets")
$stateDirectory = [IO.Path]::Combine($DataRoot, "state")
$brokerDirectory = [IO.Path]::Combine($DataRoot, "broker")
$tlsDirectory = [IO.Path]::Combine($DataRoot, "tls")
foreach ($directory in @($InstallRoot, $DataRoot, $configDirectory, $secretDirectory, $stateDirectory, $brokerDirectory, $tlsDirectory)) {
  [void][IO.Directory]::CreateDirectory($directory)
  Set-SystemAdminDirectoryAcl $directory
  $item = Get-Item -LiteralPath $directory -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail "relay_install_destination_reparse_rejected"
  }
}
if ($isUpgrade) {
  Preserve-UpgradeState ([IO.Path]::Combine($recoveryDirectory, "data")) $DataRoot $existingTarget
}

$installedAgent = [IO.Path]::Combine($InstallRoot, "mrd-relay-agent.exe")
$installedBroker = [IO.Path]::Combine($InstallRoot, "mrd-relay-coturn-control.exe")
$installedVerifier = [IO.Path]::Combine($InstallRoot, "verify-relay-node.ps1")
Copy-Item -LiteralPath $AgentBinary -Destination $installedAgent
Copy-Item -LiteralPath $BrokerBinary -Destination $installedBroker
Copy-Item -LiteralPath ([IO.Path]::Combine($PSScriptRoot, "verify-relay-node.ps1")) -Destination $installedVerifier
Copy-Item -LiteralPath $TrustedCaFile -Destination ([IO.Path]::Combine($configDirectory, "trusted-ca.pem"))
Copy-Item -LiteralPath $TlsCertificateFile -Destination ([IO.Path]::Combine($tlsDirectory, "fullchain.pem"))
Copy-Item -LiteralPath $TlsPrivateKeyFile -Destination ([IO.Path]::Combine($tlsDirectory, "privkey.pem"))
$turnBaselinePath = [IO.Path]::Combine($brokerDirectory, "turnserver.conf.base")
$baselineEncoding = New-Object Text.UTF8Encoding($false)
[IO.File]::WriteAllText($turnBaselinePath, $renderedBaselineText, $baselineEncoding)
$targetConfiguration["turnserver_baseline_path"] = $turnBaselinePath
if ($Target -eq "Native") {
  $installedNativeWrapper = [IO.Path]::Combine($InstallRoot, "mrd-verified-native-drain-wrapper.exe")
  $installedNativeCoturn = [IO.Path]::Combine($InstallRoot, "turnserver.exe")
  Copy-Item -LiteralPath $VerifiedNativeDrainWrapper -Destination $installedNativeWrapper
  Copy-Item -LiteralPath $NativeCoturnBinary -Destination $installedNativeCoturn
  $VerifiedNativeDrainWrapper = $installedNativeWrapper
  $NativeCoturnBinary = $installedNativeCoturn
  $targetConfiguration["VerifiedNativeDrainWrapper"] = $VerifiedNativeDrainWrapper
  $targetConfiguration["native_coturn_binary"] = $NativeCoturnBinary
  $targetConfiguration["native_wrapper_sha256"] = (Get-FileHash -LiteralPath $VerifiedNativeDrainWrapper -Algorithm SHA256).Hash.ToLowerInvariant()
  $targetConfiguration["native_coturn_sha256"] = (Get-FileHash -LiteralPath $NativeCoturnBinary -Algorithm SHA256).Hash.ToLowerInvariant()
  $installedWrapperSignature = Get-AuthenticodeSignature -LiteralPath $VerifiedNativeDrainWrapper
  if ($installedWrapperSignature.Status -ne "Valid" -or
      $null -eq $installedWrapperSignature.SignerCertificate -or
      [string]::IsNullOrEmpty($installedWrapperSignature.SignerCertificate.Subject)) {
    Fail "relay_install_native_wrapper_signer_missing"
  }
  $targetConfiguration["native_wrapper_signer"] = $installedWrapperSignature.SignerCertificate.Subject
}

$enrollmentBlob = [IO.Path]::Combine($secretDirectory, "enrollment-token.dpapi")
$turnBlob = [IO.Path]::Combine($secretDirectory, "turn-rest-secret.dpapi")
$agentConfigPath = [IO.Path]::Combine($configDirectory, "agent.json")
$targetConfigPath = [IO.Path]::Combine($brokerDirectory, "target.json")
$brokerConfigPath = [IO.Path]::Combine($brokerDirectory, "broker.json")
$activeTurnSecretPath = [IO.Path]::Combine($brokerDirectory, "active-turn-secret.dpapi")
$brokerRuntimeStatePath = [IO.Path]::Combine($brokerDirectory, "control-state.dpapi")
$brokerJournalPath = [IO.Path]::Combine($brokerDirectory, "control-journal.dpapi")
$manifestPath = [IO.Path]::Combine($DataRoot, "install-manifest.json")

$agentCommand = '"' + $installedAgent + '" run --config "' + $agentConfigPath + '"'
$brokerCommand = '"' + $installedBroker + '" broker --config "' + $brokerConfigPath + '"'
Configure-Service $BrokerServiceName $brokerCommand "LocalSystem"
Configure-Service $AgentServiceName $agentCommand "NT AUTHORITY\LocalService" $BrokerServiceName
$null = Invoke-Sc @("sidtype", $AgentServiceName, "restricted")
$null = Invoke-Sc @("sidtype", $BrokerServiceName, "restricted")
$null = Invoke-Sc @("failureflag", $AgentServiceName, "0")
$null = Invoke-Sc @("failure", $AgentServiceName, "reset=", "4294967295", "actions=", "restart/5000/restart/30000/none/0")
$null = Invoke-Sc @("failureflag", $BrokerServiceName, "0")
$null = Invoke-Sc @("failure", $BrokerServiceName, "reset=", "4294967295", "actions=", "restart/5000/restart/30000/none/0")

$agentServiceSid = Get-ServiceSid $AgentServiceName
$brokerServiceSid = Get-ServiceSid $BrokerServiceName
$installedBrokerHash = (Get-FileHash -LiteralPath $installedBroker -Algorithm SHA256).Hash.ToLowerInvariant()
$productionTargetName = switch ($Target) {
  "Native" { "windows-service" }
  "Docker" { "docker" }
  "Wsl2" { "wsl2" }
}
$productionTargetConfig = switch ($Target) {
  "Native" {
    [ordered]@{
      kind = "windows-service"
      agent_service_sid = $agentServiceSid
      broker_executable = $installedBroker
      broker_sha256 = $installedBrokerHash
      native_wrapper = $VerifiedNativeDrainWrapper
      native_wrapper_sha256 = $targetConfiguration.native_wrapper_sha256
      native_wrapper_signer = $targetConfiguration.native_wrapper_signer
    }
  }
  "Docker" {
    [ordered]@{
      kind = "docker"
      agent_service_sid = $agentServiceSid
      broker_executable = $installedBroker
      broker_sha256 = $installedBrokerHash
      docker_executable = $DockerExecutable
      canonical_image = $DockerImage
      expected_container_id_state_path = [IO.Path]::Combine($brokerDirectory, "docker-identity.json")
      managed_label = "io.mrd.relay.managed=true"
      container_read_only = $true
      restart_policy = "no"
      relay_udp_range_published = $true
      published_ports = @($productionDockerPorts)
      read_only_mounts = @(
        [ordered]@{
          source = [IO.Path]::Combine($brokerDirectory, "docker-envelope")
          destination = "/run/mrd/turnserver.conf"
          read_only = $true
        },
        [ordered]@{
          source = $tlsDirectory
          destination = "/run/mrd/tls"
          read_only = $true
        }
      )
    }
  }
  "Wsl2" {
    [ordered]@{
      kind = "wsl2"
      agent_service_sid = $agentServiceSid
      broker_executable = $installedBroker
      broker_sha256 = $installedBrokerHash
      wsl_executable = $WslExecutable
      distro = $WslDistributionName
      system_owned = $true
      mirrored_networking = $true
    }
  }
}

$renderedConfig = [ordered]@{
  backend_url = $sourceConfig.backend_url
  node_id = $sourceConfig.node_id
  region = $sourceConfig.region
  failure_domain = $sourceConfig.failure_domain
  endpoints = @($sourceConfig.endpoints)
  max_allocations = $maxAllocations
  max_egress_bps = $maxEgressBps
  identity_path = [IO.Path]::Combine($stateDirectory, "identity.json")
  runtime_state_path = [IO.Path]::Combine($stateDirectory, "runtime.json")
  trusted_ca_path = [IO.Path]::Combine($configDirectory, "trusted-ca.pem")
  metrics_url = $sourceConfig.metrics_url
  heartbeat_interval_seconds = $sourceConfig.heartbeat_interval_seconds
  backend_backoff_cap_seconds = $sourceConfig.backend_backoff_cap_seconds
  target = $productionTargetName
  relay_min_port = 49160
  relay_max_port = 49260
  transport_capabilities = @($transportCapabilities)
  tls_listener_port = $TlsPort
  enrollment_token_path = $enrollmentBlob
  turn_rest_secret_path = $turnBlob
  target_config = $productionTargetConfig
}

$brokerConfiguration = [ordered]@{
  schema_version = 1
  pipe = $ControlPipeName
  target_config_path = $targetConfigPath
  enrollment_token_path = $enrollmentBlob
  turn_rest_secret_path = $turnBlob
  pipe_acl = @("SYSTEM", "BUILTIN\Administrators", "NT SERVICE\$AgentServiceName")
  verify_client_token_twice = $true
  minimal_environment = @("SystemRoot", "ProgramFiles", "ProgramData")
  node_id = $sourceConfig.node_id
  broker_service_sid = $brokerServiceSid
  active_turn_secret_path = $activeTurnSecretPath
  runtime_state_path = $brokerRuntimeStatePath
  journal_path = $brokerJournalPath
}

# HardenedAtomicFile requires the immediate trusted root and every existing
# leaf to have exactly SYSTEM + Administrators + the one owning service SID.
foreach ($path in @($configDirectory, $secretDirectory, $stateDirectory)) {
  Set-ExactServiceStoreAcl $path $agentServiceSid
}
foreach ($path in @($brokerDirectory, $tlsDirectory)) {
  Set-ExactServiceStoreAcl $path $brokerServiceSid
}
if ($Target -ceq "Docker") {
  Initialize-DockerEnvelope ([IO.Path]::Combine($brokerDirectory, "docker-envelope")) `
    $brokerServiceSid $isUpgrade
}

$utf8NoBom = New-Object Text.UTF8Encoding($false)
foreach ($triple in @(
    @($agentConfigPath, ($renderedConfig | ConvertTo-Json -Depth 12 -Compress), $agentServiceSid),
    @($targetConfigPath, ($targetConfiguration | ConvertTo-Json -Depth 12 -Compress), $brokerServiceSid),
    @($brokerConfigPath, ($brokerConfiguration | ConvertTo-Json -Depth 12 -Compress), $brokerServiceSid)
  )) {
  $temporary = $triple[0] + "." + [Guid]::NewGuid().ToString("N") + ".pending"
  [IO.File]::WriteAllText($temporary, [string]$triple[1] + "`n", $utf8NoBom)
  Move-Item -LiteralPath $temporary -Destination $triple[0] -Force
  Set-ExactServiceStoreAcl $triple[0] $triple[2]
}

if ($Target -eq "Native") {
  $nativeCommand = '"' + $VerifiedNativeDrainWrapper + '" --service --coturn "' + $NativeCoturnBinary + '"'
  if (Test-ServiceExists $NativeCoturnServiceName) {
    $null = Invoke-Sc @("config", $NativeCoturnServiceName, "binPath=", $nativeCommand, "start=", "demand", "obj=", "NT AUTHORITY\LocalService")
  } else {
    $null = Invoke-Sc @("create", $NativeCoturnServiceName, "binPath=", $nativeCommand, "start=", "demand", "obj=", "NT AUTHORITY\LocalService")
  }
  $null = Invoke-Sc @("sidtype", $NativeCoturnServiceName, "restricted")
  $null = Invoke-Sc @("failureflag", $NativeCoturnServiceName, "0")
  $null = Invoke-Sc @("failure", $NativeCoturnServiceName, "reset=", "4294967295", "actions=", "none/0")
  foreach ($nativePath in @($VerifiedNativeDrainWrapper, $NativeCoturnBinary)) {
    $null = & icacls.exe $nativePath "/setowner" "BUILTIN\Administrators"
    if ($LASTEXITCODE -ne 0) { Fail "relay_install_native_owner_failed" }
    $null = & icacls.exe $nativePath "/inheritance:r" "/grant:r" `
      "SYSTEM:(F)" "BUILTIN\Administrators:(F)" "NT SERVICE\${NativeCoturnServiceName}:(RX)" `
      "NT SERVICE\${BrokerServiceName}:(RX)"
    if ($LASTEXITCODE -ne 0) { Fail "relay_install_native_acl_failed" }
  }
}

Set-AgentDirectoryAcl $InstallRoot
foreach ($path in @($DataRoot, $installedAgent, $installedBroker, $installedVerifier)) {
  Set-AgentReadableAcl $path
}
$trustedCaInstalledPath = [IO.Path]::Combine($configDirectory, "trusted-ca.pem")
Set-ExactAgentReadAcl $configDirectory $agentServiceSid -Directory
Set-ExactAgentReadAcl $agentConfigPath $agentServiceSid
Set-ExactAgentReadAcl $trustedCaInstalledPath $agentServiceSid
foreach ($path in @(
    $targetConfigPath, $brokerConfigPath, $turnBaselinePath,
    ([IO.Path]::Combine($tlsDirectory, "fullchain.pem")),
    ([IO.Path]::Combine($tlsDirectory, "privkey.pem"))
  )) {
  Set-ExactServiceStoreAcl $path $brokerServiceSid
}

# Do not reproduce the DPAPI/envelope format in PowerShell. The signed agent
# provisions a purpose/node/path-bound Machine-DPAPI BoundSecretStore from a
# bounded stdin stream and verifies that it can reopen the resulting envelope.
Invoke-RustSecretProvisioning $installedAgent $agentConfigPath "enrollment" $EnrollmentTokenFile
Invoke-RustSecretProvisioning $installedAgent $agentConfigPath "turn" $TurnSecretFile
foreach ($blob in @($enrollmentBlob, $turnBlob)) {
  Set-ExactServiceStoreAcl $blob $agentServiceSid
}
foreach ($statePath in @(
    ([IO.Path]::Combine($stateDirectory, "identity.json")),
    ([IO.Path]::Combine($stateDirectory, "runtime.json"))
  )) {
  if ([IO.File]::Exists($statePath)) { Set-ExactServiceStoreAcl $statePath $agentServiceSid }
}
foreach ($brokerStatePath in @(
    $activeTurnSecretPath, $brokerRuntimeStatePath, $brokerJournalPath,
    ([IO.Path]::Combine($brokerDirectory, "docker-identity.json")),
    ([IO.Path]::Combine($brokerDirectory, "docker-envelope"))
  )) {
  if ([IO.File]::Exists($brokerStatePath)) { Set-ExactServiceStoreAcl $brokerStatePath $brokerServiceSid }
}

$null = & $installedAgent validate --config $agentConfigPath
if ($LASTEXITCODE -ne 0) { Fail "relay_install_rendered_config_invalid" }

$manifest = [ordered]@{
  schema_version = 1
  target = $Target
  agent_sha256 = (Get-FileHash -LiteralPath $installedAgent -Algorithm SHA256).Hash.ToLowerInvariant()
  broker_sha256 = (Get-FileHash -LiteralPath $installedBroker -Algorithm SHA256).Hash.ToLowerInvariant()
  target_manager_sha256 = if ($Target -in @("Docker", "Wsl2")) { $targetManagerHash } else { $null }
  turnserver_baseline_sha256 = (Get-FileHash -LiteralPath $turnBaselinePath -Algorithm SHA256).Hash.ToLowerInvariant()
  recovery_directory = $recoveryDirectory
  public_acceptance = "Task 11 required; missing evidence is INFRA_FAIL"
}
$manifestTemporary = $manifestPath + "." + [Guid]::NewGuid().ToString("N") + ".pending"
[IO.File]::WriteAllText($manifestTemporary, ($manifest | ConvertTo-Json -Depth 5 -Compress) + "`n", $utf8NoBom)
Move-Item -LiteralPath $manifestTemporary -Destination $manifestPath -Force
$null = & icacls.exe $manifestPath "/setowner" "BUILTIN\Administrators"
if ($LASTEXITCODE -ne 0) { Fail "relay_install_manifest_owner_failed" }
$null = & icacls.exe $manifestPath "/inheritance:r" "/grant:r" `
  "SYSTEM:(F)" "BUILTIN\Administrators:(F)"
if ($LASTEXITCODE -ne 0) { Fail "relay_install_manifest_acl_failed" }

foreach ($ruleName in @(
    "MRD Relay TURN UDP 3478", "MRD Relay TURN TCP 3478", "MRD Relay TURN TLS TCP",
    "MRD Relay Range UDP", "MRD Relay Range TCP"
  )) {
  foreach ($existingRule in @(Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
    Remove-NetFirewallRule -InputObject $existingRule
  }
}
$null = New-NetFirewallRule -DisplayName "MRD Relay TURN UDP 3478" -Direction Inbound -Action Allow -Protocol UDP -LocalPort 3478
$null = New-NetFirewallRule -DisplayName "MRD Relay TURN TCP 3478" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3478
$null = New-NetFirewallRule -DisplayName "MRD Relay TURN TLS TCP" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $TlsPort
$null = New-NetFirewallRule -DisplayName "MRD Relay Range UDP" -Direction Inbound -Action Allow -Protocol UDP -LocalPort "49160-49260"
$null = New-NetFirewallRule -DisplayName "MRD Relay Range TCP" -Direction Inbound -Action Allow -Protocol TCP -LocalPort "49160-49260"

$restoreServiceState.target_may_have_changed = $true
Set-UpgradeTransactionPhase $checkpoint $checkpointPath "verifying"
$null = Invoke-Sc @("start", $BrokerServiceName)
$null = Invoke-Sc @("start", $AgentServiceName)

$verified = $false
for ($attempt = 0; $attempt -lt 12; $attempt++) {
  try {
    if ($isUpgrade) {
      & $installedVerifier -Target $Target -InstallRoot $InstallRoot -DataRoot $DataRoot -Drained
    } else {
      & $installedVerifier -Target $Target -InstallRoot $InstallRoot -DataRoot $DataRoot
    }
    if ($LASTEXITCODE -eq 0) { $verified = $true; break }
  } catch {
    # Enrollment is asynchronous; only stable, redacted failures are retried.
  }
  Start-Sleep -Seconds 5
}
if (-not $verified) {
  if ($isUpgrade) { Fail "relay_install_drained_verification_failed" }
  Fail "relay_install_local_preflight_failed"
}
if ($isUpgrade) {
  $postInstallDrainProof = Get-CompletedDrainProof $existingTarget
  Assert-SameDrainFence $firstDrainProof $postInstallDrainProof
}

Set-UpgradeTransactionPhase $checkpoint $checkpointPath "complete"
$transactionStarted = $false
if ($isUpgrade) {
  Write-Output ("relay_install_complete_drained recovery_path=" + $recoveryDirectory)
} else {
  Write-Output ("relay_install_complete recovery_path=" + $recoveryDirectory)
}
} catch {
  $originalFailure = $_
  if ($transactionStarted) {
    try {
      Restore-UpgradeCheckpoint $recoveryDirectory $InstallRoot $DataRoot `
        $restoreServiceState @($previousFirewallRules) ([string]$checkpoint.transaction_phase)
    } catch {
      throw "relay_install_rollback_failed"
    }
  }
  throw $originalFailure
}
} finally {
  $deploymentLock.Dispose()
}
