[CmdletBinding()]
param(
  [ValidateSet("Native", "Docker", "Wsl2")][string]$Target = "Native",
  [string]$InstallRoot = "$env:ProgramFiles\MRD Relay",
  [string]$DataRoot = "$env:ProgramData\MRD\RelayAgent",
  [switch]$Drained,
  [switch]$SelfTest
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
$ProgramDataSystemRoot = [IO.Path]::GetFullPath($env:ProgramData).TrimEnd([IO.Path]::DirectorySeparatorChar)
$DefaultManagedBoundary = [IO.Path]::Combine($ProgramDataSystemRoot, "MRD")
$SystemManagedAncestorAllowlist = @(
  $ProgramDataSystemRoot,
  [IO.Path]::GetPathRoot($ProgramDataSystemRoot)
)
$ExpectedKeys = @(
  "schema_version", "scope", "target", "generation", "applied_secret_version",
  "challenge_sha256", "listener_reachable", "credential_authenticated",
  "allocation_created", "permission_created", "packets_sent", "packets_received",
  "bytes_sent", "bytes_received", "local_candidate_kind", "remote_candidate_kind",
  "proof_sha256"
)

function Fail {
  param([Parameter(Mandatory = $true)][string]$Reason)
  throw $Reason
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
      Fail "relay_verify_wsl_requires_local_system"
    }
  } catch {
    if ($_.Exception.Message -eq "relay_verify_wsl_requires_local_system") { throw }
    Fail "relay_verify_wsl_identity_unavailable"
  }
}

function ConvertTo-NativeCommandLineArgument {
  param([AllowEmptyString()][string]$Argument)
  if ($null -eq $Argument -or $Argument.Length -gt 4096 -or
      $Argument -match '[\x00-\x1f\x7f]') {
    Fail "relay_verify_external_process_argument_invalid"
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
      Fail "relay_verify_external_process_output_encoding_invalid"
    }
    $decoder = if ($OutputEncoding -ceq "Utf16Le") {
      New-Object Text.UnicodeEncoding($false, $false, $true)
    } else {
      New-Object Text.UTF8Encoding($false, $true)
    }
    try { $text = $decoder.GetString($bytes) } catch [Text.DecoderFallbackException] {
      Fail "relay_verify_external_process_output_encoding_invalid"
    }
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
    if ($text.IndexOf([char]0) -ge 0 -or $text.IndexOf([char]0xFFFD) -ge 0) {
      Fail "relay_verify_external_process_output_encoding_invalid"
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
    Fail "relay_verify_external_process_capture_root_invalid"
  }
  if ($Arguments.Count -gt 32) { Fail "relay_verify_external_process_argument_invalid" }
  $encodedArguments = @($Arguments | ForEach-Object { ConvertTo-NativeCommandLineArgument ([string]$_) })
  $commandLine = $encodedArguments -join ' '
  if ($commandLine.Length -gt 16384) { Fail "relay_verify_external_process_argument_invalid" }
  $captureId = [Guid]::NewGuid().ToString("N")
  $stdoutPath = [IO.Path]::Combine($safeCaptureRoot, ".$captureId.stdout")
  $stderrPath = [IO.Path]::Combine($safeCaptureRoot, ".$captureId.stderr")
  $process = $null
  try {
    $process = Start-Process -FilePath $safePath -ArgumentList $commandLine -NoNewWindow -PassThru `
      -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    if ($null -eq $process) { Fail "relay_verify_external_process_start_failed" }
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    while (-not $process.HasExited) {
      $capturedBytes = 0L
      if ([IO.File]::Exists($stdoutPath)) { $capturedBytes += (Get-Item -LiteralPath $stdoutPath -Force).Length }
      if ([IO.File]::Exists($stderrPath)) { $capturedBytes += (Get-Item -LiteralPath $stderrPath -Force).Length }
      if ($capturedBytes -gt $MaxOutputBytes) {
        try { $process.Kill() } catch { Fail "relay_verify_external_process_output_kill_failed" }
        if (-not $process.WaitForExit(5000)) { Fail "relay_verify_external_process_output_kill_failed" }
        Fail "relay_verify_external_process_output_too_large"
      }
      if ([DateTime]::UtcNow -ge $deadline) {
        try { $process.Kill() } catch { Fail "relay_verify_external_process_timeout_kill_failed" }
        if (-not $process.WaitForExit(5000)) { Fail "relay_verify_external_process_timeout_kill_failed" }
        Fail "relay_verify_external_process_timeout"
      }
      Start-Sleep -Milliseconds 25
    }
    $process.WaitForExit()
    $capturedBytes = 0L
    if ([IO.File]::Exists($stdoutPath)) { $capturedBytes += (Get-Item -LiteralPath $stdoutPath -Force).Length }
    if ([IO.File]::Exists($stderrPath)) { $capturedBytes += (Get-Item -LiteralPath $stderrPath -Force).Length }
    if ($capturedBytes -gt $MaxOutputBytes) { Fail "relay_verify_external_process_output_too_large" }
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

function Assert-DockerMountSafeDataRoot {
  param([Parameter(Mandatory = $true)][string]$Path)
  if ($Path.IndexOf(',') -ge 0 -or $Path.IndexOf('=') -ge 0) {
    Fail "relay_verify_docker_data_root_mount_syntax_invalid"
  }
}

function Get-ChallengeHash {
  param([Parameter(Mandatory = $true)][string]$Challenge)
  if ($Challenge -notmatch '^[0-9a-f]{64}$') { Fail "relay_verify_challenge_invalid" }
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

function Assert-PreflightEvidence {
  param(
    [Parameter(Mandatory = $true)][string]$Json,
    [Parameter(Mandatory = $true)][string]$Challenge,
    [Parameter(Mandatory = $true)][string]$ExpectedTarget
  )
  if ([Text.Encoding]::UTF8.GetByteCount($Json) -gt 8192 -or
      $Json.Contains("`n") -or $Json.Contains("`r")) {
    Fail "relay_verify_preflight_framing_invalid"
  }
  try { $value = $Json | ConvertFrom-Json } catch { Fail "relay_verify_preflight_json_invalid" }
  $names = @($value.PSObject.Properties.Name)
  $sortedActual = @($names | Sort-Object)
  $sortedExpected = @($ExpectedKeys | Sort-Object)
  if ($names.Count -ne $ExpectedKeys.Count -or
      (($sortedActual -join "`n") -cne ($sortedExpected -join "`n"))) {
    Fail "relay_verify_preflight_schema_invalid"
  }
  $rawKeyCount = [regex]::Matches($Json, '"[A-Za-z0-9_]+"\s*:').Count
  if ($rawKeyCount -ne $ExpectedKeys.Count) { Fail "relay_verify_preflight_duplicate_key_invalid" }
  if ($value.schema_version -ne 1 -or $value.scope -cne "local" -or $value.target -cne $ExpectedTarget) {
    Fail "relay_verify_preflight_identity_invalid"
  }
  if ($value.challenge_sha256 -cne (Get-ChallengeHash $Challenge)) {
    Fail "relay_verify_preflight_challenge_mismatch"
  }
  foreach ($field in @("generation", "applied_secret_version")) {
    $number = $value.$field
    if (($number -isnot [int] -and $number -isnot [long]) -or $number -le 0) {
      Fail "relay_verify_preflight_generation_invalid"
    }
  }
  foreach ($field in @("listener_reachable", "credential_authenticated", "allocation_created", "permission_created")) {
    if ($value.$field -isnot [bool] -or $value.$field -ne $true) {
      Fail "relay_verify_preflight_stage_failed"
    }
  }
  foreach ($field in @("packets_sent", "packets_received", "bytes_sent", "bytes_received")) {
    $number = $value.$field
    if (($number -isnot [int] -and $number -isnot [long]) -or $number -le 0) {
      Fail "relay_verify_preflight_traffic_invalid"
    }
  }
  if ($value.local_candidate_kind -cne "relay" -or $value.remote_candidate_kind -cne "relay") {
    Fail "relay_verify_preflight_candidate_invalid"
  }
  if ($value.proof_sha256 -isnot [string] -or $value.proof_sha256 -notmatch '^[0-9a-f]{64}$') {
    Fail "relay_verify_preflight_proof_invalid"
  }
}

function Assert-DrainProofEvidence {
  param(
    [Parameter(Mandatory = $true)][string]$Json,
    [Parameter(Mandatory = $true)][string]$Challenge,
    [Parameter(Mandatory = $true)][string]$ExpectedTarget
  )
  $expectedDrainKeys = @(
    "schema_version", "scope", "target", "generation", "applied_secret_version",
    "draining", "active_allocations", "drain_completed", "challenge_sha256", "proof_sha256"
  )
  if ([Text.Encoding]::UTF8.GetByteCount($Json) -gt 8192 -or $Json.Contains("`n") -or $Json.Contains("`r")) {
    Fail "relay_verify_drain_proof_framing_invalid"
  }
  try { $value = $Json | ConvertFrom-Json } catch { Fail "relay_verify_drain_proof_json_invalid" }
  $actual = @($value.PSObject.Properties.Name | Sort-Object)
  if (($actual -join "`n") -cne (($expectedDrainKeys | Sort-Object) -join "`n") -or
      [regex]::Matches($Json, '"[A-Za-z0-9_]+"\s*:').Count -ne $expectedDrainKeys.Count) {
    Fail "relay_verify_drain_proof_schema_invalid"
  }
  if ($value.schema_version -ne 1 -or $value.scope -cne "local" -or
      $value.target -cne $ExpectedTarget -or [int64]$value.generation -le 0 -or
      [int64]$value.applied_secret_version -le 0 -or $value.draining -ne $true -or
      [int64]$value.active_allocations -ne 0 -or $value.drain_completed -ne $true -or
      $value.challenge_sha256 -cne (Get-ChallengeHash $Challenge) -or
      [string]$value.proof_sha256 -notmatch '^[0-9a-f]{64}$') {
    Fail "relay_verify_drain_proof_invalid"
  }
}

function Get-ExpectedListeningIp {
  param([Parameter(Mandatory = $true)][string]$ExternalAddress)
  $publicAddress = $null
  if (-not [Net.IPAddress]::TryParse($ExternalAddress.Split('/', 2)[0], [ref]$publicAddress)) {
    Fail "relay_verify_external_ip_invalid"
  }
  if ($publicAddress.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
    return "0.0.0.0"
  }
  if ($publicAddress.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
    return "::"
  }
  Fail "relay_verify_external_ip_invalid"
}

function Invoke-SelfTest {
  $challenge = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
  $good = [ordered]@{
    schema_version = 1
    scope = "local"
    target = "windows-service"
    generation = 7
    applied_secret_version = 3
    challenge_sha256 = Get-ChallengeHash $challenge
    listener_reachable = $true
    credential_authenticated = $true
    allocation_created = $true
    permission_created = $true
    packets_sent = 2
    packets_received = 2
    bytes_sent = 64
    bytes_received = 64
    local_candidate_kind = "relay"
    remote_candidate_kind = "relay"
    proof_sha256 = ("a" * 64)
  }
  $goodJson = $good | ConvertTo-Json -Compress
  Assert-PreflightEvidence $goodJson $challenge "windows-service"
  $negativeCases = @(
    ($goodJson.Substring(0, $goodJson.Length - 1) + ',"credential":"must-be-rejected"}'),
    ($goodJson -replace '"challenge_sha256":"[0-9a-f]{64}"', '"challenge_sha256":"0000000000000000000000000000000000000000000000000000000000000000"'),
    ($goodJson -replace '"generation":7', '"generation":0'),
    ($goodJson -replace '"packets_received":2', '"packets_received":0')
  )
  foreach ($invalidJson in $negativeCases) {
    $rejected = $false
    try { Assert-PreflightEvidence $invalidJson $challenge "windows-service" } catch { $rejected = $true }
    if (-not $rejected) { Fail "relay_verify_self_test_negative_accepted" }
  }
  $goodDrain = [ordered]@{
    schema_version = 1
    scope = "local"
    target = "windows-service"
    generation = 7
    applied_secret_version = 3
    draining = $true
    active_allocations = 0
    drain_completed = $true
    challenge_sha256 = Get-ChallengeHash $challenge
    proof_sha256 = ("b" * 64)
  }
  $goodDrainJson = $goodDrain | ConvertTo-Json -Compress
  Assert-DrainProofEvidence $goodDrainJson $challenge "windows-service"
  foreach ($invalidDrain in @(
      ($goodDrainJson.Substring(0, $goodDrainJson.Length - 1) + ',"secret":"rejected"}'),
      ($goodDrainJson -replace '"active_allocations":0', '"active_allocations":1'),
      ($goodDrainJson -replace '"challenge_sha256":"[0-9a-f]{64}"', '"challenge_sha256":"0000000000000000000000000000000000000000000000000000000000000000"')
    )) {
    $rejected = $false
    try { Assert-DrainProofEvidence $invalidDrain $challenge "windows-service" } catch { $rejected = $true }
    if (-not $rejected) { Fail "relay_verify_self_test_drain_negative_accepted" }
  }
  foreach ($unsafePath in @("\\server\share\node", "\\?\C:\node", "C:\node:alternate")) {
    $rejected = $false
    try { $null = Get-SafeFullPath $unsafePath } catch { $rejected = $true }
    if (-not $rejected) { Fail "relay_verify_self_test_unsafe_path_accepted" }
  }
  $alignedBits = [int64]1000000000
  if (($alignedBits % 8) -ne 0 -or [int64]($alignedBits / 8) -ne 125000000) {
    Fail "relay_verify_self_test_bandwidth_conversion_invalid"
  }
  $misalignedBits = [int64]1000000001
  if (($misalignedBits % 8) -eq 0) { Fail "relay_verify_self_test_misaligned_bandwidth_accepted" }
  if ((Get-ExpectedListeningIp "198.20.0.10/10.0.0.10") -cne "0.0.0.0") {
    Fail "relay_verify_listener_self_test_ipv4_mismatch"
  }
  if ((Get-ExpectedListeningIp "2606:4700:4700::1111/fd00::10") -cne "::") {
    Fail "relay_verify_listener_self_test_ipv6_mismatch"
  }
  Assert-AncestorAclRuleSelfTest
  Assert-DockerProductionSpecSelfTest
  Assert-BoundedNativeProcessSelfTest
  if (-not (Test-IsLocalSystemSid "S-1-5-18")) {
    Fail "relay_verify_wsl_system_context_self_test_rejected_system"
  }
  foreach ($untrustedSid in @("S-1-5-19", "S-1-5-20", "S-1-5-32-544", "s-1-5-18", "")) {
    if (Test-IsLocalSystemSid $untrustedSid) {
      Fail "relay_verify_wsl_system_context_self_test_accepted_non_system"
    }
  }
  foreach ($unsafeRoot in @("C:\MRD,Relay", "C:\MRD=Relay")) {
    $rejected = $false
    try { Assert-DockerMountSafeDataRoot $unsafeRoot } catch { $rejected = $true }
    if (-not $rejected) { Fail "relay_verify_docker_mount_root_self_test_unsafe_accepted" }
  }
  Write-Output "relay_verify_self_test_passed"
}

function Assert-BoundedNativeProcessSelfTest {
  foreach ($unsafeArgument in @("line`nbreak", "nul$([char]0)byte", ("x" * 4097))) {
    $rejected = $false
    try { $null = ConvertTo-NativeCommandLineArgument $unsafeArgument } catch { $rejected = $true }
    if (-not $rejected) { Fail "relay_verify_bounded_process_self_test_unsafe_argument_accepted" }
  }
  $captureRoot = [IO.Path]::Combine([IO.Path]::GetTempPath(), "mrd-relay-verify-process-self-test-" + [Guid]::NewGuid().ToString("N"))
  [void][IO.Directory]::CreateDirectory($captureRoot)
  $utf16Fixture = [IO.Path]::Combine($captureRoot, "utf16le.fixture")
  $oddUtf16Fixture = [IO.Path]::Combine($captureRoot, "utf16le-odd.fixture")
  $nulUtf8Fixture = [IO.Path]::Combine($captureRoot, "utf8-nul.fixture")
  try {
    [IO.File]::WriteAllBytes(
      $utf16Fixture,
      (New-Object Text.UnicodeEncoding($false, $false, $true)).GetBytes("MRDRelay`r`n"))
    if ((Read-StrictNativeCapture $utf16Fixture "Utf16Le") -cne "MRDRelay`r`n") {
      Fail "relay_verify_bounded_process_self_test_utf16le_decode_invalid"
    }
    [IO.File]::WriteAllBytes($oddUtf16Fixture, [byte[]]@(0x41, 0x00, 0x42))
    $oddRejected = $false
    try { $null = Read-StrictNativeCapture $oddUtf16Fixture "Utf16Le" } catch { $oddRejected = $true }
    if (-not $oddRejected) { Fail "relay_verify_bounded_process_self_test_odd_utf16le_accepted" }
    [IO.File]::WriteAllBytes($nulUtf8Fixture, [byte[]]@(0x41, 0x00, 0x42))
    $nulRejected = $false
    try { $null = Read-StrictNativeCapture $nulUtf8Fixture "Utf8" } catch { $nulRejected = $true }
    if (-not $nulRejected) { Fail "relay_verify_bounded_process_self_test_utf8_nul_accepted" }
    $hostExecutable = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $result = Invoke-BoundedNativeProcess $hostExecutable @(
      "-NoProfile", "-NonInteractive", "-Command",
      '[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false); [Console]::Out.Write("verify-bounded-ok")'
    ) 5000 1024 "Utf8" $captureRoot
    if ($result.ExitCode -ne 0 -or $result.StdOut -cne "verify-bounded-ok" -or $result.StdErr.Length -ne 0) {
      Fail "relay_verify_bounded_process_self_test_success_invalid"
    }
    $timedOut = $false
    try {
      $null = Invoke-BoundedNativeProcess $hostExecutable @(
        "-NoProfile", "-NonInteractive", "-Command",
        '[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false); Start-Sleep -Seconds 2'
      ) 100 1024 "Utf8" $captureRoot
    } catch {
      if ($_.Exception.Message -eq "relay_verify_external_process_timeout") { $timedOut = $true }
    }
    if (-not $timedOut) { Fail "relay_verify_bounded_process_self_test_timeout_not_rejected" }
    $oversized = $false
    try {
      $null = Invoke-BoundedNativeProcess $hostExecutable @(
        "-NoProfile", "-NonInteractive", "-Command",
        '[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false); [Console]::Out.Write(("x" * 2048))'
      ) 5000 128 "Utf8" $captureRoot
    } catch {
      if ($_.Exception.Message -eq "relay_verify_external_process_output_too_large") { $oversized = $true }
    }
    if (-not $oversized) { Fail "relay_verify_bounded_process_self_test_oversize_not_rejected" }
  } finally {
    foreach ($fixturePath in @($utf16Fixture, $oddUtf16Fixture, $nulUtf8Fixture)) {
      if ([IO.File]::Exists($fixturePath)) { Remove-Item -LiteralPath $fixturePath -Force }
    }
    if ([IO.Directory]::Exists($captureRoot)) { Remove-Item -LiteralPath $captureRoot -Force }
  }
}

function Get-SafeFullPath {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [switch]$MustExist,
    [switch]$Leaf
  )
  if (-not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith("\\")) {
    Fail "relay_verify_unsafe_path"
  }
  $full = [IO.Path]::GetFullPath($Path)
  if ($full.StartsWith("\\?\") -or $full.StartsWith("\\.\") -or
      ($full.Length -gt 2 -and $full.Substring(2).Contains(":"))) {
    Fail "relay_verify_device_or_ads_path_rejected"
  }
  if ($MustExist -and -not ([IO.File]::Exists($full) -or [IO.Directory]::Exists($full))) {
    Fail "relay_verify_path_missing"
  }
  if ($Leaf -and -not [IO.File]::Exists($full)) { Fail "relay_verify_file_missing" }
  $cursor = if ([IO.File]::Exists($full)) { [IO.Path]::GetDirectoryName($full) } else { $full }
  while (-not [string]::IsNullOrEmpty($cursor)) {
    if ([IO.Directory]::Exists($cursor)) {
      $item = Get-Item -LiteralPath $cursor -Force
      if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail "relay_verify_reparse_ancestor_rejected"
      }
    }
    $parent = [IO.Directory]::GetParent($cursor)
    if ($null -eq $parent) { break }
    $cursor = $parent.FullName
  }
  if ([IO.File]::Exists($full)) {
    $leafItem = Get-Item -LiteralPath $full -Force
    if (($leafItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      Fail "relay_verify_reparse_leaf_rejected"
    }
  }
  return $full
}

function Get-ScOutput {
  param([Parameter(Mandatory = $true)][string[]]$Arguments)
  $output = @(& sc.exe @Arguments 2>&1)
  if ($LASTEXITCODE -ne 0) { Fail "relay_verify_scm_query_failed" }
  return ($output -join "`n")
}

function Get-ServiceSid {
  param([Parameter(Mandatory = $true)][string]$Name)
  try {
    $account = New-Object Security.Principal.NTAccount("NT SERVICE\$Name")
    $sid = $account.Translate([Security.Principal.SecurityIdentifier]).Value
  } catch {
    Fail "relay_verify_service_sid_resolution_failed"
  }
  if ($sid -notmatch '^S-1-5-80-(?:[0-9]+-){4}[0-9]+$') {
    Fail "relay_verify_service_sid_invalid"
  }
  return $sid
}

function Assert-ExactServiceStoreAcl {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$ServiceSid
  )
  $acl = Get-Acl -LiteralPath $Path
  $allowed = @("S-1-5-18", "S-1-5-32-544", $ServiceSid)
  $seen = @{}
  if (-not $acl.AreAccessRulesProtected) { Fail "relay_verify_store_acl_inheritance_enabled" }
  $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if ($ownerSid -notin @("S-1-5-18", "S-1-5-32-544")) {
    Fail "relay_verify_store_owner_invalid"
  }
  foreach ($entry in $acl.Access) {
    if ($entry.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $entry.IsInherited -or
        $entry.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
        $entry.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or
        $entry.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) {
      Fail "relay_verify_store_acl_rule_invalid"
    }
    $sid = $entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    if ($allowed -notcontains $sid -or $sid -eq "S-1-5-19") {
      Fail "relay_verify_store_acl_principal_invalid"
    }
    if ($seen.ContainsKey($sid)) { Fail "relay_verify_store_acl_duplicate_principal" }
    $seen[$sid] = $true
  }
  if ($seen.Count -ne 3) { Fail "relay_verify_store_acl_count_invalid" }
  foreach ($sid in $allowed) {
    if (-not $seen.ContainsKey($sid)) { Fail "relay_verify_store_acl_principal_missing" }
  }
}

function Assert-ExactAgentReadAcl {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$AgentServiceSid,
    [switch]$Directory
  )
  $acl = Get-Acl -LiteralPath $Path
  if (-not $acl.AreAccessRulesProtected) { Fail "relay_verify_read_acl_inheritance_enabled" }
  if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @("S-1-5-18", "S-1-5-32-544")) {
    Fail "relay_verify_read_owner_invalid"
  }
  $allowed = @("S-1-5-18", "S-1-5-32-544", $AgentServiceSid)
  $seen = @{}
  foreach ($entry in $acl.Access) {
    $sid = $entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    $expectedRights = if ($sid -eq $AgentServiceSid) {
      [Security.AccessControl.FileSystemRights]::ReadAndExecute
    } else {
      [Security.AccessControl.FileSystemRights]::FullControl
    }
    $expectedInheritance = if ($Directory) {
      [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
      [Security.AccessControl.InheritanceFlags]::None
    }
    if ($entry.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $entry.IsInherited -or $allowed -notcontains $sid -or $seen.ContainsKey($sid) -or
        $entry.FileSystemRights -ne $expectedRights -or
        $entry.InheritanceFlags -ne $expectedInheritance -or
        $entry.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
      Fail "relay_verify_read_acl_rule_invalid"
    }
    $seen[$sid] = $true
  }
  if ($seen.Count -ne 3) { Fail "relay_verify_read_acl_count_invalid" }
  foreach ($sid in $allowed) {
    if (-not $seen.ContainsKey($sid)) { Fail "relay_verify_read_acl_principal_missing" }
  }
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
  if (($Entry.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) {
    return $true
  }
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
  if (-not [IO.Directory]::Exists($Path)) { Fail "relay_verify_boundary_missing" }
  $item = Get-Item -LiteralPath $Path -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail "relay_verify_boundary_reparse_rejected"
  }
  $acl = Get-Acl -LiteralPath $Path
  if (-not $acl.AreAccessRulesProtected -or
      $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @("S-1-5-18", "S-1-5-32-544")) {
    Fail "relay_verify_boundary_owner_or_inheritance_invalid"
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
      Fail "relay_verify_boundary_acl_invalid"
    }
    $seen[$sid] = $true
  }
  if ($seen.Count -ne 2) { Fail "relay_verify_boundary_acl_count_invalid" }
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
    Fail "relay_verify_acl_self_test_read_rejected"
  }
  $createRule = [Security.AccessControl.FileSystemAccessRule]::new(
    $untrusted,
    ([Security.AccessControl.FileSystemRights]::WriteData -bor
      [Security.AccessControl.FileSystemRights]::AppendData),
    $noneInheritance, $nonePropagation, $allow)
  if (-not (Test-AncestorAccessRuleAllowed $createRule $true $trustedWriters)) {
    Fail "relay_verify_acl_self_test_system_create_rejected"
  }
  if (-not (Test-AncestorAccessRuleAllowed $createRule $false $trustedWriters)) {
    Fail "relay_verify_acl_self_test_custom_create_rejected"
  }
  $propagatingCreateRule = [Security.AccessControl.FileSystemAccessRule]::new(
    $untrusted, [Security.AccessControl.FileSystemRights]::AppendData,
    [Security.AccessControl.InheritanceFlags]::ObjectInherit,
    $nonePropagation, $allow)
  if (-not (Test-AncestorAccessRuleAllowed $propagatingCreateRule $true $trustedWriters)) {
    Fail "relay_verify_acl_self_test_propagating_create_rejected"
  }
  $inheritOnlyDeleteRule = [Security.AccessControl.FileSystemAccessRule]::new(
    $untrusted, [Security.AccessControl.FileSystemRights]::Delete,
    [Security.AccessControl.InheritanceFlags]::ObjectInherit,
    [Security.AccessControl.PropagationFlags]::InheritOnly, $allow)
  if (-not (Test-AncestorAccessRuleAllowed $inheritOnlyDeleteRule $true $trustedWriters)) {
    Fail "relay_verify_acl_self_test_inherit_only_delete_rejected"
  }
  $deleteRule = [Security.AccessControl.FileSystemAccessRule]::new(
    $untrusted, [Security.AccessControl.FileSystemRights]::Delete,
    $noneInheritance, $nonePropagation, $allow)
  if (Test-AncestorAccessRuleAllowed $deleteRule $true $trustedWriters) {
    Fail "relay_verify_acl_self_test_effective_delete_accepted"
  }
  $trustedRule = [Security.AccessControl.FileSystemAccessRule]::new(
    $trusted, [Security.AccessControl.FileSystemRights]::FullControl,
    [Security.AccessControl.InheritanceFlags]::ContainerInherit,
    $nonePropagation, $allow)
  if (-not (Test-AncestorAccessRuleAllowed $trustedRule $false $trustedWriters)) {
    Fail "relay_verify_acl_self_test_trusted_writer_rejected"
  }
  foreach ($standardAncestor in @(
      [IO.Path]::GetPathRoot($env:ProgramData), $env:ProgramData, $env:ProgramFiles
    )) {
    $systemManaged = $standardAncestor -ieq [IO.Path]::GetPathRoot($env:ProgramData) -or
      $standardAncestor -ieq $env:ProgramData
    foreach ($entry in (Get-Acl -LiteralPath $standardAncestor).Access) {
      if (-not (Test-AncestorAccessRuleAllowed $entry $systemManaged $trustedWriters)) {
        Fail "relay_verify_acl_self_test_standard_ancestor_rejected"
      }
    }
  }
}

function Assert-TrustedManagedAncestorAcl {
  param(
    [Parameter(Mandatory = $true)][string]$ManagedRoot,
    [Parameter(Mandatory = $true)][string]$AgentServiceSid,
    [Parameter(Mandatory = $true)][string]$BrokerServiceSid
  )
  $trustedOwners = @("S-1-5-18", "S-1-5-32-544")
  try {
    $trustedInstaller = New-Object Security.Principal.NTAccount("NT SERVICE\TrustedInstaller")
    $trustedOwners += $trustedInstaller.Translate([Security.Principal.SecurityIdentifier]).Value
  } catch {
    Fail "relay_verify_trusted_installer_sid_invalid"
  }
  $cursor = $ManagedRoot
  while (-not [string]::IsNullOrEmpty($cursor)) {
    if ([IO.Directory]::Exists($cursor)) {
      $ancestorAcl = Get-Acl -LiteralPath $cursor
      $owner = $ancestorAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value
      if ($trustedOwners -notcontains $owner) { Fail "relay_verify_ancestor_owner_invalid" }
      $isSystemManagedAncestor = @($SystemManagedAncestorAllowlist | Where-Object { $_ -ieq $cursor }).Count -eq 1
      foreach ($entry in $ancestorAcl.Access) {
        if (-not (Test-AncestorAccessRuleAllowed $entry $isSystemManagedAncestor $trustedOwners)) {
          Fail "relay_verify_ancestor_writer_invalid"
        }
      }
    }
    $parent = [IO.Directory]::GetParent($cursor)
    if ($null -eq $parent) { break }
    $cursor = $parent.FullName
  }
  $acl = Get-Acl -LiteralPath $ManagedRoot
  $allowed = @("S-1-5-18", "S-1-5-32-544", $AgentServiceSid, $BrokerServiceSid)
  $seen = @{}
  if (-not $acl.AreAccessRulesProtected) { Fail "relay_verify_managed_root_inheritance_enabled" }
  foreach ($entry in $acl.Access) {
    $sid = $entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    $expectedRights = if ($sid -in @($AgentServiceSid, $BrokerServiceSid)) {
      [Security.AccessControl.FileSystemRights]::ReadAndExecute
    } else {
      [Security.AccessControl.FileSystemRights]::FullControl
    }
    if ($entry.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $entry.IsInherited -or $allowed -notcontains $sid -or $seen.ContainsKey($sid) -or
        $entry.FileSystemRights -ne $expectedRights -or
        $entry.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
        $entry.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
      Fail "relay_verify_managed_root_acl_invalid"
    }
    $seen[$sid] = $true
  }
  if ($seen.Count -ne 4) { Fail "relay_verify_managed_root_acl_count_invalid" }
}

function Assert-ExactJsonKeys {
  param(
    [Parameter(Mandatory = $true)]$Value,
    [Parameter(Mandatory = $true)][string[]]$Keys,
    [Parameter(Mandatory = $true)][string]$Reason
  )
  $actual = @($Value.PSObject.Properties.Name | Sort-Object)
  $expected = @($Keys | Sort-Object)
  if (($actual -join "`n") -cne ($expected -join "`n")) { Fail $Reason }
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
  if (-not (Test-ExactDockerProductionSpec $good $mounts 5349)) { Fail "relay_verify_docker_spec_self_test_good_rejected" }
  $commandOverride = New-DockerProductionSpecFixture $mounts
  $commandOverride.Args = @("--config", "/tmp/attacker.conf")
  if (Test-ExactDockerProductionSpec $commandOverride $mounts 5349) {
    Fail "relay_verify_docker_spec_self_test_command_override_accepted"
  }
  $extraCapability = New-DockerProductionSpecFixture $mounts
  $extraCapability.HostConfig.CapAdd = @("NET_ADMIN")
  if (Test-ExactDockerProductionSpec $extraCapability $mounts 5349) {
    Fail "relay_verify_docker_spec_self_test_extra_capability_accepted"
  }
  $rootUser = New-DockerProductionSpecFixture $mounts
  $rootUser.Config.User = ""
  if (Test-ExactDockerProductionSpec $rootUser $mounts 5349) {
    Fail "relay_verify_docker_spec_self_test_root_user_accepted"
  }
  $hostPid = New-DockerProductionSpecFixture $mounts
  $hostPid.HostConfig.PidMode = "host"
  if (Test-ExactDockerProductionSpec $hostPid $mounts 5349) {
    Fail "relay_verify_docker_spec_self_test_host_pid_accepted"
  }
  $device = New-DockerProductionSpecFixture $mounts
  $device.HostConfig.Devices = @([pscustomobject]@{ PathOnHost = "C:\\device" })
  if (Test-ExactDockerProductionSpec $device $mounts 5349) {
    Fail "relay_verify_docker_spec_self_test_device_accepted"
  }
  $nullDevices = New-DockerProductionSpecFixture $mounts
  $nullDevices.HostConfig.Devices = $null
  if (-not (Test-ExactDockerProductionSpec $nullDevices $mounts 5349)) {
    Fail "relay_verify_docker_spec_self_test_null_devices_rejected"
  }
}

function Assert-AuthenticodeAndHash {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$ExpectedHash
  )
  if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ine $ExpectedHash) {
    Fail "relay_verify_binary_hash_mismatch"
  }
  $signature = Get-AuthenticodeSignature -LiteralPath $Path
  if ($signature.Status -ne "Valid") { Fail "relay_verify_binary_signature_invalid" }
}

if ($SelfTest) {
  Invoke-SelfTest
  exit 0
}

if ($Target -ceq "Wsl2") {
  # WSL registrations are per-token; the broker owns the LocalSystem namespace.
  Assert-CurrentProcessIsLocalSystem
}

$InstallRoot = Get-SafeFullPath $InstallRoot -MustExist
$DataRoot = Get-SafeFullPath $DataRoot -MustExist
if ($Target -ceq "Docker") { Assert-DockerMountSafeDataRoot $DataRoot }
$agentBinary = Get-SafeFullPath ([IO.Path]::Combine($InstallRoot, "mrd-relay-agent.exe")) -MustExist -Leaf
$brokerBinary = Get-SafeFullPath ([IO.Path]::Combine($InstallRoot, "mrd-relay-coturn-control.exe")) -MustExist -Leaf
$agentConfigPath = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, "config", "agent.json")) -MustExist -Leaf
$targetConfigPath = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, "broker", "target.json")) -MustExist -Leaf
$brokerConfigPath = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, "broker", "broker.json")) -MustExist -Leaf
$manifestPath = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, "install-manifest.json")) -MustExist -Leaf
$enrollmentBlob = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, "secrets", "enrollment-token.dpapi")) -MustExist -Leaf
$turnBlob = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, "secrets", "turn-rest-secret.dpapi")) -MustExist -Leaf
$turnBaselinePath = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, "broker", "turnserver.conf.base")) -MustExist -Leaf
$tlsCertificatePath = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, "tls", "fullchain.pem")) -MustExist -Leaf
$tlsPrivateKeyPath = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, "tls", "privkey.pem")) -MustExist -Leaf
$trustedCaPath = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, "config", "trusted-ca.pem")) -MustExist -Leaf
$identityPath = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, "state", "identity.json")) -MustExist -Leaf
$runtimeStatePath = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, "state", "runtime.json")) -MustExist -Leaf
$activeTurnSecretPath = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, "broker", "active-turn-secret.dpapi")) -MustExist -Leaf
$brokerRuntimeStatePath = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, "broker", "control-state.dpapi")) -MustExist -Leaf
$brokerJournalPath = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, "broker", "control-journal.dpapi")) -MustExist -Leaf
$agentServiceSid = Get-ServiceSid $AgentServiceName
$brokerServiceSid = Get-ServiceSid $BrokerServiceName

foreach ($blob in @($enrollmentBlob, $turnBlob, $identityPath, $runtimeStatePath)) {
  Assert-ExactServiceStoreAcl $blob $agentServiceSid
  $length = (Get-Item -LiteralPath $blob -Force).Length
  if ($length -le 0 -or $length -gt 1048576) { Fail "relay_verify_agent_store_size_invalid" }
}
Assert-ExactAgentReadAcl $agentConfigPath $agentServiceSid
Assert-ExactAgentReadAcl $trustedCaPath $agentServiceSid
foreach ($blob in @(
    $targetConfigPath, $brokerConfigPath, $turnBaselinePath,
    $activeTurnSecretPath, $brokerRuntimeStatePath, $brokerJournalPath
  )) {
  Assert-ExactServiceStoreAcl $blob $brokerServiceSid
  $length = (Get-Item -LiteralPath $blob -Force).Length
  if ($length -le 0 -or $length -gt 1048576) { Fail "relay_verify_broker_store_size_invalid" }
}
foreach ($tlsPath in @($tlsCertificatePath, $tlsPrivateKeyPath)) {
  Assert-ExactServiceStoreAcl $tlsPath $brokerServiceSid
  if ((Get-Item -LiteralPath $tlsPath -Force).Length -le 0) { Fail "relay_verify_tls_file_empty" }
}
Assert-ExactAgentReadAcl ([IO.Path]::Combine($DataRoot, "config")) $agentServiceSid -Directory
Assert-ExactServiceStoreAcl ([IO.Path]::Combine($DataRoot, "secrets")) $agentServiceSid
Assert-ExactServiceStoreAcl ([IO.Path]::Combine($DataRoot, "state")) $agentServiceSid
Assert-ExactServiceStoreAcl ([IO.Path]::Combine($DataRoot, "broker")) $brokerServiceSid
Assert-ExactServiceStoreAcl ([IO.Path]::Combine($DataRoot, "tls")) $brokerServiceSid
Assert-TrustedManagedAncestorAcl $DataRoot $agentServiceSid $brokerServiceSid
if ([IO.Path]::GetDirectoryName($DataRoot) -ieq $DefaultManagedBoundary) {
  Assert-ExactSystemAdminBoundaryAcl $DefaultManagedBoundary
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$targetConfiguration = Get-Content -LiteralPath $targetConfigPath -Raw | ConvertFrom-Json
$brokerConfiguration = Get-Content -LiteralPath $brokerConfigPath -Raw | ConvertFrom-Json
$agentConfiguration = Get-Content -LiteralPath $agentConfigPath -Raw | ConvertFrom-Json
Assert-ExactJsonKeys $agentConfiguration @(
  "backend_url", "node_id", "region", "failure_domain", "endpoints",
  "max_allocations", "max_egress_bps", "identity_path", "runtime_state_path",
  "trusted_ca_path", "metrics_url", "heartbeat_interval_seconds",
  "backend_backoff_cap_seconds", "target", "relay_min_port", "relay_max_port",
  "transport_capabilities", "tls_listener_port", "enrollment_token_path",
  "turn_rest_secret_path", "target_config"
) "relay_verify_agent_config_schema_invalid"
Assert-ExactJsonKeys $brokerConfiguration @(
  "schema_version", "pipe", "target_config_path", "enrollment_token_path",
  "turn_rest_secret_path", "pipe_acl", "verify_client_token_twice",
  "minimal_environment", "node_id", "broker_service_sid",
  "active_turn_secret_path", "runtime_state_path", "journal_path"
) "relay_verify_broker_config_schema_invalid"
if ($manifest.target -cne $Target -or $targetConfiguration.target -cne $Target) {
  Fail "relay_verify_target_mismatch"
}
if ($brokerConfiguration.pipe -cne $ControlPipeName -or
    $brokerConfiguration.verify_client_token_twice -ne $true -or
    $brokerConfiguration.pipe_acl.Count -ne 3 -or
    $brokerConfiguration.pipe_acl -notcontains "SYSTEM" -or
    $brokerConfiguration.pipe_acl -notcontains "BUILTIN\Administrators" -or
    $brokerConfiguration.pipe_acl -notcontains "NT SERVICE\$AgentServiceName" -or
    $brokerConfiguration.node_id -cne $agentConfiguration.node_id -or
    $brokerConfiguration.broker_service_sid -cne $brokerServiceSid -or
    $brokerConfiguration.active_turn_secret_path -cne $activeTurnSecretPath -or
    $brokerConfiguration.runtime_state_path -cne $brokerRuntimeStatePath -or
    $brokerConfiguration.journal_path -cne $brokerJournalPath -or
    $brokerConfiguration.target_config_path -cne $targetConfigPath -or
    $brokerConfiguration.enrollment_token_path -cne $enrollmentBlob -or
    $brokerConfiguration.turn_rest_secret_path -cne $turnBlob) {
  Fail "relay_verify_named_pipe_acl_or_token_check_invalid"
}
Assert-AuthenticodeAndHash $agentBinary $manifest.agent_sha256
Assert-AuthenticodeAndHash $brokerBinary $manifest.broker_sha256
if ((Get-FileHash -LiteralPath $turnBaselinePath -Algorithm SHA256).Hash -ine $manifest.turnserver_baseline_sha256 -or
    $targetConfiguration.turnserver_baseline_path -cne $turnBaselinePath) {
  Fail "relay_verify_turnserver_baseline_hash_invalid"
}
$baselinePairs = @{}
$baselineDeniedCount = 0
foreach ($rawLine in @(Get-Content -LiteralPath $turnBaselinePath)) {
  $line = $rawLine.Trim()
  if ([string]::IsNullOrEmpty($line) -or $line.StartsWith("#")) { continue }
  if ($line -like "*CHANGE_ME*") {
    Fail "relay_verify_turnserver_baseline_placeholder_invalid"
  }
  $parts = $line.Split('=', 2)
  $key = $parts[0]
  $value = if ($parts.Count -eq 2) { $parts[1] } else { "" }
  if ($key -ceq "denied-peer-ip") {
    $baselineDeniedCount++
  } elseif ($baselinePairs.ContainsKey($key)) {
    Fail "relay_verify_turnserver_baseline_duplicate"
  }
  $baselinePairs[$key] = $value
}
if ($baselineDeniedCount -ne 12 -or
    $baselinePairs["static-auth-secret"] -cne "__MRD_BROKER_SECRET_V1__" -or
    -not $baselinePairs.ContainsKey("unauthorized-ratelimit") -or
    $baselinePairs["unauthorized-ratelimit-rps"] -cne "10" -or
    [int]$baselinePairs["tls-listening-port"] -ne [int]$targetConfiguration.tls_port -or
    [int64]$baselinePairs["total-quota"] -ne [int64]$targetConfiguration.max_allocations -or
    ([int64]$baselinePairs["bps-capacity"] * 8) -ne [int64]$targetConfiguration.max_egress_bps -or
    [string]::IsNullOrEmpty([string]$baselinePairs["external-ip"]) -or
    [string]::IsNullOrEmpty([string]$baselinePairs["realm"]) -or
    [string]::IsNullOrEmpty([string]$baselinePairs["server-name"])) {
  Fail "relay_verify_turnserver_baseline_contract_invalid"
}
$expectedListeningIp = Get-ExpectedListeningIp ([string]$baselinePairs["external-ip"])
if ($baselinePairs["listening-ip"] -cne $expectedListeningIp) {
  Fail "relay_verify_listener_family_mismatch"
}
foreach ($endpoint in @($agentConfiguration.endpoints)) {
  $endpointMatch = [regex]::Match(
    [string]$endpoint,
    '^(?:turn|turns):(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):[0-9]{1,5}(?:\?transport=(?:udp|tcp))?$'
  )
  $endpointHost = if ($endpointMatch.Success) { $endpointMatch.Groups[1].Value.Trim('[', ']') } else { "" }
  if (-not $endpointMatch.Success -or
      $endpointHost -ine $baselinePairs["server-name"]) {
    Fail "relay_verify_endpoint_server_name_mismatch"
  }
  $endpointAddress = $null
  if ([Net.IPAddress]::TryParse($endpointHost, [ref]$endpointAddress)) {
    $publicAddress = $null
    if (-not [Net.IPAddress]::TryParse(
          ([string]$baselinePairs["external-ip"]).Split('/', 2)[0], [ref]$publicAddress) -or
        $endpointAddress.AddressFamily -ne $publicAddress.AddressFamily) {
      Fail "relay_verify_endpoint_listener_family_mismatch"
    }
  }
}

if ($agentConfiguration.PSObject.Properties.Name -contains "enrollment_token" -or
    $agentConfiguration.PSObject.Properties.Name -contains "turn_rest_secret") {
  Fail "relay_verify_inline_secret_rejected"
}
if ($agentConfiguration.enrollment_token_path -cne $enrollmentBlob -or
    $agentConfiguration.turn_rest_secret_path -cne $turnBlob -or
    $agentConfiguration.identity_path -cne $identityPath -or
    $agentConfiguration.runtime_state_path -cne $runtimeStatePath -or
    $agentConfiguration.trusted_ca_path -cne $trustedCaPath) {
  Fail "relay_verify_dpapi_credential_path_invalid"
}
$expectedProductionTarget = switch ($Target) {
  "Native" { "windows-service" }
  "Docker" { "docker" }
  "Wsl2" { "wsl2" }
}
if ($agentConfiguration.target -cne $expectedProductionTarget -or
    [int]$agentConfiguration.relay_min_port -ne 49160 -or
    [int]$agentConfiguration.relay_max_port -ne 49260 -or
    [int]$agentConfiguration.tls_listener_port -ne [int]$targetConfiguration.tls_port -or
    ($agentConfiguration.transport_capabilities -join ",") -cne "turn_udp,turn_tcp,turns_tcp" -or
    ($targetConfiguration.transport_capabilities -join ",") -cne "turn_udp,turn_tcp,turns_tcp" -or
    ($agentConfiguration.endpoints -join "`n") -cne ($targetConfiguration.configured_endpoints -join "`n")) {
  Fail "relay_verify_production_target_contract_invalid"
}
$agentTarget = $agentConfiguration.target_config
if ($agentTarget.agent_service_sid -cne $agentServiceSid -or
    $agentTarget.broker_executable -cne $brokerBinary -or
    $agentTarget.broker_sha256 -cne $manifest.broker_sha256) {
  Fail "relay_verify_agent_broker_identity_invalid"
}
$maxEgressBps = [int64]$agentConfiguration.max_egress_bps
$coturnBytesPerSecond = [int64]$targetConfiguration.coturn_bps_capacity_bytes_per_second
if ($maxEgressBps -le 0 -or ($maxEgressBps % 8) -ne 0 -or
    ($coturnBytesPerSecond * 8) -ne $maxEgressBps) {
  Fail "relay_verify_bandwidth_unit_mismatch"
}
if ([int64]$agentConfiguration.max_allocations -ne [int64]$targetConfiguration.max_allocations -or
    [int64]$targetConfiguration.max_allocations -gt 100 -or
    [int]$targetConfiguration.relay_port_min -ne 49160 -or
    [int]$targetConfiguration.relay_port_max -ne 49260) {
  Fail "relay_verify_capacity_mismatch"
}

$agentSidType = Get-ScOutput @("qsidtype", $AgentServiceName)
$brokerSidType = Get-ScOutput @("qsidtype", $BrokerServiceName)
if ($agentSidType -notmatch 'RESTRICTED' -or $brokerSidType -notmatch 'RESTRICTED') {
  Fail "relay_verify_service_sid_not_restricted"
}
$agentFailure = Get-ScOutput @("qfailure", $AgentServiceName)
$agentFailureFlag = Get-ScOutput @("qfailureflag", $AgentServiceName)
if ($agentFailure -notmatch '4294967295' -or $agentFailure -notmatch '5000' -or
    $agentFailure -notmatch '30000' -or $agentFailure -notmatch 'NONE' -or
    $agentFailureFlag -notmatch '(?:FALSE|0)') {
  Fail "relay_verify_scm_crash_only_recovery_invalid"
}
$brokerFailure = Get-ScOutput @("qfailure", $BrokerServiceName)
$brokerFailureFlag = Get-ScOutput @("qfailureflag", $BrokerServiceName)
if ($brokerFailure -notmatch '4294967295' -or $brokerFailure -notmatch '5000' -or
    $brokerFailure -notmatch '30000' -or $brokerFailure -notmatch 'NONE' -or
    $brokerFailureFlag -notmatch '(?:FALSE|0)') {
  Fail "relay_verify_broker_crash_only_recovery_invalid"
}
# Canonical policy: restart/5000/restart/30000/none/0, reset 4294967295.

foreach ($serviceName in @($AgentServiceName, $BrokerServiceName)) {
  $registryPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$serviceName"
  $serviceRegistry = Get-ItemProperty -LiteralPath $registryPath
  if ([int]$serviceRegistry.Start -ne 2 -or [int]$serviceRegistry.DelayedAutoStart -ne 1) {
    Fail "relay_verify_delayed_auto_start_invalid"
  }
}

$agentState = Get-ScOutput @("query", $AgentServiceName)
$brokerState = Get-ScOutput @("query", $BrokerServiceName)
if ($agentState -notmatch 'RUNNING' -or $brokerState -notmatch 'RUNNING') {
  Fail "relay_verify_service_inactive"
}
$agentConfigurationOutput = Get-ScOutput @("qc", $AgentServiceName)
$brokerConfigurationOutput = Get-ScOutput @("qc", $BrokerServiceName)
if ($agentConfigurationOutput -notmatch [regex]::Escape($agentBinary) -or
    $agentConfigurationOutput -notmatch 'LocalService' -or
    $brokerConfigurationOutput -notmatch [regex]::Escape($brokerBinary) -or
    $brokerConfigurationOutput -notmatch 'LocalSystem') {
  Fail "relay_verify_service_binary_or_account_invalid"
}

switch ($Target) {
  "Native" {
    Assert-ExactJsonKeys $agentTarget @(
      "kind", "agent_service_sid", "broker_executable", "broker_sha256",
      "native_wrapper", "native_wrapper_sha256", "native_wrapper_signer"
    ) "relay_verify_native_agent_target_schema_invalid"
    if ($agentTarget.kind -cne "windows-service" -or
        $agentTarget.native_wrapper -cne $targetConfiguration.VerifiedNativeDrainWrapper -or
        $agentTarget.native_wrapper_sha256 -cne $targetConfiguration.native_wrapper_sha256 -or
        $agentTarget.native_wrapper_signer -cne $targetConfiguration.native_wrapper_signer) {
      Fail "relay_verify_native_agent_target_invalid"
    }
    $wrapperPath = Get-SafeFullPath ([string]$targetConfiguration.VerifiedNativeDrainWrapper) -MustExist -Leaf
    Assert-AuthenticodeAndHash $wrapperPath ([string]$targetConfiguration.native_wrapper_sha256)
    $wrapperSignature = Get-AuthenticodeSignature -LiteralPath $wrapperPath
    if ($null -eq $wrapperSignature.SignerCertificate -or
        $wrapperSignature.SignerCertificate.Subject -cne $targetConfiguration.native_wrapper_signer) {
      Fail "relay_verify_native_wrapper_signer_invalid"
    }
    $nativeCoturnPath = Get-SafeFullPath ([string]$targetConfiguration.native_coturn_binary) -MustExist -Leaf
    Assert-AuthenticodeAndHash $nativeCoturnPath ([string]$targetConfiguration.native_coturn_sha256)
    $nativeFailure = Get-ScOutput @("qfailure", $NativeCoturnServiceName)
    if ($nativeFailure -notmatch 'NONE' -or $nativeFailure -match 'RESTART') {
      Fail "relay_verify_native_RestartPolicy_must_be_Restart=no"
    }
    if ($Drained -and (Get-ScOutput @("query", $NativeCoturnServiceName)) -notmatch 'STOPPED') {
      Fail "relay_verify_native_drained_target_active"
    }
  }
  "Docker" {
    Assert-ExactJsonKeys $agentTarget @(
      "kind", "agent_service_sid", "broker_executable", "broker_sha256",
      "docker_executable", "canonical_image", "expected_container_id_state_path",
      "managed_label", "container_read_only", "restart_policy",
      "relay_udp_range_published", "published_ports", "read_only_mounts"
    ) "relay_verify_docker_agent_target_schema_invalid"
    if ($agentTarget.kind -cne "docker" -or
        $agentTarget.docker_executable -cne $targetConfiguration.docker_executable -or
        $agentTarget.canonical_image -cne $DockerImage -or
        $agentTarget.expected_container_id_state_path -cne $targetConfiguration.expected_container_id_state_path -or
        $agentTarget.managed_label -cne "io.mrd.relay.managed=true" -or
        $agentTarget.container_read_only -ne $true -or
        $agentTarget.restart_policy -cne "no" -or
        $agentTarget.relay_udp_range_published -ne $true) {
      Fail "relay_verify_docker_agent_target_invalid"
    }
    $dockerIdentityPath = Get-SafeFullPath ([string]$targetConfiguration.expected_container_id_state_path) -MustExist -Leaf
    if ($dockerIdentityPath -cne [IO.Path]::Combine($DataRoot, "broker", "docker-identity.json")) {
      Fail "relay_verify_docker_identity_path_invalid"
    }
    Assert-ExactServiceStoreAcl $dockerIdentityPath $brokerServiceSid
    $dockerEnvelopePath = Get-SafeFullPath ([IO.Path]::Combine($DataRoot, "broker", "docker-envelope")) -MustExist -Leaf
    Assert-ExactServiceStoreAcl $dockerEnvelopePath $brokerServiceSid
    if ((Get-Item -LiteralPath $dockerEnvelopePath -Force).Length -le 0) {
      Fail "relay_verify_docker_envelope_invalid"
    }
    $dockerIdentity = Get-Content -LiteralPath $dockerIdentityPath -Raw | ConvertFrom-Json
    $dockerIdentityKeys = @($dockerIdentity.PSObject.Properties.Name | Sort-Object)
    $expectedDockerIdentityKeys = @(
      "container_id", "generation", "image_id", "image_reference", "schema_version", "target"
    ) | Sort-Object
    if (($dockerIdentityKeys -join "`n") -cne ($expectedDockerIdentityKeys -join "`n") -or
        $dockerIdentity.schema_version -ne 1 -or $dockerIdentity.target -cne "docker" -or
        [int64]$dockerIdentity.generation -le 0 -or
        [string]$dockerIdentity.container_id -notmatch '^[0-9a-f]{64}$' -or
        [string]$dockerIdentity.image_id -notmatch '^sha256:[0-9a-f]{64}$' -or
        $dockerIdentity.image_reference -cne $DockerImage) {
      Fail "relay_verify_docker_persisted_identity_invalid"
    }
    $dockerPath = Get-SafeFullPath ([string]$targetConfiguration.docker_executable) -MustExist -Leaf
    Assert-AuthenticodeAndHash $dockerPath ([string]$manifest.target_manager_sha256)
    $inspectResult = Invoke-BoundedNativeProcess $dockerPath `
      @("inspect", $DockerContainerName) 30000 65536 "Utf8" ([IO.Path]::Combine($DataRoot, "broker"))
    if ($inspectResult.ExitCode -ne 0) { Fail "relay_verify_docker_container_missing" }
    $containers = @(($inspectResult.StdOut | ConvertFrom-Json))
    if ($containers.Count -ne 1) { Fail "relay_verify_docker_container_ambiguous" }
    $container = $containers[0]
    $imageResult = Invoke-BoundedNativeProcess $dockerPath `
      @("image", "inspect", $DockerImage) 30000 65536 "Utf8" ([IO.Path]::Combine($DataRoot, "broker"))
    if ($imageResult.ExitCode -ne 0) { Fail "relay_verify_docker_image_missing" }
    $images = @(($imageResult.StdOut | ConvertFrom-Json))
    if ($container.Id -cne $dockerIdentity.container_id -or
        $container.Image -cne $dockerIdentity.image_id -or
        $container.Image -cne $images[0].Id -or
        $container.Config.Image -cne $DockerImage -or
        $container.Config.Labels.'io.mrd.relay.managed' -cne "true" -or
        $container.HostConfig.RestartPolicy.Name -cne "no" -or
        $container.HostConfig.ReadonlyRootfs -ne $true -or
        ($Drained -and $container.State.Running -ne $false) -or
        (-not $Drained -and $container.State.Running -ne $true)) {
      Fail "relay_verify_docker_identity_or_RestartPolicy_invalid"
    }
    if (-not (Test-ExactDockerProductionSpec $container $targetConfiguration.bind_mounts ([int]$targetConfiguration.tls_port))) {
      Fail "relay_verify_docker_production_spec_invalid"
    }
    if (@($container.Mounts).Count -ne 2) { Fail "relay_verify_docker_mount_count_invalid" }
    foreach ($mount in $container.Mounts) {
      if ($mount.RW -ne $false) { Fail "relay_verify_docker_mount_not_read_only" }
    }
    $metricsBinding = $container.HostConfig.PortBindings.'9641/tcp'[0]
    if ($metricsBinding.HostIp -cne "127.0.0.1" -or $metricsBinding.HostPort -cne "9641") {
      Fail "relay_verify_docker_metrics_not_loopback"
    }
    foreach ($protocol in @("tcp", "udp")) {
      foreach ($relayPort in 49160..49260) {
        $bindingName = "$relayPort/$protocol"
        $bindingProperty = $container.HostConfig.PortBindings.PSObject.Properties[$bindingName]
        if ($null -eq $bindingProperty -or @($bindingProperty.Value).Count -ne 1 -or
            [string]$bindingProperty.Value[0].HostPort -cne [string]$relayPort) {
          Fail "relay_verify_docker_relay_range_mapping_invalid"
        }
      }
    }
    $expectedPublishedPorts = @(
      "3478:3478/udp", "3478:3478/tcp",
      "$($targetConfiguration.tls_port):$($targetConfiguration.tls_port)/tcp",
      "49160-49260:49160-49260/udp", "49160-49260:49160-49260/tcp",
      "127.0.0.1:9641:9641/tcp"
    )
    if (@($targetConfiguration.published_ports).Count -ne $expectedPublishedPorts.Count) {
      Fail "relay_verify_docker_port_mapping_invalid"
    }
    foreach ($port in $expectedPublishedPorts) {
      if ($targetConfiguration.published_ports -notcontains $port) {
        Fail "relay_verify_docker_port_mapping_invalid"
      }
    }
  }
  "Wsl2" {
    Assert-ExactJsonKeys $agentTarget @(
      "kind", "agent_service_sid", "broker_executable", "broker_sha256",
      "wsl_executable", "distro", "system_owned", "mirrored_networking"
    ) "relay_verify_wsl2_agent_target_schema_invalid"
    if ($agentTarget.kind -cne "wsl2" -or
        $agentTarget.wsl_executable -cne $targetConfiguration.wsl_executable -or
        $agentTarget.distro -cne $WslDistributionName -or
        $agentTarget.system_owned -ne $true -or
        $agentTarget.mirrored_networking -ne $true) {
      Fail "relay_verify_wsl2_agent_target_invalid"
    }
    $wslPath = Get-SafeFullPath ([string]$targetConfiguration.wsl_executable) -MustExist -Leaf
    Assert-AuthenticodeAndHash $wslPath ([string]$manifest.target_manager_sha256)
    if ($targetConfiguration.distribution -cne $WslDistributionName -or
        $targetConfiguration.owner -cne "LocalSystem" -or
        $targetConfiguration.networking_mode -cne "mirrored" -or
        $targetConfiguration.systemd_required -ne $true -or
        $targetConfiguration.IPAccounting -cne "yes" -or
        $targetConfiguration.live_udp_range_probe_required -ne $true) {
      Fail "relay_verify_wsl2_system_owned_mirrored_systemd_IPAccounting_invalid"
    }
  }
}

$expectedFirewall = @{
  "MRD Relay TURN UDP 3478" = @("UDP", "3478")
  "MRD Relay TURN TCP 3478" = @("TCP", "3478")
  "MRD Relay TURN TLS TCP" = @("TCP", [string]$targetConfiguration.tls_port)
  "MRD Relay Range UDP" = @("UDP", "49160-49260")
  "MRD Relay Range TCP" = @("TCP", "49160-49260")
}
foreach ($name in $expectedFirewall.Keys) {
  $rules = @(Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)
  if ($rules.Count -ne 1 -or $rules[0].Enabled -ne "True" -or
      $rules[0].Direction -ne "Inbound" -or $rules[0].Action -ne "Allow") {
    Fail "relay_verify_firewall_rule_invalid"
  }
  $filter = $rules[0] | Get-NetFirewallPortFilter
  if ([string]$filter.Protocol -cne $expectedFirewall[$name][0] -or
      [string]$filter.LocalPort -cne $expectedFirewall[$name][1]) {
    Fail "relay_verify_firewall_port_invalid"
  }
}

$random = New-Object byte[] 32
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($random) } finally { $rng.Dispose() }
$challenge = (($random | ForEach-Object { $_.ToString("x2") }) -join "")
[Array]::Clear($random, 0, $random.Length)
$expectedTarget = switch ($Target) {
  "Native" { "windows-service" }
  "Docker" { "docker" }
  "Wsl2" { "wsl2" }
}

$validateArguments = @("validate", "--config", $agentConfigPath)
$null = & $agentBinary @validateArguments
if ($LASTEXITCODE -ne 0) { Fail "relay_verify_static_validation_failed" }
if ($Drained) {
  $drainArguments = @("drain-proof", "--config", $agentConfigPath, "--challenge", $challenge)
  $drainLines = @(& $agentBinary @drainArguments)
  if ($LASTEXITCODE -ne 0 -or $drainLines.Count -ne 1) {
    Fail "relay_verify_drain_proof_failed"
  }
  Assert-DrainProofEvidence ([string]$drainLines[0]) $challenge $expectedTarget
  Write-Output "relay_verify_drained_passed scope=local"
  exit 0
}
$preflightArguments = @("preflight", "--config", $agentConfigPath, "--challenge", $challenge)
$preflightLines = @(& $agentBinary @preflightArguments)
if ($LASTEXITCODE -ne 0 -or $preflightLines.Count -ne 1) {
  Fail "relay_verify_live_preflight_failed"
}
Assert-PreflightEvidence ([string]$preflightLines[0]) $challenge $expectedTarget

# The exact local proof establishes listener + credential + allocation +
# permission + bidirectional relayed packets. scope=local never claims public
# reachability; public UDP/TCP/TLS/SNI/range acceptance remains Task 11.
Write-Output "relay_verify_passed scope=local"
