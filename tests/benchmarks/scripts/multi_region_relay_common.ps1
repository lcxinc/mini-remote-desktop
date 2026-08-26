$ErrorActionPreference = "Stop"

$script:MultiRegionRelaySummaryVersion = "multi-region-relay-summary.v1"
$script:MultiRegionRelayMaxControlOutputBytes = 1048576

function Write-MultiRegionRelayUtf8Json {
  param(
    [Parameter(Mandatory = $true)]$InputObject,
    [Parameter(Mandatory = $true)][string]$Path,
    [int]$Depth = 24
  )

  $parent = Split-Path -Parent $Path
  if ($parent) {
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
  }
  $json = ConvertTo-Json -InputObject $InputObject -Depth $Depth
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText([System.IO.Path]::GetFullPath($Path), $json, $utf8NoBom)
}

function Get-MultiRegionRelayScenarioIds {
  @(
    "linux_primary_linux_backup",
    "linux_primary_windows_backup",
    "failure_before_allocation",
    "regional_outage",
    "planned_drain",
    "soft_capacity",
    "hard_capacity",
    "udp_block_tls_fallback",
    "certificate_revocation",
    "backend_outage_existing_allocation",
    "backend_outage_expired_cache"
  )
}

function New-MultiRegionRelayActionPlan {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(
      "linux_primary_linux_backup",
      "linux_primary_windows_backup",
      "failure_before_allocation",
      "regional_outage",
      "planned_drain",
      "soft_capacity",
      "hard_capacity",
      "udp_block_tls_fallback",
      "certificate_revocation",
      "backend_outage_existing_allocation",
      "backend_outage_expired_cache"
    )]
    [string]$Scenario
  )

  $actions = New-Object System.Collections.Generic.List[object]
  $actions.Add([pscustomobject]@{ action = "preflight"; target = "lab" })
  switch ($Scenario) {
    "failure_before_allocation" {
      $actions.Add([pscustomobject]@{ action = "failure_before_allocation"; target = "primary" })
    }
    default {
      $actions.Add([pscustomobject]@{ action = "start_session"; target = "controller" })
    }
  }
  switch ($Scenario) {
    "linux_primary_linux_backup" {
      $actions.Add([pscustomobject]@{ action = "process_kill"; target = "primary_linux" })
    }
    "linux_primary_windows_backup" {
      $actions.Add([pscustomobject]@{ action = "process_kill"; target = "primary_linux" })
    }
    "failure_before_allocation" {
      $actions.Add([pscustomobject]@{ action = "verify_admission_failover"; target = "backup" })
    }
    "regional_outage" {
      $actions.Add([pscustomobject]@{ action = "network_outage"; target = "primary_region" })
    }
    "planned_drain" {
      $actions.Add([pscustomobject]@{ action = "drain"; target = "primary" })
    }
    "soft_capacity" {
      $actions.Add([pscustomobject]@{ action = "set_soft_capacity"; target = "primary" })
    }
    "hard_capacity" {
      $actions.Add([pscustomobject]@{ action = "set_hard_capacity"; target = "primary" })
    }
    "udp_block_tls_fallback" {
      $actions.Add([pscustomobject]@{ action = "udp_block"; target = "controller_to_relays" })
      $actions.Add([pscustomobject]@{ action = "tls_fallback"; target = "backup" })
    }
    "certificate_revocation" {
      $actions.Add([pscustomobject]@{ action = "certificate_revocation"; target = "primary" })
    }
    "backend_outage_existing_allocation" {
      $actions.Add([pscustomobject]@{ action = "backend_outage"; target = "control_plane" })
      $actions.Add([pscustomobject]@{ action = "verify_existing_allocation"; target = "controller" })
    }
    "backend_outage_expired_cache" {
      $actions.Add([pscustomobject]@{ action = "backend_outage"; target = "control_plane" })
      $actions.Add([pscustomobject]@{ action = "expire_directory_cache"; target = "controller" })
      $actions.Add([pscustomobject]@{ action = "verify_new_session_rejected"; target = "controller" })
    }
  }
  $actions.Add([pscustomobject]@{ action = "verify_recovery"; target = "controller" })
  $actions.Add([pscustomobject]@{ action = "cleanup"; target = "session" })
  $actions.ToArray()
}

function Get-MultiRegionRelayConfigValue {
  param([hashtable]$Configuration, [string]$Name)
  if ($null -ne $Configuration -and $Configuration.ContainsKey($Name)) {
    return [string]$Configuration[$Name]
  }
  [Environment]::GetEnvironmentVariable($Name)
}

function Test-MultiRegionRelayInfrastructure {
  param([hashtable]$Configuration)

  $failures = New-Object System.Collections.Generic.List[string]
  $requiredValues = @(
    "MRD_RELAY_LAB_CONTROL",
    "MRD_RELAY_LAB_CONTROLLER_HOST",
    "MRD_RELAY_LAB_AGENT_HOST",
    "MRD_RELAY_LAB_PRIMARY_NODE",
    "MRD_RELAY_LAB_BACKUP_NODE",
    "MRD_RELAY_LAB_WINDOWS_NODE",
    "MRD_RELAY_LAB_PRIMARY_CERT_PATH",
    "MRD_RELAY_LAB_BACKUP_CERT_PATH",
    "MRD_RELAY_LAB_UDP_PORT",
    "MRD_RELAY_LAB_TLS_PORT",
    "MRD_RELAY_LAB_AUTH_SECRET"
  )
  foreach ($name in $requiredValues) {
    $value = Get-MultiRegionRelayConfigValue -Configuration $Configuration -Name $name
    if (-not $value -or -not $value.Trim()) {
      $failures.Add("missing required infrastructure value: $name")
    }
  }

  foreach ($name in @("MRD_RELAY_LAB_CONTROL", "MRD_RELAY_LAB_PRIMARY_CERT_PATH", "MRD_RELAY_LAB_BACKUP_CERT_PATH")) {
    $value = Get-MultiRegionRelayConfigValue -Configuration $Configuration -Name $name
    if ($value -and -not (Test-Path -LiteralPath $value -PathType Leaf)) {
      $failures.Add("configured infrastructure file does not exist: $name")
    }
  }
  foreach ($name in @("MRD_RELAY_LAB_UDP_PORT", "MRD_RELAY_LAB_TLS_PORT")) {
    $value = Get-MultiRegionRelayConfigValue -Configuration $Configuration -Name $name
    $port = 0
    if ($value -and (-not [int]::TryParse($value, [ref]$port) -or $port -lt 1 -or $port -gt 65535)) {
      $failures.Add("configured infrastructure port is invalid: $name")
    }
  }
  [pscustomobject]@{
    ready = $failures.Count -eq 0
    failures = $failures.ToArray()
  }
}

function Test-MultiRegionRelayPayloadContainsSecretFields {
  param($Payload)
  if ($null -eq $Payload) { return $false }
  $json = ConvertTo-Json -InputObject $Payload -Depth 32 -Compress
  $json -match '"(?:password|secret|token|credential|private_key|private_key_pem)"\s*:'
}

function Get-MultiRegionRelayEvidenceFailures {
  param(
    $Artifact,
    [string]$ExpectedInvocationId,
    [string]$ExpectedScenario
  )

  $failures = New-Object System.Collections.Generic.List[string]
  if ($null -eq $Artifact) {
    $failures.Add("quality artifact is missing")
    return $failures.ToArray()
  }
  if ($null -eq $Artifact.relay) {
    $failures.Add("runtime relay evidence is missing")
    return $failures.ToArray()
  }
  if ($ExpectedInvocationId -and [string]$Artifact.run_id -ne $ExpectedInvocationId) {
    $failures.Add("artifact run_id is not bound to the invocation")
  }
  if ($ExpectedScenario -and [string]$Artifact.scenario.id -ne $ExpectedScenario) {
    $failures.Add("artifact scenario is not bound to the requested row")
  }
  $relay = $Artifact.relay
  if (-not [bool]$relay.directory.signature_verified) { $failures.Add("directory signature is unverified") }
  if (-not $relay.primary.failure_domain -or -not $relay.backup.failure_domain) { $failures.Add("failure domains are missing") }
  if ([string]$relay.primary.failure_domain -eq [string]$relay.backup.failure_domain) { $failures.Add("failure domains are not distinct") }
  if ([string]$relay.primary.region -eq [string]$relay.backup.region) { $failures.Add("regions are not distinct") }
  if (-not [bool]$relay.reservation.committed) { $failures.Add("capacity reservation is uncommitted") }
  if (
    [string]$relay.reservation.primary_node_id -ne [string]$relay.primary.node_id -or
    [string]$relay.reservation.backup_node_id -ne [string]$relay.backup.node_id
  ) {
    $failures.Add("capacity reservations are not bound to selected nodes")
  }
  if (
    [string]$relay.selected_pair.local_candidate_type -ne "relay" -or
    [string]$relay.selected_pair.remote_candidate_type -ne "relay" -or
    -not [bool]$relay.selected_pair.nominated -or
    -not [bool]$relay.selected_pair.runtime_verified
  ) {
    $failures.Add("selected pair is not runtime-verified relay/relay")
  }
  if (-not [bool]$relay.allocation.primary_established -or -not [bool]$relay.allocation.backup_established) {
    $failures.Add("TURN allocations are incomplete")
  }
  if (
    [string]$relay.allocation.primary_node_id -ne [string]$relay.primary.node_id -or
    [string]$relay.allocation.backup_node_id -ne [string]$relay.backup.node_id
  ) {
    $failures.Add("TURN allocations are not bound to selected nodes")
  }
  if ([uint64]$relay.generation.after -ne ([uint64]$relay.generation.before + 1)) {
    $failures.Add("migration generation did not advance once")
  }
  if (-not [bool]$relay.restored_media.media_resumed) { $failures.Add("media did not resume") }
  if (-not [bool]$relay.restored_media.permissions_unchanged) { $failures.Add("permissions changed") }
  if (-not [bool]$relay.restored_media.release_all_recorded) { $failures.Add("ReleaseAll is missing") }
  if (
    -not [bool]$relay.cleanup.reservation_released -or
    -not [bool]$relay.cleanup.old_allocation_closed -or
    -not [bool]$relay.cleanup.replacement_allocation_closed -or
    -not [bool]$relay.cleanup.input_thawed -or
    -not [bool]$relay.cleanup.lab_reset
  ) {
    $failures.Add("cleanup evidence is incomplete")
  }
  if (Test-MultiRegionRelayPayloadContainsSecretFields -Payload $Artifact) {
    $failures.Add("artifact contains a forbidden secret field")
  }
  $failures.ToArray()
}

function Get-MultiRegionRelayVerdict {
  param([object[]]$Results)
  if (@($Results | Where-Object { $_.verdict -eq "INFRA_FAIL" }).Count -gt 0) {
    return "INFRA_FAIL"
  }
  if (@($Results | Where-Object { $_.verdict -ne "PASS" }).Count -gt 0) {
    return "PRODUCT_FAIL"
  }
  "PASS"
}

function ConvertTo-MultiRegionRelayControlResult {
  param($Response, [string]$Action)
  if ($null -eq $Response) {
    return [pscustomobject]@{ action = $Action; verdict = "INFRA_FAIL"; failure = "control returned no response" }
  }
  $verdict = [string]$Response.verdict
  if ($verdict -notin @("PASS", "PRODUCT_FAIL", "INFRA_FAIL")) {
    return [pscustomobject]@{ action = $Action; verdict = "INFRA_FAIL"; failure = "control returned an invalid verdict" }
  }
  [pscustomobject]@{
    action = $Action
    verdict = $verdict
    failure = [string]$Response.failure
    artifact = $Response.artifact
  }
}

function Invoke-MultiRegionRelayScenario {
  param(
    [Parameter(Mandatory = $true)][string]$Scenario,
    [Parameter(Mandatory = $true)][scriptblock]$ControlInvoker,
    [string]$InvocationId = ([Guid]::NewGuid().ToString("N"))
  )

  $results = New-Object System.Collections.Generic.List[object]
  $stopActions = $false
  try {
    foreach ($step in @(New-MultiRegionRelayActionPlan -Scenario $Scenario)) {
      if ($stopActions) { break }
      $request = [pscustomobject]@{
        schema_version = 1
        invocation_id = $InvocationId
        scenario = $Scenario
        action = $step.action
        target = $step.target
      }
      try {
        $result = ConvertTo-MultiRegionRelayControlResult -Response (& $ControlInvoker $request) -Action $step.action
      } catch {
        $result = [pscustomobject]@{ action = $step.action; verdict = "INFRA_FAIL"; failure = $_.Exception.Message }
      }
      $results.Add($result)
      $stopActions = $result.verdict -ne "PASS"
    }
  } finally {
    $resetRequest = [pscustomobject]@{
      schema_version = 1
      invocation_id = $InvocationId
      scenario = $Scenario
      action = "reset"
      target = "lab"
    }
    try {
      $results.Add((ConvertTo-MultiRegionRelayControlResult -Response (& $ControlInvoker $resetRequest) -Action "reset"))
    } catch {
      $results.Add([pscustomobject]@{ action = "reset"; verdict = "INFRA_FAIL"; failure = $_.Exception.Message })
    }
  }

  $collectRequest = [pscustomobject]@{
    schema_version = 1
    invocation_id = $InvocationId
    scenario = $Scenario
    action = "collect_evidence"
    target = "lab"
  }
  try {
    $results.Add((ConvertTo-MultiRegionRelayControlResult -Response (& $ControlInvoker $collectRequest) -Action "collect_evidence"))
  } catch {
    $results.Add([pscustomobject]@{ action = "collect_evidence"; verdict = "INFRA_FAIL"; failure = $_.Exception.Message })
  }

  $artifact = @($results | Where-Object { $_.action -eq "collect_evidence" } | Select-Object -Last 1).artifact
  $evidenceFailures = @(
    Get-MultiRegionRelayEvidenceFailures `
      -Artifact $artifact `
      -ExpectedInvocationId $InvocationId `
      -ExpectedScenario $Scenario
  )
  foreach ($failure in $evidenceFailures) {
    $results.Add([pscustomobject]@{ action = "evidence_validation"; verdict = "PRODUCT_FAIL"; failure = $failure })
  }
  [pscustomobject]@{
    scenario = $Scenario
    invocation_id = $InvocationId
    verdict = Get-MultiRegionRelayVerdict -Results $results.ToArray()
    actions = $results.ToArray()
    artifact = $artifact
  }
}

function Invoke-MultiRegionRelayLabControl {
  param(
    [Parameter(Mandatory = $true)][string]$ControlPath,
    [Parameter(Mandatory = $true)]$Request,
    [int]$TimeoutSeconds = 120
  )

  if (-not (Test-Path -LiteralPath $ControlPath -PathType Leaf)) {
    throw "configured lab-control executable is missing"
  }
  $startInfo = New-Object System.Diagnostics.ProcessStartInfo
  $startInfo.FileName = [System.IO.Path]::GetFullPath($ControlPath)
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardInput = $true
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  $process = New-Object System.Diagnostics.Process
  $process.StartInfo = $startInfo
  if (-not $process.Start()) { throw "lab-control process did not start" }
  $stdoutTask = $process.StandardOutput.ReadToEndAsync()
  $stderrTask = $process.StandardError.ReadToEndAsync()
  $requestJson = ConvertTo-Json -InputObject $Request -Depth 8 -Compress
  $process.StandardInput.WriteLine($requestJson)
  $process.StandardInput.Close()
  if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
    try { $process.Kill() } catch {}
    throw "lab-control process timed out"
  }
  $stdout = $stdoutTask.GetAwaiter().GetResult()
  $stderr = $stderrTask.GetAwaiter().GetResult()
  if ($stdout.Length -gt $script:MultiRegionRelayMaxControlOutputBytes -or $stderr.Length -gt $script:MultiRegionRelayMaxControlOutputBytes) {
    throw "lab-control output exceeded the bounded response size"
  }
  if ($process.ExitCode -ne 0) {
    $verdict = if ($process.ExitCode -eq 2) { "PRODUCT_FAIL" } else { "INFRA_FAIL" }
    return [pscustomobject]@{ verdict = $verdict; failure = "lab-control exited with code $($process.ExitCode)" }
  }
  try {
    $response = $stdout | ConvertFrom-Json
  } catch {
    throw "lab-control returned invalid JSON"
  }
  $secret = [Environment]::GetEnvironmentVariable("MRD_RELAY_LAB_AUTH_SECRET")
  if ($secret -and ($stdout.Contains($secret) -or $stderr.Contains($secret))) {
    throw "lab-control exposed configured secret material"
  }
  if (Test-MultiRegionRelayPayloadContainsSecretFields -Payload $response) {
    throw "lab-control response contains a forbidden secret field"
  }
  $response
}
