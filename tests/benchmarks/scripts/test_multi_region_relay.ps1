$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptDir "multi_region_relay_common.ps1")

function Assert-True {
  param([bool]$Condition, [string]$Message)
  if (-not $Condition) { throw "ASSERT: $Message" }
}

function Assert-Equal {
  param($Actual, $Expected, [string]$Message)
  if ($Actual -ne $Expected) { throw "ASSERT: $Message (actual=$Actual expected=$Expected)" }
}

$allActions = foreach ($scenario in Get-MultiRegionRelayScenarioIds) {
  @(New-MultiRegionRelayActionPlan -Scenario $scenario).action
}
foreach ($required in @("process_kill", "network_outage", "udp_block", "tls_fallback", "drain")) {
  Assert-True ($required -in $allActions) "action plan contains $required"
}
$initialWanPlan = @(New-MultiRegionRelayActionPlan -Scenario "initial_wan_local")
Assert-True ("initial_wan_local" -notin @(Get-MultiRegionRelayScenarioIds)) "initial WAN local prerequisites do not block the existing all-device-lab matrix"
Assert-Equal @($initialWanPlan | Where-Object { $_.action -eq "run_initial_wan_row" }).Count 11 "initial WAN plan covers every required row"
Assert-Equal $initialWanPlan[$initialWanPlan.Count - 1].action "cleanup" "initial WAN plan ends with deterministic cleanup"

function New-TestInitialWanRow {
  param([string]$InvocationId, [string]$RowId)
  $negative = $RowId -in @("target_rejection", "capacity_exhaustion", "backend_loss_before_approval", "expired_generation")
  $negativeReasons = @{ target_rejection = "target_rejected"; capacity_exhaustion = "capacity_exhausted"; backend_loss_before_approval = "backend_unavailable_before_approval"; expired_generation = "generation_expired" }
  $migration = $RowId -eq "primary_failure_cross_failure_domain_migration"
  $grantObserved = -not $negative -or $RowId -eq "expired_generation"
  $targetApproved = -not $negative -or $RowId -in @("capacity_exhaustion", "expired_generation")
  $relayAccessObserved = -not $negative -or $RowId -eq "expired_generation"
  $transport = if ($RowId -eq "tcp_generation_zero") { "tcp" } elseif ($RowId -eq "tls_generation_zero") { "tls" } else { "udp" }
  [pscustomobject]@{
    schema_version = $script:InitialWanRowEvidenceVersion
    invocation_id = $InvocationId
    evidence_id = "$InvocationId`:$RowId"
    row = $RowId
    verdict = "PASS"
    topology = [pscustomobject]@{ controller_service_runtime = $true; target_service_runtime = $true; realtime_server = $true; fastapi_backend = $true; controller_runtime_id = "$InvocationId`:controller"; target_runtime_id = "$InvocationId`:target"; realtime_runtime_id = "$InvocationId`:realtime"; backend_runtime_id = "$InvocationId`:backend"; coturn_image = $script:PinnedCoturnImage; coturn_node_count = 2; regions = @("local-a", "local-b"); failure_domains = @("process-a", "process-b") }
    authorization = [pscustomobject]@{ attended = $true; intent_signature_verified = $true; grant_signature_verified = $grantObserved; scope_digest_equal = $grantObserved; target_approved = $targetApproved }
    generation = [pscustomobject]@{ controller = [uint64]$(if ($migration) { 1 } else { 0 }); target = [uint64]$(if ($migration) { 1 } else { 0 }); before_migration = [uint64]0; after_migration = [uint64]$(if ($migration) { 1 } else { 0 }) }
    reservation = [pscustomobject]@{ owner_verified = $relayAccessObserved; committed = -not $negative; session_id = "test-session"; controller_session_id = "test-session"; target_session_id = "test-session"; controller_directory_id = $(if ($relayAccessObserved) { "test-directory" } else { $null }); target_directory_id = $(if ($relayAccessObserved) { "test-directory" } else { $null }); controller_relay_url_digest = $(if ($relayAccessObserved) { "test-digest" } else { $null }); target_relay_url_digest = $(if ($relayAccessObserved) { "test-digest" } else { $null }); primary_reservation_id = $(if ($relayAccessObserved) { "test-primary" } else { $null }); backup_reservation_id = $(if ($relayAccessObserved) { "test-backup" } else { $null }) }
    selected_pair = [pscustomobject]@{ local_candidate_type = $(if ($negative) { "none" } else { "relay" }); remote_candidate_type = $(if ($negative) { "none" } else { "relay" }); transport = $transport; runtime_verified = -not $negative }
    traffic = [pscustomobject]@{ media_frames = [uint64]$(if ($negative) { 0 } else { 1 }); control_events = [uint64]$(if ($negative) { 0 } else { 1 }); realtime_control_events = [uint64]$(if ($negative) { 0 } else { 1 }); media_probe_id = "$InvocationId`:$RowId`:media"; control_probe_id = "$InvocationId`:$RowId`:control"; realtime_control_probe_id = "$InvocationId`:$RowId`:realtime-control" }
    fault = [pscustomobject]@{ expected_rejection = $(if ($negative) { $negativeReasons[$RowId] } else { $null }); transport_opened = -not $negative; primary_failed = $migration; cross_failure_domain = $migration; service_restart_count = [uint64]$(if ($RowId -eq "service_restart") { 1 } else { 0 }); service_runtime_before_id = $(if ($RowId -eq "service_restart") { "$InvocationId`:target:before-restart" } else { $null }); service_runtime_after_id = $(if ($RowId -eq "service_restart") { "$InvocationId`:target:after-restart" } else { $null }); signaling_disconnect_count = [uint64]$(if ($RowId -eq "signaling_disconnect") { 1 } else { 0 }); signaling_connection_before_id = $(if ($RowId -eq "signaling_disconnect") { "$InvocationId`:signal:before-disconnect" } else { $null }); signaling_connection_after_id = $(if ($RowId -eq "signaling_disconnect") { "$InvocationId`:signal:after-disconnect" } else { $null }) }
    cleanup = [pscustomobject]@{ release_all_recorded = $true; release_all_sequence = @("input_down", "release_all", "input_frozen"); reservation_released = $true; allocations_closed = $true; signaling_closed = $true; service_tasks_joined = $true; containers_removed = $true; created_container_names = @("mrd-wan-e2e-$InvocationId-coturn-a"); removed_container_names = @("mrd-wan-e2e-$InvocationId-coturn-a") }
    attestation = [pscustomobject]@{ key_id = "test-attestation"; signature_b64 = "TEST_ONLY_SIGNATURE" }
  }
}

$initialInvocation = "initial-contract-invocation"
$initialArtifact = [pscustomobject]@{
  schema_version = $script:InitialWanEvidenceVersion
  invocation_id = $initialInvocation
  scenario = [pscustomobject]@{ id = "initial_wan_local" }
  rows = @(Get-InitialWanRowIds | ForEach-Object { New-TestInitialWanRow -InvocationId $initialInvocation -RowId $_ })
}
Assert-Equal @(Get-InitialWanEvidenceFailures -Artifact $initialArtifact -ExpectedInvocationId $initialInvocation).Count 0 "complete initial WAN runtime evidence passes"
$initialReplay = $initialArtifact | ConvertTo-Json -Depth 24 | ConvertFrom-Json
$initialReplay.invocation_id = "stale-invocation"
Assert-True (@(Get-InitialWanEvidenceFailures -Artifact $initialReplay -ExpectedInvocationId $initialInvocation).Count -gt 0) "initial WAN evidence cannot be replayed"
$initialMetadataOnly = $initialArtifact | ConvertTo-Json -Depth 24 | ConvertFrom-Json
$initialMetadataOnly.rows[0].traffic.media_frames = 0
Assert-True (@(Get-InitialWanEvidenceFailures -Artifact $initialMetadataOnly -ExpectedInvocationId $initialInvocation).Count -gt 0) "initial WAN metadata without traffic cannot pass"
$initialRequests = New-Object System.Collections.Generic.List[object]
$initialControl = {
  param($Request)
  $initialRequests.Add($Request)
  if ($Request.action -eq "collect_evidence") {
    return [pscustomobject]@{ verdict = "PASS"; artifact = $initialArtifact }
  }
  [pscustomobject]@{ verdict = "PASS" }
}
$initialRun = Invoke-MultiRegionRelayScenario -Scenario "initial_wan_local" -ControlInvoker $initialControl -InvocationId $initialInvocation
Assert-Equal $initialRun.verdict "PASS" "initial WAN orchestration and evidence protocol agree"
Assert-Equal @($initialRequests | Where-Object { $_.action -eq "run_initial_wan_row" }).Count 11 "control receives eleven row actions"
Assert-Equal @($initialRequests | Where-Object { $_.action -eq "reset" }).Count 1 "control receives a deterministic reset"
foreach ($request in @($initialRequests | Where-Object { $_.action -eq "run_initial_wan_row" })) {
  Assert-True ($request.target -in @(Get-InitialWanRowIds)) "row action uses the target field shared by the Rust live protocol"
  Assert-Equal $request.invocation_id $initialInvocation "row action remains invocation-bound"
}

$repoRoot = (Resolve-Path (Join-Path $scriptDir "..\..\..")).Path
$validArtifact = Get-Content -LiteralPath (Join-Path $repoRoot "tests\quality-gates\fixtures\multi-region-relay-valid.json") -Raw | ConvertFrom-Json
function New-BoundMultiRegionRelayArtifact {
  param($Template, $Request)
  $artifact = $Template | ConvertTo-Json -Depth 24 | ConvertFrom-Json
  $artifact.run_id = [string]$Request.invocation_id
  $artifact.scenario.id = [string]$Request.scenario
  $artifact
}
$calls = New-Object System.Collections.Generic.List[string]
$successfulControl = {
  param($Request)
  $calls.Add([string]$Request.action)
  if ($Request.action -eq "collect_evidence") {
    return [pscustomobject]@{ verdict = "PASS"; artifact = (New-BoundMultiRegionRelayArtifact -Template $validArtifact -Request $Request) }
  }
  [pscustomobject]@{ verdict = "PASS" }
}
$success = Invoke-MultiRegionRelayScenario -Scenario "linux_primary_linux_backup" -ControlInvoker $successfulControl -InvocationId "success-invocation"
Assert-Equal $success.verdict "PASS" "complete runtime evidence passes deterministic orchestration"
Assert-Equal $calls[0] "preflight" "preflight is first"
Assert-Equal $calls[$calls.Count - 2] "reset" "reset runs after mutating actions"
Assert-Equal $calls[$calls.Count - 1] "collect_evidence" "evidence is collected after reset"

$replayedControl = {
  param($Request)
  if ($Request.action -eq "collect_evidence") {
    return [pscustomobject]@{ verdict = "PASS"; artifact = $validArtifact }
  }
  [pscustomobject]@{ verdict = "PASS" }
}
$replayed = Invoke-MultiRegionRelayScenario -Scenario "linux_primary_linux_backup" -ControlInvoker $replayedControl -InvocationId "fresh-invocation"
Assert-Equal $replayed.verdict "PRODUCT_FAIL" "an artifact from another invocation or scenario cannot be replayed"

$failedCalls = New-Object System.Collections.Generic.List[string]
$productFailureControl = {
  param($Request)
  $failedCalls.Add([string]$Request.action)
  if ($Request.action -eq "process_kill") {
    return [pscustomobject]@{ verdict = "PRODUCT_FAIL"; failure = "fault did not remove primary" }
  }
  if ($Request.action -eq "collect_evidence") {
    return [pscustomobject]@{ verdict = "PASS"; artifact = (New-BoundMultiRegionRelayArtifact -Template $validArtifact -Request $Request) }
  }
  [pscustomobject]@{ verdict = "PASS" }
}
$productFailure = Invoke-MultiRegionRelayScenario -Scenario "linux_primary_linux_backup" -ControlInvoker $productFailureControl -InvocationId "product-failure-invocation"
Assert-Equal $productFailure.verdict "PRODUCT_FAIL" "a failed product action fails the row"
Assert-True ("reset" -in $failedCalls) "reset still runs after product failure"

$metadataOnlyControl = {
  param($Request)
  if ($Request.action -eq "collect_evidence") {
    return [pscustomobject]@{ verdict = "PASS"; artifact = [pscustomobject]@{ route = [pscustomobject]@{ selected = "relay" } } }
  }
  [pscustomobject]@{ verdict = "PASS" }
}
$metadataOnly = Invoke-MultiRegionRelayScenario -Scenario "linux_primary_linux_backup" -ControlInvoker $metadataOnlyControl -InvocationId "metadata-only-invocation"
Assert-Equal $metadataOnly.verdict "PRODUCT_FAIL" "metadata-only relay claims cannot pass"

$infraDominates = Get-MultiRegionRelayVerdict -Results @(
  [pscustomobject]@{ verdict = "PRODUCT_FAIL" },
  [pscustomobject]@{ verdict = "INFRA_FAIL" }
)
Assert-Equal $infraDominates "INFRA_FAIL" "infrastructure failure dominates aggregation"

$missingConfiguration = @{}
foreach ($name in @(
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
)) {
  $missingConfiguration[$name] = ""
}
$missingInfrastructure = Test-MultiRegionRelayInfrastructure -Configuration $missingConfiguration
Assert-True (-not $missingInfrastructure.ready) "missing lab configuration is not a pass or skip"
Assert-True (@($missingInfrastructure.failures).Count -ge 10) "all required infrastructure classes are checked"

$secretPayload = [pscustomobject]@{ password = "must-not-appear" }
Assert-True (Test-MultiRegionRelayPayloadContainsSecretFields -Payload $secretPayload) "secret-bearing response fields are rejected"
Assert-True (-not (Test-MultiRegionRelayPayloadContainsSecretFields -Payload $validArtifact)) "committed evidence is secret-free"

$runner = Get-Content -LiteralPath (Join-Path $scriptDir "run_multi_region_relay.ps1") -Raw
Assert-True ($runner.Contains("Test-MultiRegionRelayInfrastructure")) "runner fails closed on missing infrastructure"
Assert-True ($runner.Contains("Invoke-MultiRegionRelayScenario")) "runner uses deterministic orchestration"
Assert-True ($runner.Contains("mrd-quality-gate")) "runner enforces the Rust evidence gate"
Assert-True ($runner.Contains("evidence_file_contract")) "runner validates the actual initial WAN artifact in Rust"
Assert-True ($runner.Contains("MRD_INITIAL_WAN_EVIDENCE_PATH")) "runner binds the initial WAN artifact path explicitly"
Assert-True ($runner.Contains("Invoke-InitialWanRunnerCleanup")) "runner independently verifies initial WAN container cleanup"
Assert-True ($runner.Contains("MRD_INITIAL_WAN_ATTESTATION_PUBLIC_KEY")) "runner requires a trusted initial WAN attestation key"
Assert-True ($runner.Contains("exit 3")) "runner exposes INFRA_FAIL as exit 3"
Assert-True (-not $runner.Contains("continue-on-error")) "runner has no optional enforcement"

Write-Host "multi-region relay PowerShell contracts passed"
