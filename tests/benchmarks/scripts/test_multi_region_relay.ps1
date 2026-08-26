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
Assert-True ($runner.Contains("exit 3")) "runner exposes INFRA_FAIL as exit 3"
Assert-True (-not $runner.Contains("continue-on-error")) "runner has no optional enforcement"

Write-Host "multi-region relay PowerShell contracts passed"
