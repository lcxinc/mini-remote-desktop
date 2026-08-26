param(
  [ValidateSet(
    "all",
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
  [string]$Scenario = "all",
  [string]$OutputRoot = "artifacts/e2e/multi-region-relay",
  [string]$RepoRoot = "",
  [string]$LabControlPath = $env:MRD_RELAY_LAB_CONTROL,
  [string]$CargoCommand = "cargo"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptDir "multi_region_relay_common.ps1")
if (-not $RepoRoot) {
  $RepoRoot = (Resolve-Path (Join-Path $scriptDir "..\..\..")).Path
}
$OutputRoot = if ([System.IO.Path]::IsPathRooted($OutputRoot)) {
  [System.IO.Path]::GetFullPath($OutputRoot)
} else {
  [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $OutputRoot))
}
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$summaryPath = Join-Path $OutputRoot "multi-region-relay-summary.json"
$infrastructure = Test-MultiRegionRelayInfrastructure
if (-not (Get-Command $CargoCommand -ErrorAction SilentlyContinue)) {
  $infrastructure = [pscustomobject]@{
    ready = $false
    failures = @($infrastructure.failures) + @("quality-gate command is unavailable: $CargoCommand")
  }
}
if (-not $infrastructure.ready) {
  $summary = [pscustomobject]@{
    schema_version = $script:MultiRegionRelaySummaryVersion
    verdict = "INFRA_FAIL"
    infrastructure_failures = @($infrastructure.failures)
    rows = @()
  }
  Write-MultiRegionRelayUtf8Json -InputObject $summary -Path $summaryPath
  [Console]::Error.WriteLine("multi-region relay infrastructure is incomplete")
  exit 3
}

$scenarioIds = if ($Scenario -eq "all") { @(Get-MultiRegionRelayScenarioIds) } else { @($Scenario) }
$rows = New-Object System.Collections.Generic.List[object]
foreach ($scenarioId in $scenarioIds) {
  $controlInvoker = {
    param($Request)
    Invoke-MultiRegionRelayLabControl -ControlPath $LabControlPath -Request $Request
  }
  $row = Invoke-MultiRegionRelayScenario -Scenario $scenarioId -ControlInvoker $controlInvoker
  $artifactPath = Join-Path $OutputRoot "$scenarioId.artifact.json"
  $evaluationPath = Join-Path $OutputRoot "$scenarioId.evaluation.json"
  $evaluationVerdict = $row.verdict
  $qualityExitCode = $null
  if ($null -ne $row.artifact) {
    Write-MultiRegionRelayUtf8Json -InputObject $row.artifact -Path $artifactPath
    Push-Location $RepoRoot
    try {
      try {
        & $CargoCommand run -q -p mrd-quality-gate --bin mrd-quality-gate -- `
          --artifact $artifactPath `
          --policy (Join-Path $RepoRoot "tests\quality-gates\policies\windows-multi-region-relay.v1.json") `
          --output $evaluationPath
        $qualityExitCode = $LASTEXITCODE
      } catch {
        $qualityExitCode = 3
      }
    } finally {
      Pop-Location
    }
    if ($qualityExitCode -eq 3) {
      $evaluationVerdict = "INFRA_FAIL"
    } elseif ($qualityExitCode -in @(2, 4) -and $evaluationVerdict -ne "INFRA_FAIL") {
      $evaluationVerdict = "PRODUCT_FAIL"
    } elseif ($qualityExitCode -ne 0) {
      $evaluationVerdict = "INFRA_FAIL"
    }
  }
  $rows.Add([pscustomobject]@{
    scenario = $scenarioId
    invocation_id = $row.invocation_id
    verdict = $evaluationVerdict
    action_results = @($row.actions | Select-Object action, verdict, failure)
    artifact_path = if (Test-Path -LiteralPath $artifactPath) { $artifactPath } else { $null }
    evaluation_path = if (Test-Path -LiteralPath $evaluationPath) { $evaluationPath } else { $null }
    quality_gate_exit_code = $qualityExitCode
  })
}

$verdict = Get-MultiRegionRelayVerdict -Results @($rows)
$summary = [pscustomobject]@{
  schema_version = $script:MultiRegionRelaySummaryVersion
  verdict = $verdict
    rows = $rows.ToArray()
}
Write-MultiRegionRelayUtf8Json -InputObject $summary -Path $summaryPath
switch ($verdict) {
  "PASS" { exit 0 }
  "INFRA_FAIL" { exit 3 }
  default { exit 2 }
}
