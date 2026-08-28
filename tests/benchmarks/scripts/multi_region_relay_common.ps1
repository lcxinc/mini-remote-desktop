$ErrorActionPreference = "Stop"

$script:MultiRegionRelaySummaryVersion = "multi-region-relay-summary.v1"
$script:MultiRegionRelayMaxControlOutputBytes = 1048576
$script:InitialWanEvidenceVersion = "mrd-initial-wan-session-matrix.v1"
$script:InitialWanRowEvidenceVersion = "mrd-initial-wan-session-evidence.v1"
$script:PinnedCoturnImage = "coturn/coturn:4.17.2@sha256:aa68aab64a3b929d57fc2924c98ea447bf996cf8dade2508e7b71eaf23f1f14e"

function Get-InitialWanRowIds {
  @(
    "udp_generation_zero",
    "tcp_generation_zero",
    "tls_generation_zero",
    "target_rejection",
    "capacity_exhaustion",
    "backend_loss_before_approval",
    "signaling_disconnect",
    "expired_generation",
    "service_restart",
    "primary_failure_cross_failure_domain_migration",
    "deterministic_release_all"
  )
}

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
      "backend_outage_expired_cache",
      "initial_wan_local"
    )]
    [string]$Scenario
  )

  $actions = New-Object System.Collections.Generic.List[object]
  $actions.Add([pscustomobject]@{ action = "preflight"; target = "lab" })
  if ($Scenario -eq "initial_wan_local") {
    foreach ($row in Get-InitialWanRowIds) {
      $actions.Add([pscustomobject]@{ action = "run_initial_wan_row"; target = $row })
    }
    $actions.Add([pscustomobject]@{ action = "cleanup"; target = "invocation" })
    return $actions.ToArray()
  }
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
  param([hashtable]$Configuration, [string]$Scenario = "all")

  $failures = New-Object System.Collections.Generic.List[string]
  $requiredValues = if ($Scenario -eq "initial_wan_local") {
    @(
      "MRD_INITIAL_WAN_LAB_CONTROL",
      "MRD_INITIAL_WAN_ATTESTATION_PUBLIC_KEY",
      "MRD_INITIAL_WAN_ATTESTATION_KEY_ID"
    )
  } else { @(
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
  ) }
  foreach ($name in $requiredValues) {
    $value = Get-MultiRegionRelayConfigValue -Configuration $Configuration -Name $name
    if (-not $value -or -not $value.Trim()) {
      $failures.Add("missing required infrastructure value: $name")
    }
  }

  $requiredFiles = if ($Scenario -eq "initial_wan_local") {
    @("MRD_INITIAL_WAN_LAB_CONTROL", "MRD_INITIAL_WAN_ATTESTATION_PUBLIC_KEY")
  } else {
    @("MRD_RELAY_LAB_CONTROL", "MRD_RELAY_LAB_PRIMARY_CERT_PATH", "MRD_RELAY_LAB_BACKUP_CERT_PATH")
  }
  foreach ($name in $requiredFiles) {
    $value = Get-MultiRegionRelayConfigValue -Configuration $Configuration -Name $name
    if ($value -and -not (Test-Path -LiteralPath $value -PathType Leaf)) {
      $failures.Add("configured infrastructure file does not exist: $name")
    }
  }
  $portNames = if ($Scenario -eq "initial_wan_local") { @() } else { @("MRD_RELAY_LAB_UDP_PORT", "MRD_RELAY_LAB_TLS_PORT") }
  foreach ($name in $portNames) {
    $value = Get-MultiRegionRelayConfigValue -Configuration $Configuration -Name $name
    $port = 0
    if ($value -and (-not [int]::TryParse($value, [ref]$port) -or $port -lt 1 -or $port -gt 65535)) {
      $failures.Add("configured infrastructure port is invalid: $name")
    }
  }
  if ($Scenario -eq "initial_wan_local") {
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if ($null -eq $docker) {
      $failures.Add("Docker CLI is unavailable for the pinned coturn data plane")
    } else {
      try {
        $serverVersion = & $docker.Source version --format "{{.Server.Version}}" 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $serverVersion) {
          $failures.Add("Docker server is unavailable for the pinned coturn data plane")
        }
        & $docker.Source image inspect $script:PinnedCoturnImage --format "{{.Id}}" 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
          $failures.Add("the exact pinned coturn image is unavailable")
        }
      } catch {
        $failures.Add("Docker preflight failed for the pinned coturn data plane")
      }
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
  $json -match '"[^"\r\n]*(?:password|secret|token|credential|private_key)[^"\r\n]*"\s*:' -or
    $json -match '(?i)(?:a=ice-pwd:|a=ice-ufrag:|candidate:|(?:^|["\s])turns?:[^"\s]+@|authorization:|bearer\s)'
}

function Invoke-InitialWanRunnerCleanup {
  param(
    [Parameter(Mandatory = $true)][string]$InvocationId,
    $Artifact
  )

  $results = New-Object System.Collections.Generic.List[object]
  $docker = Get-Command docker -ErrorAction SilentlyContinue
  if ($null -eq $docker) {
    $results.Add([pscustomobject]@{ verdict = "INFRA_FAIL"; failure = "Docker CLI became unavailable during cleanup" })
    return $results.ToArray()
  }
  $expectedPrefix = "mrd-wan-e2e-$InvocationId-"
  $names = @(
    $Artifact.rows |
      ForEach-Object { @($_.cleanup.created_container_names) } |
      Where-Object { $_ } |
      Sort-Object -Unique
  )
  foreach ($name in $names) {
    $name = [string]$name
    if (-not $name.StartsWith($expectedPrefix)) {
      $results.Add([pscustomobject]@{ verdict = "PRODUCT_FAIL"; failure = "artifact named a container outside the invocation" })
      continue
    }
    $containerId = & $docker.Source container inspect --format "{{.Id}}" $name 2>$null
    if ($LASTEXITCODE -eq 0 -and $containerId) {
      $results.Add([pscustomobject]@{ verdict = "PRODUCT_FAIL"; failure = "lab control leaked an invocation container" })
      & $docker.Source container rm --force $containerId 2>$null | Out-Null
      if ($LASTEXITCODE -ne 0) {
        $results.Add([pscustomobject]@{ verdict = "INFRA_FAIL"; failure = "runner could not recover an invocation container" })
      }
    }
  }

  $label = "mrd.e2e.invocation=$InvocationId"
  $labelledIds = @(& $docker.Source container ls --all --quiet --filter "label=$label" 2>$null | Where-Object { $_ })
  if ($LASTEXITCODE -ne 0) {
    $results.Add([pscustomobject]@{ verdict = "INFRA_FAIL"; failure = "runner could not inspect invocation-labelled containers" })
    return $results.ToArray()
  }
  foreach ($containerId in $labelledIds) {
    $results.Add([pscustomobject]@{ verdict = "PRODUCT_FAIL"; failure = "lab control leaked an invocation-labelled container" })
    & $docker.Source container rm --force ([string]$containerId) 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
      $results.Add([pscustomobject]@{ verdict = "INFRA_FAIL"; failure = "runner could not recover an invocation-labelled container" })
    }
  }
  $remaining = @(& $docker.Source container ls --all --quiet --filter "label=$label" 2>$null | Where-Object { $_ })
  if ($LASTEXITCODE -ne 0 -or $remaining.Count -ne 0) {
    $results.Add([pscustomobject]@{ verdict = "INFRA_FAIL"; failure = "invocation container cleanup could not be verified" })
  }
  $results.ToArray()
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

function Get-InitialWanEvidenceFailures {
  param(
    $Artifact,
    [string]$ExpectedInvocationId
  )

  $failures = New-Object System.Collections.Generic.List[string]
  if ($null -eq $Artifact) {
    $failures.Add("initial WAN evidence is missing")
    return $failures.ToArray()
  }
  if ([string]$Artifact.schema_version -ne $script:InitialWanEvidenceVersion) {
    $failures.Add("initial WAN evidence schema is unsupported")
  }
  if ([string]$Artifact.invocation_id -ne $ExpectedInvocationId) {
    $failures.Add("initial WAN artifact is not bound to the invocation")
  }
  if ([string]$Artifact.scenario.id -ne "initial_wan_local") {
    $failures.Add("initial WAN artifact is not bound to the requested scenario")
  }
  if (Test-MultiRegionRelayPayloadContainsSecretFields -Payload $Artifact) {
    $failures.Add("initial WAN artifact contains a forbidden secret field")
  }

  $rows = @($Artifact.rows)
  $expectedRows = @(Get-InitialWanRowIds)
  if ($rows.Count -ne $expectedRows.Count) {
    $failures.Add("initial WAN evidence row count is incomplete")
    return $failures.ToArray()
  }
  foreach ($rowId in $expectedRows) {
    $row = @($rows | Where-Object { [string]$_.row -eq $rowId })
    if ($row.Count -ne 1) {
      $failures.Add("initial WAN row is missing or duplicated: $rowId")
      continue
    }
    $row = $row[0]
    if (
      [string]$row.schema_version -ne $script:InitialWanRowEvidenceVersion -or
      [string]$row.invocation_id -ne $ExpectedInvocationId -or
      [string]$row.evidence_id -ne "$ExpectedInvocationId`:$rowId" -or
      [string]$row.verdict -ne "PASS"
    ) {
      $failures.Add("initial WAN row identity or verdict is invalid: $rowId")
      continue
    }
    if (-not $row.attestation.key_id -or -not $row.attestation.signature_b64) {
      $failures.Add("initial WAN row attestation is missing: $rowId")
    }
    if (
      -not [bool]$row.topology.controller_service_runtime -or
      -not [bool]$row.topology.target_service_runtime -or
      -not [bool]$row.topology.realtime_server -or
      -not [bool]$row.topology.fastapi_backend -or
      [string]$row.topology.coturn_image -ne $script:PinnedCoturnImage -or
      [uint64]$row.topology.coturn_node_count -lt 1
    ) {
      $failures.Add("initial WAN row lacks the required live topology: $rowId")
    }
    if (
      [string]$row.topology.controller_runtime_id -ne "$ExpectedInvocationId`:controller" -or
      [string]$row.topology.target_runtime_id -ne "$ExpectedInvocationId`:target" -or
      [string]$row.topology.realtime_runtime_id -ne "$ExpectedInvocationId`:realtime" -or
      [string]$row.topology.backend_runtime_id -ne "$ExpectedInvocationId`:backend"
    ) {
      $failures.Add("initial WAN runtime identities are not invocation-bound: $rowId")
    }
    if (
      -not [bool]$row.authorization.attended -or
      -not [bool]$row.authorization.intent_signature_verified -or
      [uint64]$row.generation.controller -ne [uint64]$row.generation.target -or
      [string]$row.reservation.session_id -ne [string]$row.reservation.controller_session_id -or
      [string]$row.reservation.session_id -ne [string]$row.reservation.target_session_id
    ) {
      $failures.Add("initial WAN authorization, generation, or reservation ownership is invalid: $rowId")
    }

    $negativeReasons = @{
      target_rejection = "target_rejected"
      capacity_exhaustion = "capacity_exhausted"
      backend_loss_before_approval = "backend_unavailable_before_approval"
      expired_generation = "generation_expired"
    }
    $negativeRows = @($negativeReasons.Keys)
    $relayAccessObserved = $rowId -notin @("target_rejection", "capacity_exhaustion", "backend_loss_before_approval")
    if ($relayAccessObserved) {
      if (
        -not [bool]$row.reservation.owner_verified -or
        [string]$row.reservation.controller_directory_id -ne [string]$row.reservation.target_directory_id -or
        [string]$row.reservation.controller_relay_url_digest -ne [string]$row.reservation.target_relay_url_digest -or
        -not $row.reservation.primary_reservation_id -or
        -not $row.reservation.backup_reservation_id -or
        [string]$row.reservation.primary_reservation_id -eq [string]$row.reservation.backup_reservation_id
      ) {
        $failures.Add("initial WAN relay access is not identically bound to both peers: $rowId")
      }
    } elseif (
      [bool]$row.reservation.owner_verified -or
      $row.reservation.controller_directory_id -or
      $row.reservation.target_directory_id -or
      $row.reservation.controller_relay_url_digest -or
      $row.reservation.target_relay_url_digest -or
      $row.reservation.primary_reservation_id -or
      $row.reservation.backup_reservation_id
    ) {
      $failures.Add("initial WAN row claims relay access before admission: $rowId")
    }
    if ($rowId -in $negativeRows) {
      $grantObserved = $rowId -eq "expired_generation"
      $targetApproved = $rowId -in @("capacity_exhaustion", "expired_generation")
      if (
        [string]$row.fault.expected_rejection -ne [string]$negativeReasons[$rowId] -or
        [bool]$row.authorization.grant_signature_verified -ne $grantObserved -or
        [bool]$row.authorization.scope_digest_equal -ne $grantObserved -or
        [bool]$row.authorization.target_approved -ne $targetApproved -or
        [bool]$row.fault.transport_opened -or
        [bool]$row.reservation.committed
      ) {
        $failures.Add("initial WAN negative row did not fail closed: $rowId")
      }
    } else {
      $expectedTransport = if ($rowId -eq "tcp_generation_zero") { "tcp" } elseif ($rowId -eq "tls_generation_zero") { "tls" } else { "udp" }
      if (
      -not [bool]$row.authorization.target_approved -or
      -not [bool]$row.authorization.grant_signature_verified -or
      -not [bool]$row.authorization.scope_digest_equal -or
      -not [bool]$row.reservation.committed -or
      [string]$row.selected_pair.local_candidate_type -ne "relay" -or
      [string]$row.selected_pair.remote_candidate_type -ne "relay" -or
      [string]$row.selected_pair.transport -ne $expectedTransport -or
      -not [bool]$row.selected_pair.runtime_verified -or
      [uint64]$row.traffic.media_frames -eq 0 -or
      [uint64]$row.traffic.control_events -eq 0 -or
      [uint64]$row.traffic.realtime_control_events -eq 0 -or
      [string]$row.traffic.media_probe_id -ne "$ExpectedInvocationId`:$rowId`:media" -or
      [string]$row.traffic.control_probe_id -ne "$ExpectedInvocationId`:$rowId`:control" -or
      [string]$row.traffic.realtime_control_probe_id -ne "$ExpectedInvocationId`:$rowId`:realtime-control"
      ) {
        $failures.Add("initial WAN connected row lacks actual relay traffic: $rowId")
      }
    }

    if ($rowId -ne "primary_failure_cross_failure_domain_migration" -and (
      [uint64]$row.generation.controller -ne 0 -or
      [uint64]$row.generation.before_migration -ne 0 -or
      [uint64]$row.generation.after_migration -ne 0
    )) {
      $failures.Add("initial WAN row did not remain on shared generation zero: $rowId")
    }
    if ($rowId -eq "service_restart" -and (
      [uint64]$row.fault.service_restart_count -eq 0 -or
      -not $row.fault.service_runtime_before_id -or
      -not $row.fault.service_runtime_after_id -or
      [string]$row.fault.service_runtime_before_id -eq [string]$row.fault.service_runtime_after_id -or
      -not ([string]$row.fault.service_runtime_before_id).StartsWith("$ExpectedInvocationId`:target:") -or
      -not ([string]$row.fault.service_runtime_after_id).StartsWith("$ExpectedInvocationId`:target:")
    )) {
      $failures.Add("service restart row lacks before/after runtime proof")
    }
    if ($rowId -ne "service_restart" -and [uint64]$row.fault.service_restart_count -ne 0) {
      $failures.Add("non-restart row claims a service restart: $rowId")
    }
    if ($rowId -eq "signaling_disconnect" -and (
      [uint64]$row.fault.signaling_disconnect_count -eq 0 -or
      -not $row.fault.signaling_connection_before_id -or
      -not $row.fault.signaling_connection_after_id -or
      [string]$row.fault.signaling_connection_before_id -eq [string]$row.fault.signaling_connection_after_id -or
      -not ([string]$row.fault.signaling_connection_before_id).StartsWith("$ExpectedInvocationId`:signal:") -or
      -not ([string]$row.fault.signaling_connection_after_id).StartsWith("$ExpectedInvocationId`:signal:")
    )) {
      $failures.Add("signaling disconnect row lacks before/after connection proof")
    }
    if ($rowId -ne "signaling_disconnect" -and [uint64]$row.fault.signaling_disconnect_count -ne 0) {
      $failures.Add("non-disconnect row claims a signaling disconnect: $rowId")
    }

    if ($rowId -eq "primary_failure_cross_failure_domain_migration" -and (
      -not [bool]$row.fault.primary_failed -or
      -not [bool]$row.fault.cross_failure_domain -or
      [uint64]$row.topology.coturn_node_count -lt 2 -or
      @($row.topology.failure_domains).Count -lt 2 -or
      [string]$row.topology.failure_domains[0] -eq [string]$row.topology.failure_domains[1] -or
      [uint64]$row.generation.after_migration -ne ([uint64]$row.generation.before_migration + 1)
    )) {
      $failures.Add("initial WAN migration proof is incomplete")
    }
    if (
      -not [bool]$row.cleanup.release_all_recorded -or
      -not [bool]$row.cleanup.reservation_released -or
      -not [bool]$row.cleanup.allocations_closed -or
      -not [bool]$row.cleanup.signaling_closed -or
      -not [bool]$row.cleanup.service_tasks_joined -or
      -not [bool]$row.cleanup.containers_removed -or
      (Compare-Object @("input_down", "release_all", "input_frozen") @($row.cleanup.release_all_sequence)) -or
      @($row.cleanup.created_container_names).Count -eq 0 -or
      (Compare-Object @($row.cleanup.created_container_names) @($row.cleanup.removed_container_names)) -or
      @($row.cleanup.created_container_names | Where-Object { -not ([string]$_).StartsWith("mrd-wan-e2e-$ExpectedInvocationId-") }).Count -gt 0
    ) {
      $failures.Add("initial WAN cleanup is incomplete or not exact: $rowId")
    }
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
  $evidenceFailures = if ($Scenario -eq "initial_wan_local") {
    @(Get-InitialWanEvidenceFailures -Artifact $artifact -ExpectedInvocationId $InvocationId)
  } else {
    @(
      Get-MultiRegionRelayEvidenceFailures `
        -Artifact $artifact `
        -ExpectedInvocationId $InvocationId `
        -ExpectedScenario $Scenario
    )
  }
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
