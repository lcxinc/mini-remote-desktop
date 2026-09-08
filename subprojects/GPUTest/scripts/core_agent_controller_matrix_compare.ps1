param(
    [string]$MatrixConfig = "config/matrix.windows.json",
    [int]$SampleCount = 5,
    [int]$DurationSec = 5,
    [int]$TargetFps = 60,
    [int]$Width = 1920,
    [int]$Height = 1080,
    [string]$Capture = "desktop_dup",
    [string]$Transport = "quic",
    [string]$Render = "gpu_present",
    [switch]$Visualize,
    [switch]$AllowDebugCodecs
)

$ErrorActionPreference = "Stop"

function New-RunDir {
    $base = Join-Path $PSScriptRoot "..\artifacts\demo"
    New-Item -ItemType Directory -Force -Path $base | Out-Null
    for ($i = 0; $i -lt 50; $i++) {
        $ts = Get-Date -Format "yyyyMMdd_HHmmss_fff"
        $suffix = Get-Random -Minimum 100 -Maximum 999
        $dir = Join-Path $base "core_agent_controller_matrix_compare_${ts}_$suffix"
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir | Out-Null
            return (Resolve-Path $dir).Path
        }
        Start-Sleep -Milliseconds 10
    }
    throw "failed to allocate unique run directory"
}

function Is-DebugCodec {
    param([string]$Name)
    $n = $Name.ToLowerInvariant()
    return ($n -eq "raw_bgra" -or $n -eq "raw_bgra_chunked" -or $n -eq "lz4" -or $n -eq "lz4_bgra")
}

function Select-Cases {
    param(
        [object]$Cfg,
        [int]$Count
    )
    $cases = @()
    foreach ($p in $Cfg.valid_paths) {
        $enc = [string]$p.encoder
        $dec = [string]$p.decoder
        if (-not $AllowDebugCodecs -and ((Is-DebugCodec -Name $enc) -or (Is-DebugCodec -Name $dec))) {
            continue
        }
        $cases += [pscustomobject]@{
            capture = $Capture
            encoder = $enc
            decoder = $dec
            transport = $Transport
            render = $Render
            width = $Width
            height = $Height
            fps = $TargetFps
        }
        if ($cases.Count -ge $Count) {
            break
        }
    }
    return $cases
}

function Read-JsonReport {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        throw "missing report file: $Path"
    }
    $raw = Get-Content -Path $Path -Raw
    $objs = [regex]::Matches($raw, '(?s)\{.*?\}')
    for ($i = $objs.Count - 1; $i -ge 0; $i--) {
        $txt = $objs[$i].Value
        try {
            $obj = $txt | ConvertFrom-Json
            if ($null -ne $obj.role -and $null -ne $obj.e2e_p95_ms) {
                return $obj
            }
        } catch {
        }
    }
    throw "no parseable json report in file: $Path"
}

function Fps-Achieved {
    param([object]$Report)
    if ([double]$Report.frames_total -le 0) {
        return 0.0
    }
    return ([double]$Report.frames_received / [double]$Report.frames_total) * [double]$Report.target_fps
}

function Invoke-Demo {
    param(
        [string]$Mode,
        [object]$Case
    )
    $demoScript = Join-Path $PSScriptRoot "core_agent_controller_demo.ps1"
    $demoRoot = Join-Path $PSScriptRoot "..\artifacts\demo"
    New-Item -ItemType Directory -Force -Path $demoRoot | Out-Null
    $before = @(
        Get-ChildItem -Path $demoRoot -Directory -Filter "core_agent_controller_*" |
            ForEach-Object { $_.FullName.ToLowerInvariant() }
    )
    try {
        if ($AllowDebugCodecs) {
            & $demoScript `
                -Mode $Mode `
                -DurationSec $DurationSec `
                -TargetFps $Case.fps `
                -Width $Case.width `
                -Height $Case.height `
                -Capture $Case.capture `
                -Encoder $Case.encoder `
                -Decoder $Case.decoder `
                -Transport $Case.transport `
                -Render $Case.render `
                -MatrixConfig $MatrixConfig `
                -Visualize:$Visualize `
                -AllowDebugCodecs
        } else {
            & $demoScript `
                -Mode $Mode `
                -DurationSec $DurationSec `
                -TargetFps $Case.fps `
                -Width $Case.width `
                -Height $Case.height `
                -Capture $Case.capture `
                -Encoder $Case.encoder `
                -Decoder $Case.decoder `
                -Transport $Case.transport `
                -Render $Case.render `
                -MatrixConfig $MatrixConfig `
                -Visualize:$Visualize
        }
    } catch {
        throw "demo failed mode=$Mode chain=$($Case.capture)->$($Case.encoder)->$($Case.transport)->$($Case.decoder)->$($Case.render)`n$($_.Exception.Message)"
    }
    $after = Get-ChildItem -Path $demoRoot -Directory -Filter "core_agent_controller_*"
    $newDir = $after |
        Where-Object { $before -notcontains $_.FullName.ToLowerInvariant() } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($null -eq $newDir) {
        $newDir = $after | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    }
    if ($null -eq $newDir) {
        throw "unable to locate demo output directory in $demoRoot"
    }
    return $newDir.FullName
}

$runDir = New-RunDir
$cfg = Get-Content -Path $MatrixConfig -Raw | ConvertFrom-Json
$cases = Select-Cases -Cfg $cfg -Count $SampleCount
if ($cases.Count -eq 0) {
    throw "no cases selected from matrix config: $MatrixConfig"
}

$rows = @()
$idx = 0
foreach ($case in $cases) {
    $idx += 1
    $chain = "$($case.capture)->$($case.encoder)->$($case.transport)->$($case.decoder)->$($case.render)"
    Write-Host "[MATRIX-COMPARE] case=$idx/$($cases.Count) chain=$chain"

    $singleDir = Invoke-Demo -Mode "single" -Case $case
    $multiDir = Invoke-Demo -Mode "multi" -Case $case

    $singleAgent = Read-JsonReport -Path (Join-Path $singleDir "agent.single.json")
    $singleController = Read-JsonReport -Path (Join-Path $singleDir "controller.single.json")
    $multiAgent = Read-JsonReport -Path (Join-Path $multiDir "agent.multi.json")
    $multiController = Read-JsonReport -Path (Join-Path $multiDir "controller.multi.json")

    foreach ($role in @("agent", "controller")) {
        if ($role -eq "agent") {
            $s = $singleAgent
            $m = $multiAgent
        } else {
            $s = $singleController
            $m = $multiController
        }
        $row = [pscustomobject]@{
            case_id = $idx
            role = $role
            capture = $case.capture
            encoder = $case.encoder
            transport = $case.transport
            decoder = $case.decoder
            render = $case.render
            width = $case.width
            height = $case.height
            fps = $case.fps
            single_pass = [bool]$s.pass
            multi_pass = [bool]$m.pass
            single_fps_achieved = [math]::Round((Fps-Achieved -Report $s), 3)
            multi_fps_achieved = [math]::Round((Fps-Achieved -Report $m), 3)
            delta_fps = [math]::Round((Fps-Achieved -Report $m) - (Fps-Achieved -Report $s), 3)
            single_e2e_p50_ms = [double]$s.e2e_p50_ms
            multi_e2e_p50_ms = [double]$m.e2e_p50_ms
            delta_e2e_p50_ms = [math]::Round(([double]$m.e2e_p50_ms - [double]$s.e2e_p50_ms), 3)
            single_e2e_p95_ms = [double]$s.e2e_p95_ms
            multi_e2e_p95_ms = [double]$m.e2e_p95_ms
            delta_e2e_p95_ms = [math]::Round(([double]$m.e2e_p95_ms - [double]$s.e2e_p95_ms), 3)
            single_e2e_p99_ms = [double]$s.e2e_p99_ms
            multi_e2e_p99_ms = [double]$m.e2e_p99_ms
            delta_e2e_p99_ms = [math]::Round(([double]$m.e2e_p99_ms - [double]$s.e2e_p99_ms), 3)
            single_bitrate_avg_mbps = [double]$s.bitrate_avg_mbps
            multi_bitrate_avg_mbps = [double]$m.bitrate_avg_mbps
            delta_bitrate_avg_mbps = [math]::Round(([double]$m.bitrate_avg_mbps - [double]$s.bitrate_avg_mbps), 6)
            single_wire_overhead_est_mbps = [double]$s.wire_overhead_est_mbps
            multi_wire_overhead_est_mbps = [double]$m.wire_overhead_est_mbps
            delta_wire_overhead_est_mbps = [math]::Round(([double]$m.wire_overhead_est_mbps - [double]$s.wire_overhead_est_mbps), 6)
            single_run_dir = $singleDir
            multi_run_dir = $multiDir
        }
        $rows += $row
    }
}

$rowsPath = Join-Path $runDir "matrix_compare_rows.json"
$csvPath = Join-Path $runDir "matrix_compare.csv"
$summaryPath = Join-Path $runDir "summary.json"

$rows | ConvertTo-Json -Depth 6 | Set-Content -Path $rowsPath -Encoding UTF8
$rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

$controllerRows = @($rows | Where-Object { $_.role -eq "controller" })
$summary = [pscustomobject]@{
    run_dir = $runDir
    matrix_config = $MatrixConfig
    sample_count = $cases.Count
    duration_sec = $DurationSec
    target_fps = $TargetFps
    width = $Width
    height = $Height
    capture = $Capture
    transport = $Transport
    render = $Render
    visualize = [bool]$Visualize
    allow_debug_codecs = [bool]$AllowDebugCodecs
    pass_both_count = @($controllerRows | Where-Object { $_.single_pass -and $_.multi_pass }).Count
    avg_delta_e2e_p95_ms_controller = if ($controllerRows.Count -gt 0) {
        [math]::Round((($controllerRows | Measure-Object -Property delta_e2e_p95_ms -Average).Average), 3)
    } else { 0.0 }
    avg_delta_fps_controller = if ($controllerRows.Count -gt 0) {
        [math]::Round((($controllerRows | Measure-Object -Property delta_fps -Average).Average), 3)
    } else { 0.0 }
    rows_json = $rowsPath
    csv = $csvPath
}
$summary | ConvertTo-Json -Depth 6 | Set-Content -Path $summaryPath -Encoding UTF8

Write-Host "[MATRIX-COMPARE] run_dir=$runDir"
Write-Host "[MATRIX-COMPARE] rows_json=$rowsPath"
Write-Host "[MATRIX-COMPARE] csv=$csvPath"
Write-Host "[MATRIX-COMPARE] summary=$summaryPath"
