param(
    [ValidateSet("single", "multi")]
    [string]$Mode = "single",
    [int]$DurationSec = 10,
    [int]$TargetFps = 60,
    [int]$Width = 1920,
    [int]$Height = 1080,
    [string]$Capture = "desktop_dup",
    [string]$Encoder = "software",
    [string]$Decoder = "software",
    [string]$Transport = "quic",
    [string]$Render = "gpu_present",
    [string]$MatrixConfig = "config/matrix.windows.json",
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
        $dir = Join-Path $base "core_agent_controller_${ts}_$suffix"
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir | Out-Null
            return (Resolve-Path $dir).Path
        }
        Start-Sleep -Milliseconds 10
    }
    throw "failed to allocate unique run directory"
}

function Build-Args {
    param([string]$BinName)
    $args = @(
        "run", "--bin", $BinName, "--",
        "--duration-sec", "$DurationSec",
        "--target-fps", "$TargetFps",
        "--width", "$Width",
        "--height", "$Height",
        "--capture", $Capture,
        "--encoder", $Encoder,
        "--decoder", $Decoder,
        "--transport", $Transport,
        "--render", $Render,
        "--matrix-config", $MatrixConfig
    )
    if ($AllowDebugCodecs) {
        $args += "--allow-debug-codecs"
    }
    if ($Visualize) {
        $args += "--visualize"
    }
    return $args
}

function Write-RunMeta {
    param([string]$RunDir)
    $meta = @{
        mode = $Mode
        duration_sec = $DurationSec
        target_fps = $TargetFps
        width = $Width
        height = $Height
        capture = $Capture
        encoder = $Encoder
        decoder = $Decoder
        transport = $Transport
        render = $Render
        matrix_config = $MatrixConfig
        visualize = [bool]$Visualize
        allow_debug_codecs = [bool]$AllowDebugCodecs
        ts = (Get-Date).ToString("o")
    } | ConvertTo-Json -Depth 4
    Set-Content -Path (Join-Path $RunDir "run_meta.json") -Value $meta -Encoding UTF8
}

function Run-Single {
    param([string]$RunDir)
    $agentOut = Join-Path $RunDir "agent.single.json"
    $controllerOut = Join-Path $RunDir "controller.single.json"
    $agentErr = Join-Path $RunDir "agent.single.stderr.log"
    $controllerErr = Join-Path $RunDir "controller.single.stderr.log"

    $agent = Start-Process -FilePath "cargo" -ArgumentList (Build-Args -BinName "core-agent") -PassThru -NoNewWindow `
        -RedirectStandardOutput $agentOut -RedirectStandardError $agentErr
    $agent.WaitForExit()
    $agent.Refresh()
    if ($null -ne $agent.ExitCode -and $agent.ExitCode -ne 0) {
        throw "core-agent failed in single mode, exit=$($agent.ExitCode)"
    }
    if (-not (Test-Path $agentOut)) {
        throw "core-agent did not produce output file: $agentOut"
    }

    $controller = Start-Process -FilePath "cargo" -ArgumentList (Build-Args -BinName "core-controller") -PassThru -NoNewWindow `
        -RedirectStandardOutput $controllerOut -RedirectStandardError $controllerErr
    $controller.WaitForExit()
    $controller.Refresh()
    if ($null -ne $controller.ExitCode -and $controller.ExitCode -ne 0) {
        throw "core-controller failed in single mode, exit=$($controller.ExitCode)"
    }
    if (-not (Test-Path $controllerOut)) {
        throw "core-controller did not produce output file: $controllerOut"
    }
}

function Run-Multi {
    param([string]$RunDir)
    $agentOut = Join-Path $RunDir "agent.multi.json"
    $controllerOut = Join-Path $RunDir "controller.multi.json"
    $agentErr = Join-Path $RunDir "agent.multi.stderr.log"
    $controllerErr = Join-Path $RunDir "controller.multi.stderr.log"

    $agentArgs = Build-Args -BinName "core-agent"
    $controllerArgs = Build-Args -BinName "core-controller"

    $agent = Start-Process -FilePath "cargo" -ArgumentList $agentArgs -PassThru -NoNewWindow `
        -RedirectStandardOutput $agentOut -RedirectStandardError $agentErr
    Start-Sleep -Milliseconds 250
    $controller = Start-Process -FilePath "cargo" -ArgumentList $controllerArgs -PassThru -NoNewWindow `
        -RedirectStandardOutput $controllerOut -RedirectStandardError $controllerErr

    $agent.WaitForExit()
    $controller.WaitForExit()
    $agent.Refresh()
    $controller.Refresh()

    $agentAlive = Get-Process -Id $agent.Id -ErrorAction SilentlyContinue
    $controllerAlive = Get-Process -Id $controller.Id -ErrorAction SilentlyContinue
    if ($agentAlive) {
        throw "core-agent still alive after wait, pid=$($agent.Id)"
    }
    if ($controllerAlive) {
        throw "core-controller still alive after wait, pid=$($controller.Id)"
    }

    if ($null -ne $agent.ExitCode -and $agent.ExitCode -ne 0) {
        throw "core-agent failed in multi mode, exit=$($agent.ExitCode)"
    }
    if ($null -ne $controller.ExitCode -and $controller.ExitCode -ne 0) {
        throw "core-controller failed in multi mode, exit=$($controller.ExitCode)"
    }

    if (-not (Test-Path $agentOut)) {
        throw "core-agent did not produce output file: $agentOut"
    }
    if (-not (Test-Path $controllerOut)) {
        throw "core-controller did not produce output file: $controllerOut"
    }
}

$runDir = New-RunDir
Write-RunMeta -RunDir $runDir

Write-Host "[DEMO] run_dir=$runDir"
Write-Host "[DEMO] mode=$Mode width=$Width height=$Height visualize=$([bool]$Visualize) capture=$Capture encoder=$Encoder decoder=$Decoder transport=$Transport render=$Render"

if ($Mode -eq "single") {
    Run-Single -RunDir $runDir
} else {
    Run-Multi -RunDir $runDir
}

Write-Host "[DEMO] completed run_dir=$runDir"
