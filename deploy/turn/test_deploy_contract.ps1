[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

function Assert-True {
  param(
    [Parameter(Mandatory = $true)]
    [bool]$Condition,
    [Parameter(Mandatory = $true)]
    [string]$Message
  )

  if (-not $Condition) {
    throw "deployment_contract_failed: $Message"
  }
}

function Read-RequiredText {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RelativePath
  )

  $path = Join-Path $PSScriptRoot $RelativePath
  Assert-True (Test-Path -LiteralPath $path -PathType Leaf) "missing $RelativePath"
  $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
  $text = [IO.File]::ReadAllText([IO.Path]::GetFullPath($path), $utf8)
  return $text.Replace("`r`n", "`n").Replace("`r", "`n")
}

function Assert-Matches {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Text,
    [Parameter(Mandatory = $true)]
    [string]$Pattern,
    [Parameter(Mandatory = $true)]
    [string]$Message
  )

  Assert-True ([regex]::IsMatch($Text, $Pattern)) $Message
}

function Assert-NotMatches {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Text,
    [Parameter(Mandatory = $true)]
    [string]$Pattern,
    [Parameter(Mandatory = $true)]
    [string]$Message
  )

  Assert-True (-not [regex]::IsMatch($Text, $Pattern)) $Message
}

function Assert-PowerShellSyntaxAndLiteralPaths {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RelativePath,
    [Parameter(Mandatory = $true)]
    [string]$Text
  )

  $path = Join-Path $PSScriptRoot $RelativePath
  $tokens = $null
  $parseErrors = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $path,
    [ref]$tokens,
    [ref]$parseErrors
  )
  Assert-True (@($parseErrors).Count -eq 0) "$RelativePath parses on this PowerShell runtime"

  $literalCommands = @(
    "Get-Content", "Set-Content", "Add-Content", "Clear-Content",
    "Copy-Item", "Move-Item", "Remove-Item", "Rename-Item",
    "Get-Item", "Get-ChildItem", "Test-Path", "Get-Acl", "Set-Acl"
  )
  $commands = $ast.FindAll({
      param($node)
      $node -is [System.Management.Automation.Language.CommandAst]
    }, $true)
  foreach ($command in $commands) {
    $name = $command.GetCommandName()
    if ($literalCommands -contains $name) {
      Assert-True ($command.Extent.Text -match '(?i)-LiteralPath\b') `
        "$RelativePath uses -LiteralPath for $name"
    }
  }

  Assert-NotMatches $Text '(?im)\b(?:Invoke-Expression|iex|taskkill|Stop-Process|Get-Process)\b' `
    "$RelativePath never evaluates strings or scans/kills processes"
  Assert-NotMatches $Text '(?im)\b(?:cmd(?:\.exe)?\s+/c|powershell(?:\.exe)?\s+-(?:Command|EncodedCommand))\b' `
    "$RelativePath never launches a command shell from a string"
  Assert-NotMatches $Text '(?im)(?:Write-(?:Host|Output|Verbose|Debug|Information)|Out-File).*\b(?:secret|credential|token)\b' `
    "$RelativePath never writes credential material"
  Assert-NotMatches $Text '(?im)\$env:[A-Za-z0-9_]*(?:SECRET|CREDENTIAL|TOKEN)\s*=' `
    "$RelativePath never exports credential material"
  Assert-NotMatches $Text '(?im)Remove-Item\b[^\r\n]*-(?:Recurse|Include|Exclude|Filter)\b' `
    "$RelativePath has no recursive or pattern-based deletion"
}

$required = @(
  "turnserver.conf.example",
  "README.md",
  "regions.example.yaml",
  "public-ip-test-vectors.json",
  "linux/mrd-relay-agent.service",
  "linux/mrd-coturn.service",
  "linux/mrd-relay-coturn-control.socket",
  "linux/mrd-relay-coturn-control@.service",
  "linux/mrd-relay-coturn-control.tmpfiles",
  "linux/mrd-coturn-render-config",
  "linux/mrd-relay-firewall.service",
  "linux/mrd-relay-firewall",
  "linux/mrd-relay.nft",
  "linux/install-relay-node.sh",
  "linux/uninstall-relay-node.sh",
  "linux/verify-relay-node.sh",
  "linux/validate-public-ip.py",
  "linux/validate-drain-proof.py",
  "linux/mrd-relay-drain-proof",
  "windows/install-relay-node.ps1",
  "windows/uninstall-relay-node.ps1",
  "windows/verify-relay-node.ps1"
)

$texts = @{}
foreach ($relativePath in $required) {
  $texts[$relativePath] = Read-RequiredText $relativePath
}

$publicIpVectors = $texts["public-ip-test-vectors.json"]
foreach ($pattern in @(
    '192\.88\.99\.2', '2001:5::1', '2002::1', '3fff::1',
    '64:ff9b::c0a8:101', '64:ff9b::808:808',
    '::ffff:8\.8\.8\.8', '::8\.8\.8\.8',
    '2001:1::1', '2001:3::1', '2001:4:112::1', '2001:20::1', '2001:30::1'
  )) {
  Assert-Matches $publicIpVectors $pattern "shared public-IP vectors contain $pattern"
}
foreach ($mappingPattern in @(
    '198\.20\.0\.10/10\.0\.0\.10',
    '2606:4700:4700::1111/fd00::10',
    '198\.20\.0\.10/fd00::10',
    '2606:4700:4700::1111/10\.0\.0\.10',
    '"relay_ip": "fd00::11"',
    '"relay_ip": "fd00:0:0:0:0:0:0:10"'
  )) {
  Assert-Matches $publicIpVectors $mappingPattern "shared mapping vectors contain $mappingPattern"
}

$config = $texts["turnserver.conf.example"]
Assert-True ([regex]::Matches($config, '(?m)^listening-ip=').Count -eq 1) `
  "coturn source baseline has exactly one listening-ip default"
foreach ($pattern in @(
    '(?m)^listening-port=3478$',
    '(?m)^tls-listening-port=5349$',
    '(?m)^use-auth-secret$',
    '(?m)^static-auth-secret=CHANGE_ME_WITH_43_CHAR_BASE64URL_SECRET$',
    '(?m)^rest-api-separator=:$',
    '(?m)^unauthorized-ratelimit$',
    '(?m)^unauthorized-ratelimit-rps=10$',
    '(?m)^cert=/etc/mrd-relay-agent/tls/fullchain\.pem$',
    '(?m)^pkey=/etc/mrd-relay-agent/tls/privkey\.pem$',
    '(?m)^no-tlsv1$',
    '(?m)^no-tlsv1_1$',
    '(?m)^min-port=49160$',
    '(?m)^max-port=49260$',
    '(?m)^user-quota=[1-9][0-9]*$',
    '(?m)^total-quota=[1-9][0-9]*$',
    '(?m)^max-bps=[1-9][0-9]*$',
    '(?m)^bps-capacity=[1-9][0-9]*$',
    '(?m)^prometheus$',
    '(?m)^prometheus-address=127\.0\.0\.1$',
    '(?m)^prometheus-port=9641$',
    '(?m)^no-multicast-peers$',
    '(?m)^no-cli$',
    '(?m)^drain-min-allocations=0$',
    '(?m)^denied-peer-ip=10\.0\.0\.0-10\.255\.255\.255$',
    '(?m)^denied-peer-ip=127\.0\.0\.0-127\.255\.255\.255$',
    '(?m)^denied-peer-ip=169\.254\.0\.0-169\.254\.255\.255$',
    '(?m)^denied-peer-ip=172\.16\.0\.0-172\.31\.255\.255$',
    '(?m)^denied-peer-ip=192\.168\.0\.0-192\.168\.255\.255$'
  )) {
  Assert-Matches $config $pattern "coturn hardening contains $pattern"
}
Assert-NotMatches $config '(?m)^prometheus-username-labels\s*$' `
  "Prometheus never exposes ephemeral usernames"
Assert-Matches $config '(?m)^bps-capacity=125000000$' `
  "the one-gigabit agent budget is rendered as bytes per second for coturn"
Assert-Matches $config '(?i)max_egress_bps.*bits/s.*(?:max-bps|bps-capacity).*bytes/s' `
  "coturn bandwidth unit conversion is documented at the configuration boundary"
Assert-Matches $config '(?is)SIGUSR1.*drain|drain.*SIGUSR1' `
  "coturn config documents SIGUSR1 drain semantics"
$configMinPort = [int]([regex]::Match($config, '(?m)^min-port=([0-9]+)$').Groups[1].Value)
$configMaxPort = [int]([regex]::Match($config, '(?m)^max-port=([0-9]+)$').Groups[1].Value)
$configTotalQuota = [int]([regex]::Match($config, '(?m)^total-quota=([0-9]+)$').Groups[1].Value)
Assert-True ($configTotalQuota -le ($configMaxPort - $configMinPort)) `
  "coturn total quota leaves at least one relay port of headroom"

$agentUnit = $texts["linux/mrd-relay-agent.service"]
foreach ($pattern in @(
    '(?m)^Requires=mrd-relay-coturn-control\.socket$',
    '(?m)^User=mrd-relay$',
    '(?m)^Group=mrd-relay$',
    '(?m)^LoadCredential=agent-config:/etc/mrd-relay-agent/agent\.json$',
    '(?m)^LoadCredential=enrollment-token:/etc/mrd-relay-agent/secrets/enrollment-token$',
    '(?m)^LoadCredential=turn-rest-secret:/etc/mrd-relay-agent/secrets/turn-rest-secret$',
    '(?m)^LoadCredential=trusted-ca:/etc/mrd-relay-agent/secrets/trusted-ca.pem$',
    '(?m)^ExecStartPre=/usr/local/bin/mrd-relay-agent validate --config %d/agent-config$',
    '(?m)^ExecStart=/usr/local/bin/mrd-relay-agent run --config %d/agent-config$',
    '(?m)^NoNewPrivileges=true$',
    '(?m)^ProtectSystem=strict$',
    '(?m)^ProtectHome=true$',
    '(?m)^PrivateTmp=true$',
    '(?m)^PrivateDevices=true$',
    '(?m)^RestrictSUIDSGID=true$',
    '(?m)^RestrictNamespaces=true$',
    '(?m)^LockPersonality=true$',
    '(?m)^CapabilityBoundingSet=$',
    '(?m)^UMask=0077$',
    '(?m)^ReadWritePaths=/var/lib/mrd-relay-agent$',
    '(?m)^StartLimitIntervalSec=300$',
    '(?m)^StartLimitBurst=3$',
    '(?m)^Restart=on-failure$',
    '(?m)^RestartPreventExitStatus=64 65 66 77 78$',
    '(?m)^LimitNOFILE=65536$'
  )) {
  Assert-Matches $agentUnit $pattern "systemd agent unit contains $pattern"
}
Assert-NotMatches $agentUnit '(?m)^User=root$' "relay agent never runs as root"
Assert-NotMatches $agentUnit '(?m)^(?:Wants|Requires)=.*mrd-coturn\.service' `
  "coturn lifecycle remains exclusively broker-owned"

$coturnUnit = $texts["linux/mrd-coturn.service"]
foreach ($pattern in @(
    '(?m)^Requires=mrd-relay-firewall\.service$',
    '(?m)^After=mrd-relay-firewall\.service$',
    '(?m)^Type=simple$',
    '(?m)^User=mrd-coturn$',
    '(?m)^Group=mrd-coturn$',
    '(?m)^LoadCredential=turnserver\.conf:/etc/mrd-relay-agent/secrets/turnserver\.generated\.conf$',
    '(?m)^LoadCredential=turn-cert:/etc/mrd-relay-agent/tls/fullchain\.pem$',
    '(?m)^LoadCredential=turn-key:/etc/mrd-relay-agent/tls/privkey\.pem$',
    '(?m)^ExecStart=/usr/bin/turnserver -c %d/turnserver\.conf$',
    '(?m)^NoNewPrivileges=true$',
    '(?m)^ProtectSystem=strict$',
    '(?m)^UMask=0077$',
    '(?m)^Restart=no$',
    '(?m)^CapabilityBoundingSet=$',
    '(?m)^AmbientCapabilities=$',
    '(?m)^LimitNOFILE=65536$',
    '(?m)^IPAccounting=yes$'
  )) {
  Assert-Matches $coturnUnit $pattern "systemd coturn unit contains $pattern"
}
Assert-NotMatches $coturnUnit '(?m)^WantedBy=' `
  "coturn cannot be independently enabled outside the broker"

$controlSocket = $texts["linux/mrd-relay-coturn-control.socket"]
foreach ($pattern in @(
    '(?m)^ListenStream=/run/mrd-relay-coturn-control/control\.sock$',
    '(?m)^FileDescriptorName=mrd-relay-coturn-control$',
    '(?m)^SocketUser=root$',
    '(?m)^SocketGroup=mrd-relay$',
    '(?m)^SocketMode=0660$',
    '(?m)^DirectoryMode=0750$',
    '(?m)^Accept=yes$',
    '(?m)^RemoveOnStop=yes$',
    '(?m)^MaxConnections=16$'
  )) {
  Assert-Matches $controlSocket $pattern "Linux coturn control socket contains $pattern"
}

$controlService = $texts["linux/mrd-relay-coturn-control@.service"]
foreach ($pattern in @(
    '(?m)^User=root$',
    '(?m)^Group=root$',
    '(?m)^ExecStart=/usr/local/libexec/mrd-relay-coturn-control --socket-activated$',
    '(?m)^StandardInput=null$',
    '(?m)^StandardOutput=null$',
    '(?m)^StandardError=journal$',
    '(?m)^NoNewPrivileges=true$',
    '(?m)^ProtectSystem=strict$',
    '(?m)^ReadWritePaths=/etc/mrd-relay-agent/secrets /var/lib/mrd-coturn /run/mrd-coturn$'
    ,'(?m)^RuntimeMaxSec=15s$'
    ,'(?m)^TasksMax=8$'
    ,'(?m)^MemoryMax=64M$'
  )) {
  Assert-Matches $controlService $pattern "Linux coturn control service contains $pattern"
}

$tmpfiles = $texts["linux/mrd-relay-coturn-control.tmpfiles"]
Assert-Matches $tmpfiles '(?m)^d /run/mrd-relay-coturn-control 0750 root mrd-relay -$' `
  "tmpfiles creates the socket directory with a narrow group boundary"

$firewallUnit = $texts["linux/mrd-relay-firewall.service"]
foreach ($pattern in @(
    '(?m)^Type=oneshot$',
    '(?m)^User=root$',
    '(?m)^ExecStart=/usr/local/libexec/mrd-relay-firewall apply$',
    '(?m)^ExecStart=/usr/local/libexec/mrd-relay-firewall verify$',
    '(?m)^RemainAfterExit=no$'
  )) {
  Assert-Matches $firewallUnit $pattern "Linux firewall unit contains $pattern"
}
Assert-NotMatches $firewallUnit '(?m)^ConditionPathExists=' `
  "missing firewall configuration fails the required start job instead of skipping it"
Assert-NotMatches $firewallUnit '(?m)^ExecStop=' `
  "the per-start firewall gate does not silently revoke policy when its oneshot becomes inactive"

$firewallHelper = $texts["linux/mrd-relay-firewall"]
foreach ($pattern in @(
    'nftables:apply\)',
    'firewalld:apply\)',
    'ufw:apply\)',
    'relay_firewall_backend_unknown',
    'firewall-cmd',
    'ufw',
    'nft',
    'apply\)',
    'remove\)',
    'verify\)'
    ,'--self-test'
  )) {
  Assert-Matches $firewallHelper $pattern "Linux firewall helper contains $pattern"
}

$nftables = $texts["linux/mrd-relay.nft"]
foreach ($pattern in @(
    'table inet mrd_relay',
    'udp dport 3478 accept',
    'tcp dport \{ 3478, CHANGE_ME_TLS_PORT \} accept',
    'meta l4proto \{ tcp, udp \} th dport 49160-49260 accept',
    'ip saddr 127\.0\.0\.0/8 tcp dport 9641 accept',
    'ip6 saddr ::1 tcp dport 9641 accept'
  )) {
  Assert-Matches $nftables $pattern "Linux nftables policy contains $pattern"
}

$renderer = $texts["linux/mrd-coturn-render-config"]
foreach ($pattern in @(
    'head -c 513',
    'stat -c.*%s',
    'relay_coturn_render_secret_size_invalid',
    'assert_trusted_ancestors',
    '__MRD_BROKER_SECRET_V1__',
    '/etc/mrd-relay-agent/secrets/turnserver\.generated\.conf',
    '/run/credentials/mrd-coturn\.service/turn-cert',
    '/run/credentials/mrd-coturn\.service/turn-key',
    'chmod 0600',
    'chown root:root'
  )) {
  Assert-Matches $renderer $pattern "coturn renderer contains $pattern"
}
Assert-NotMatches $renderer '(?m)chmod\s+0?6[1-7]0' `
  "generated coturn configuration is never group-readable"
Assert-NotMatches $renderer '(?m)(?:awk|sed|perl)[^\r\n]*\$secret' `
  "coturn renderer never passes a secret through argv"
Assert-Matches $renderer "trap 'exit 130' HUP INT TERM" `
  "coturn renderer terminates after signal cleanup"

$linuxInstall = $texts["linux/install-relay-node.sh"]
Assert-Matches $linuxInstall 'static-auth-secret=__MRD_BROKER_SECRET_V1__' `
  "Linux installer emits the exact closed broker secret sentinel"
foreach ($pattern in @(
    '(?m)^set -Eeuo pipefail$',
    '/run/lock/mrd-relay-deploy\.lock',
    'relay_install_deploy_lock_busy',
    'read_system_uid_range',
    'validate_service_identity_fixture',
    'assert_service_identity',
    'self_test_service_identity_contract',
    'SYS_UID_MIN',
    'SYS_UID_MAX',
    '/usr/bin/getent passwd',
    '/usr/bin/getent shadow',
    '/usr/bin/getent group',
    '/usr/bin/id -G',
    'relay_install_service_identity_password_unlocked',
    'relay_install_service_identity_supplementary_group_invalid',
    'relay_install_service_identity_group_members_invalid',
    'relay_install_system_uid_range_invalid',
    'useradd[^\r\n]*mrd-relay',
    'useradd[^\r\n]*mrd-coturn',
    'install -o root -g root -m 0600',
    'systemd-tmpfiles --create /usr/lib/tmpfiles\.d/mrd-relay-coturn-control\.conf',
    'ss[^\r\n]*:443',
    'tls-listening-port',
    '/usr/bin/systemctl daemon-reload',
    '/usr/bin/systemctl enable --now mrd-relay-coturn-control\.socket',
    '/usr/bin/systemctl enable --now mrd-relay-firewall\.service',
    '/usr/bin/systemctl enable --now mrd-relay-agent\.service',
    'mrd-verify-relay-node',
    '10-low-port\.conf',
    'CapabilityBoundingSet=CAP_NET_BIND_SERVICE',
    'AmbientCapabilities=CAP_NET_BIND_SERVICE',
    'relay_install_config_duplicate',
    'relay_install_config_unknown',
    'relay_install_config_placeholder',
    'relay_install_bandwidth_not_byte_aligned',
    'max_egress_bps % 8',
    'max_egress_bps / 8',
    'relay_install_secret_size_invalid',
    '--enrollment-token-file',
    '--trusted-ca',
    'enrollment_token_path',
    '/run/credentials/mrd-relay-agent\.service/enrollment-token',
    '/run/credentials/mrd-relay-agent\.service/turn-rest-secret',
    '/run/credentials/mrd-relay-agent\.service/trusted-ca',
    'assert_trusted_ancestors',
    '--firewall-backend',
    'nftables\|firewalld\|ufw',
    'relay_install_firewall_backend_unknown'
    ,'--self-test'
    ,'125000000'
    ,'transaction_committed=false'
    ,'rollback_install'
    ,'checkpoint_drained_broker_state'
    ,'control-state\.json'
    ,'control-journal\.json'
    ,'relay_install_drained_control_state_mode_invalid'
    ,'trap on_exit EXIT'
    ,'systemctl stop mrd-relay-agent\.service'
    ,'/proc/\$running_agent_pid/exe'
  )) {
  Assert-Matches $linuxInstall $pattern "Linux installer contains $pattern"
}
Assert-Matches $linuxInstall '(?s)assert_service_identity mrd-relay /nonexistent.*?assert_service_identity mrd-coturn /nonexistent.*?first_drain_proof=' `
  "Linux installer proves existing NSS identities before upgrade drain or managed mutation"
Assert-Matches $linuxInstall '(?s)useradd[^\r\n]*mrd-coturn.*?assert_service_identity mrd-relay /nonexistent.*?assert_service_identity mrd-coturn /nonexistent' `
  "Linux installer reads back both service identities after creation"
Assert-NotMatches $linuxInstall '(?m)--turn-config\b' `
  "Linux installer never accepts an arbitrary coturn configuration"
$nonRollbackLinuxInstall = [regex]::Replace(
  $linuxInstall,
  '(?s)rollback_install\(\)\s*\{.*?\n\}\s*\n\s*on_exit\(\)',
  'on_exit()'
)
Assert-NotMatches $nonRollbackLinuxInstall '(?m)systemctl\s+(?:enable|start|restart|enable --now)[^\r\n]*mrd-coturn\.service' `
  "fresh installation never bypasses the broker to start coturn"

$linuxFirewall = $texts["linux/mrd-relay-firewall"]
foreach ($pattern in @(
    'assert_trusted_ancestors "\$nft_policy"',
    'root:root:644',
    'mrd-relay-owner-v1',
    'relay_firewall_nftables_unknown_table',
    'nft_snapshot_valid',
    'relay_firewall_nftables_live_rules_invalid',
    'relay_firewall_self_test_tampered_live_rules_accepted',
    'relay_firewall_self_test_extra_live_rule_accepted',
    'load_firewalld_provenance', 'store_firewalld_provenance', 'owned_port=',
    'pending_add_port=', 'pending_remove_port=',
    'firewalld_classify_mutation_result', 'ALREADY_ENABLED', 'NOT_ENABLED',
    'validate_ufw_provenance', 'store_ufw_provenance',
    'ufw_classify_add_result', 'state=\(owned\|pending_add\|pending_remove\|ambiguous\)',
    'durable_write_lines', 'durable_remove_file', 'os\.replace', 'os\.fsync',
    'relay_firewall_firewalld_concurrent_rule', 'relay_firewall_ufw_concurrent_rule',
    'relay_firewall_firewalld_ownership_ambiguous', 'relay_firewall_ufw_ownership_ambiguous',
    'relay_firewall_firewalld_remove_failed', 'relay_firewall_ufw_remove_failed'
  )) {
  Assert-Matches $linuxFirewall $pattern "Linux firewall helper contains $pattern"
}
Assert-NotMatches $linuxFirewall '\|\| true' `
  "firewall rollback and removal errors are never swallowed"
Assert-NotMatches $linuxFirewall '/usr/bin/rm -f -- "\$(?:firewalld_state|ufw_state)"' `
  "firewall provenance deletion is directory-fsynced instead of directly unlinked"
Assert-Matches $linuxFirewall '(?s)firewalld_set_port_state "\$port" pending_add.*?--query-port="\$port".*?run_firewalld_mutation add "\$port"' `
  "firewalld durably marks pending add and re-queries ownership before mutation"
Assert-Matches $linuxFirewall '(?s)firewalld_set_port_state "\$port" pending_remove.*?run_firewalld_mutation remove "\$port".*?--query-port="\$port"' `
  "firewalld removal remains pending until permanent and runtime readback"
Assert-Matches $linuxFirewall '(?s)store_ufw_provenance pending_add.*?ufw_rule_count.*?ufw allow MRD-Relay.*?ufw_classify_add_result' `
  "UFW durably marks pending add and classifies the manager mutation result"
Assert-Matches $linuxFirewall '(?s)created_provenance" -eq 0.*?ufw app update MRD-Relay.*?return.*?fresh claim, do not run `ufw app update`' `
  "UFW never rewrites a concurrently appearing same-name rule during a fresh claim"
Assert-Matches $linuxFirewall '(?s)store_ufw_provenance pending_remove.*?ufw --force delete allow MRD-Relay.*?ufw_rule_count.*?durable_remove_file' `
  "UFW removal remains pending through exact readback"

$linuxUninstall = $texts["linux/uninstall-relay-node.sh"]
foreach ($pattern in @(
    '(?m)^set -Eeuo pipefail$',
    '/run/lock/mrd-relay-deploy\.lock',
    'relay_uninstall_deploy_lock_busy',
    'paths_intersect',
    'assert_archive_root_isolated',
    'self_test_archive_root_isolation',
    'relay_uninstall_archive_root_overlaps_managed_path',
    'relay_uninstall_self_test_self_archive_accepted',
    '/etc/mrd-relay-agent/removals',
    '/usr/bin/systemctl stop mrd-relay-agent\.service',
    '/usr/bin/systemctl disable mrd-relay-agent\.service',
    '/usr/bin/systemctl disable mrd-relay-firewall\.service',
    'mrd-relay-firewall verify',
    'relay_uninstall_firewall_ownership_invalid',
    'relay_uninstall_first_drain_proof_failed',
    'relay_uninstall_second_drain_proof_failed',
    '(?:archive|recovery)',
    'archive_path /etc/mrd-relay-agent',
    'archive_path /var/lib/mrd-relay-agent'
  )) {
  Assert-Matches $linuxUninstall $pattern "Linux uninstaller contains $pattern"
}
Assert-Matches $linuxUninstall '(?s)canonical_archive_root=.*?assert_archive_root_isolated.*?first_drain_proof=' `
  "Linux uninstall rejects archive/source path overlap before the first drain proof"
$preFenceLinuxUninstall = $linuxUninstall.Split(
  @('assert_same_drain_fence "$first_drain_proof" "$second_drain_proof"'),
  [StringSplitOptions]::None
)[0]
Assert-NotMatches $preFenceLinuxUninstall '(?m)systemctl\s+(?:disable|stop|restart|disable --now)[^\r\n]*mrd-coturn\.service' `
  "Linux uninstaller does not stop coturn before the authenticated drain fence"
Assert-NotMatches $linuxUninstall '(?m)\brm\s+-[^\r\n]*r' `
  "Linux uninstaller never recursively deletes state or secrets"
Assert-NotMatches $linuxInstall '(?m)^\s*/usr/bin/systemctl start mrd-coturn\.service' `
  "Linux rollback never starts coturn outside the broker state machine"

$linuxVerify = $texts["linux/verify-relay-node.sh"]
foreach ($field in @(
    "schema_version", "scope", "target", "generation", "applied_secret_version",
    "challenge_sha256",
    "listener_reachable", "credential_authenticated", "allocation_created",
    "permission_created", "packets_sent", "packets_received", "bytes_sent",
    "bytes_received", "local_candidate_kind", "remote_candidate_kind", "proof_sha256"
  )) {
  Assert-Matches $linuxVerify $field "Linux verification requires $field evidence"
}
Assert-Matches $linuxVerify 'mrd-relay-agent preflight --config' `
  "Linux verification runs the production live preflight"
Assert-Matches $linuxVerify '(?:--challenge|challenge_sha256)' `
  "Linux verification binds evidence to a fresh challenge"
Assert-Matches $linuxVerify '(?:expected_keys|expectedKeys|required_keys)' `
  "Linux verification enforces the exact preflight key set"
Assert-Matches $linuxVerify '(?:--self-test|self_test)' `
  "Linux verifier has pure dynamic negative contract tests"
foreach ($pattern in @(
    '--drained', '--expected-target', '--expected-generation', '--expected-secret-version',
    'mrd-relay-drain-proof', 'relay_verify_drained_coturn_still_active',
    'relay_verify_drained_fence_mismatch', 'relay_verify_drained_passed',
    'relay_verify_self_test_drained_fence_mismatch_accepted',
    'is-enabled --quiet mrd-relay-firewall\.service',
    'relay_verify_firewall_disabled', 'relay_verify_firewall_residency_invalid'
  )) {
  Assert-Matches $linuxVerify $pattern "Linux drained verifier contains $pattern"
}
Assert-NotMatches $linuxVerify 'is-active --quiet mrd-relay-firewall\.service' `
  "Linux verifier does not require a successful non-resident firewall oneshot to remain active"
Assert-Matches $linuxVerify '(?s)if \[\[ "\$drained" == true \]\].*?systemctl is-active --quiet mrd-coturn\.service.*?mrd-relay-drain-proof.*?else.*?mrd-relay-agent preflight --config' `
  "Linux drained verification proves broker-controlled zero allocation without a live allocation preflight"
Assert-Matches $linuxVerify 'systemd-run[^\r\n]*--uid=mrd-relay' `
  "Linux verification executes the read-only probe as the dedicated agent identity"
Assert-Matches $linuxVerify '(?i)(?:broker|no_state_mutation|read_only_probe)' `
  "Linux live preflight is explicitly a read-only broker probe"
foreach ($field in @("max_allocations", "max_egress_bps", "total-quota", "bps-capacity", "min-port", "max-port", "mrd-relay.nft", "bps_capacity \* 8")) {
  Assert-Matches $linuxVerify $field "Linux verification reconciles $field"
}
Assert-NotMatches $linuxVerify '(?m)\b(?:nc|netcat|Test-NetConnection)\b' `
  "Linux verification does not mistake a port-open check for TURN evidence"

$powerShellFiles = @(
  "windows/install-relay-node.ps1",
  "windows/uninstall-relay-node.ps1",
  "windows/verify-relay-node.ps1"
)
foreach ($relativePath in $powerShellFiles) {
  Assert-PowerShellSyntaxAndLiteralPaths $relativePath $texts[$relativePath]
}

$windowsInstall = $texts["windows/install-relay-node.ps1"]
foreach ($pattern in @(
    'SupportsShouldProcess\s*=\s*\$true',
    'ValidateSet\("Native",\s*"Docker",\s*"Wsl2"\)',
    '\$AgentServiceName\s*=\s*"mrd-relay-agent"',
    '\$BrokerServiceName\s*=\s*"mrd-relay-coturn-control"',
    '\$ControlPipeName\s*=\s*"\\\\\.\\pipe\\mrd-relay-coturn-control"',
    '\$DockerContainerName\s*=\s*"mrd-coturn"',
    '\$WslDistributionName\s*=\s*"MRDRelay"',
    'start=",\s*"delayed-auto"',
    'sidtype",\s*\$AgentServiceName,\s*"restricted"',
    'sidtype",\s*\$BrokerServiceName,\s*"restricted"',
    'failureflag",\s*\$AgentServiceName,\s*"0"',
    'failure",\s*\$AgentServiceName',
    'restart/5000/restart/30000/none/0',
    'reset=",\s*"4294967295"',
    'NT AUTHORITY\\LocalService',
    'LocalSystem',
    '\$DataRoot\s*=\s*"\$env:ProgramData\\MRD\\RelayAgent"',
    'provision-windows',
    '--purpose',
    'RedirectStandardInput\s*=\s*\$true',
    'target_config',
    'transport_capabilities',
    'relay_min_port',
    'relay_max_port',
    'tls_listener_port',
    'agent_service_sid',
    'broker_executable',
    'broker_sha256',
    'active_turn_secret_path',
    'broker_service_sid',
    'control-state\.dpapi',
    'control-journal\.dpapi',
    'ReparsePoint',
    '/inheritance:r',
    'Get-NetTCPConnection[^\r\n]*443',
    'OpenSslExecutable',
    'x509.*-checkend.*86400',
    'pkey.*-pubout',
    'relay_install_tls_key_mismatch',
    'Realm',
    'ServerName',
    'ExternalIp',
    'Test-GlobalIpAddress',
    'SelfTest',
    'relay_install_public_ip_self_test_passed',
    'IsIPv4MappedToIPv6',
    'RelayIp',
    'relay_install_endpoint_server_name_mismatch',
    'relay_install_external_ip_family_mismatch',
    'relay_install_relay_ip_family_mismatch',
    'relay_install_turn_baseline_placeholder',
    '__MRD_BROKER_SECRET_V1__',
    'UPGRADE-RECOVERY\.json',
    'relay_install_target_switch_requires_explicit_migration',
    'Preserve-UpgradeState',
    'identity\.json',
    'runtime\.json',
    'active-turn-secret\.dpapi',
    'control-state\.dpapi',
    'control-journal\.dpapi',
    'docker-identity\.json',
    'docker-envelope',
    'Restore-UpgradeCheckpoint',
    'relay_install_complete_drained',
    'firewall_rules',
    'restore_order',
    'drain-proof',
    'drain_completed',
    'VerifiedNativeDrainWrapper',
    'Get-AuthenticodeSignature',
    'Status\s*-ne\s*"Valid"',
    'restart=no',
    'RestartPolicy',
    'coturn/coturn:4\.17\.2@sha256:aa68aab64a3b929d57fc2924c98ea447bf996cf8dade2508e7b71eaf23f1f14e',
    'io\.mrd\.relay\.managed',
    'expected_container_id_state_path',
    'DockerExecutableSha256',
    'WslExecutableSha256',
    'target_manager_sha256',
    'mirrored',
    'mrd-relay-agent\.exe',
    '"preflight"',
    'Move-Item\s+-LiteralPath',
    'MRD relay deployment lock v1',
    'SpecialFolder\]::CommonApplicationData',
    'FileShare\]::None',
    'Invoke-BoundedNativeProcess', 'ValidateSet\("Utf8",\s*"Utf16Le"\)',
    'Assert-CurrentProcessIsLocalSystem', 'S-1-5-18',
    'Test-ScDependencyToken', 'relay_install_scm_self_test_multiline_dependencies_lost',
    'MRD 依赖 \$Svc', 'Set-UpgradeTransactionPhase',
    'Get-ScmUnicodeDependencies', 'Get-ScmUnicodeConfiguration',
    'QueryServiceConfigW', 'QueryServiceConfig2W', 'ExactBaseConfiguration',
    'relay_install_scm_self_test_unicode_authority_not_used',
    'relay_install_scm_self_test_unicode_base_configuration_not_used',
    'relay_install_lock_self_test_existing_boundary_reowned',
    '\[IO\.Directory\]::Move\(\$temporary,\s*\$boundary\)'
  )) {
  Assert-Matches $windowsInstall $pattern "Windows installer contains $pattern"
}
Assert-NotMatches $windowsInstall '(?im)(?:icacls|FileSystemAccessRule)[^\r\n]*LocalService' `
  "Windows secret ACL never grants the shared LocalService identity"
Assert-NotMatches $windowsInstall '(?im)ProtectedData\]::Protect' `
  "PowerShell never invents an incompatible raw DPAPI blob"
Assert-NotMatches $windowsInstall '(?im)DataProtectionScope\]::LocalMachine' `
  "Machine DPAPI is applied only by the bound Rust secret store"
Assert-NotMatches $windowsInstall '(?im)docker-users' `
  "Windows agent is never added to docker-users"
Assert-NotMatches $windowsInstall '(?m)^\s*&\s+\$(?:DockerExecutable|WslExecutable|dockerPath|wslPath)\b' `
  "Windows installer never invokes Docker or WSL outside the bounded process runner"
Assert-Matches $windowsInstall '(?s)ShouldProcess\(\$InstallRoot.*?Initialize-MachineDeploymentLockBoundary.*?Enter-DeploymentTransactionLock.*?\$existingTargetPath\s*=' `
  "Windows installer holds the fixed machine lock before classifying existing state"
Assert-NotMatches $windowsInstall 'renderedLine -cne "static-auth-secret=CHANGE_ME' `
  "Windows installed baseline never permits a CHANGE_ME secret placeholder"
Assert-Matches $windowsInstall 'public-ip-test-vectors\.json' `
  "Windows installer exercises the shared public-IP classifier vectors"
Assert-Matches $windowsInstall '(?s)Get-CompletedDrainProof.*Stop-ExactService\s+\$AgentServiceName.*Get-CompletedDrainProof.*Assert-SameDrainFence.*Stop-ExactService\s+\$BrokerServiceName' `
  "Windows upgrade stops the agent between two fresh broker proofs and fences target generation/version before stopping the broker"
Assert-Matches $windowsInstall 'Set-ExactAgentReadAcl' `
  "Windows installer has a distinct immutable config/CA read ACL"
Assert-Matches $windowsInstall 'Assert-TrustedDestinationAncestors' `
  "Windows installer validates destination ancestor owner and write ACLs"
foreach ($pattern in @(
    'SystemManagedAncestorAllowlist', 'WriteData', 'AppendData',
    'DeleteSubdirectoriesAndFiles', 'ChangePermissions', 'TakeOwnership',
    'PropagationFlags.*InheritOnly',
    'Test-AncestorAccessRuleAllowed',
    'relay_install_acl_self_test_standard_ancestor_rejected',
    'relay_install_acl_self_test_inherit_only_delete_rejected',
    'relay_install_acl_self_test_effective_delete_accepted',
    'Assert-ExactSystemAdminBoundaryAcl',
    'relay_install_destination_writer_invalid'
  )) {
  Assert-Matches $windowsInstall $pattern "Windows installer ancestor ACL gate contains $pattern"
}
Assert-Matches $windowsInstall '(?s)Set-ExactAgentReadAcl\s+\$agentConfigPath.*Set-ExactAgentReadAcl\s+\$trustedCa' `
  "Windows installer grants the agent read-only access to config and trusted CA"
Assert-Matches $windowsInstall '(?s)if \(\$isUpgrade\).*?-Drained.*?Get-CompletedDrainProof.*?Assert-SameDrainFence.*?relay_install_complete_drained' `
  "Windows upgrade verifies static state plus a post-install drain proof and remains drained"
foreach ($pattern in @(
    'RecoveryRootMarkerName', 'Assert-DisjointManagedRoots',
    'Test-RecoveryRootDisposition', 'Initialize-OrValidateRecoveryRoot',
    'relay_install_root_overlap_rejected',
    'relay_install_recovery_marker_schema_invalid',
    'relay_install_recovery_self_test_windows_accepted',
    'relay_install_recovery_self_test_nested_roots_accepted',
    'relay_install_recovery_self_test_forged_marker_accepted'
  )) {
  Assert-Matches $windowsInstall $pattern "Windows installer recovery-root gate contains $pattern"
}
Assert-NotMatches $windowsInstall '(?s)CreateDirectory\(\$RecoveryRoot\).*?Set-SystemAdminDirectoryAcl\s+\$RecoveryRoot' `
  "Windows installer never strips an arbitrary existing RecoveryRoot ACL"
Assert-Matches $windowsInstall '(?s)Initialize-DefaultManagedBoundary.*?Get-SafeFullPath\s+\$destination.*?Assert-TrustedDestinationAncestors' `
  "Windows installer revalidates reparse-free roots after creating the protected MRD boundary"
foreach ($pattern in @(
    'Get-ExpectedListeningIp',
    'listening-ip=\$expectedListeningIp',
    'relay_install_endpoint_listener_family_mismatch',
    'relay_install_listener_self_test_ipv6_mismatch'
  )) {
  Assert-Matches $windowsInstall $pattern "Windows installer binds listener family: $pattern"
}
foreach ($pattern in @(
    'Test-ExactDockerProductionSpec', '/usr/bin/turnserver',
    'no-new-privileges:true', 'Privileged', 'CapAdd', 'CapDrop',
    'NetworkMode', 'SecurityOpt', 'Config\.User', '65534:65534',
    'PidMode', 'IpcMode', 'UsernsMode', 'Devices', 'PublishAllPorts',
    'relay_install_docker_spec_self_test_command_override_accepted',
    'relay_install_docker_spec_self_test_extra_capability_accepted',
    'relay_install_docker_spec_self_test_root_user_accepted',
    'relay_install_docker_spec_self_test_host_pid_accepted',
    'relay_install_docker_spec_self_test_device_accepted',
    'relay_install_docker_spec_self_test_null_devices_rejected'
  )) {
  Assert-Matches $windowsInstall $pattern "Windows installer freezes exact Docker production spec: $pattern"
}
foreach ($pattern in @(
    'Get-DockerEnvelopePlaceholderBytes',
    'Assert-DockerEnvelopePlaceholderSelfTest',
    '# MRD broker placeholder v1; no TURN listener',
    'no-udp.*no-tcp.*no-tls.*no-dtls',
    'Initialize-DockerEnvelope',
    'WriteAllBytes',
    'Set-ExactServiceStoreAcl',
    'relay_install_docker_envelope_existing_fresh_rejected',
    'relay_install_docker_envelope_placeholder_mismatch'
  )) {
  Assert-Matches $windowsInstall $pattern "Windows installer creates the exact disabled Docker envelope placeholder: $pattern"
}
Assert-NotMatches $windowsInstall '(?s)Assert-UpgradeStateAvailable.*?Get-Content[^\r\n]*docker-envelope' `
  "Windows upgrade treats the broker-owned Docker envelope as opaque"
foreach ($pattern in @(
    'Assert-DockerMountSafeDataRoot',
    'relay_install_docker_data_root_mount_syntax_invalid',
    'Test-WslInstallDisposition',
    'relay_install_wsl_fresh_self_test_accepted',
    'relay_install_wsl_fresh_requires_verified_provisioning'
  )) {
  Assert-Matches $windowsInstall $pattern "Windows installer fails closed for target provisioning: $pattern"
}
foreach ($pattern in @(
    'ConvertFrom-ScServiceTranscript', 'Get-ExactScmSnapshot',
    'Restore-ExactScmSnapshot', 'Assert-ExactScmSnapshotEqual',
    '"qc"', '"qfailure"', '"qfailureflag"', '"qsidtype"',
    'relay_install_scm_snapshot_incomplete',
    'FAILURE_ACTIONS_ON_NONCRASH_FAILURES: TRUE',
    'FAILURE_ACTIONS_ON_NONCRASH_FAILURES: FALSE',
    'relay_install_scm_self_test_boolean_failureflag_not_normalized',
    'relay_install_scm_self_test_unknown_failureflag_accepted',
    'relay_install_scm_rollback_readback_mismatch',
    'relay_install_scm_self_test_mutation_not_detected',
    'relay_install_scm_self_test_restored_mismatch'
  )) {
  Assert-Matches $windowsInstall $pattern "Windows installer snapshots/restores exact SCM contract: $pattern"
}
Assert-Matches $windowsInstall '(?s)\$scmSnapshots\s*=.*?Get-ExactScmSnapshot.*?Configure-Service' `
  "Windows upgrade snapshots SCM before mutating service definitions"
Assert-Matches $windowsInstall '(?s)function Get-ScDependenciesFromQc.*?DEPENDENCIES.*?\$continuation.*?ConvertTo-CanonicalScDependencies' `
  "Windows installer captures and validates multiline SCM dependencies"
Assert-Matches $windowsInstall '(?s)function Restore-UpgradeCheckpoint.*?Restore-ExactScmSnapshot.*?(?:Invoke-Sc\s+@\(\"start\"|start-service)' `
  "Windows rollback restores and verifies SCM definitions before restarting services"
foreach ($pattern in @(
    'Stop-ChangedTargetForRollback', 'Assert-RollbackTargetStopPlanSelfTest',
    'relay_install_rollback_target_stop_failed', 'relay_install_rollback_target_still_running',
    '(?s)"Docker".*?@\("stop"', '--terminate', '--list', '--running'
  )) {
  Assert-Matches $windowsInstall $pattern "Windows install rollback target fence contains $pattern"
}
Assert-Matches $windowsInstall '(?s)function Restore-UpgradeCheckpoint.*?Stop-ChangedTargetForRollback.*?Move-Item\s+-LiteralPath' `
  "Windows install rollback stops and verifies the changed target before moving roots"
Assert-Matches $windowsInstall '(?s)Set-UpgradeTransactionPhase[^\r\n]*"moving-program-root".*?Move-Item\s+-LiteralPath\s+\$InstallRoot.*?Set-UpgradeTransactionPhase[^\r\n]*"program-root-moved"' `
  "Windows install atomically records the program-root move phase before mutation"
Assert-Matches $windowsInstall '(?s)Set-UpgradeTransactionPhase[^\r\n]*"moving-data-root".*?Move-Item\s+-LiteralPath\s+\$DataRoot.*?Set-UpgradeTransactionPhase[^\r\n]*"data-root-moved"' `
  "Windows install atomically records the data-root move phase before mutation"

$windowsUninstall = $texts["windows/uninstall-relay-node.ps1"]
foreach ($pattern in @(
    'SupportsShouldProcess\s*=\s*\$true',
    '\$AgentServiceName\s*=\s*"mrd-relay-agent"',
    '\$BrokerServiceName\s*=\s*"mrd-relay-coturn-control"',
    'sc\.exe',
    'Move-Item\s+-LiteralPath',
    '(?:Recovery|Archive)'
    ,'drain-proof'
    ,'drain_completed'
    ,'challenge_sha256'
    ,'Get-CompletedDrainProof'
    ,'Assert-SameDrainFence'
    ,'MRD relay deployment lock v1'
    ,'SpecialFolder\]::CommonApplicationData'
    ,'FileShare\]::None'
    ,'Invoke-BoundedNativeProcess'
    ,'ValidateSet\("Utf8",\s*"Utf16Le"\)'
    ,'Assert-WslLocalSystemContext'
    ,'S-1-5-18'
    ,'Test-ScDependencyToken'
    ,'MRD 辅助服务'
    ,'Get-ScmUnicodeDependencies'
    ,'Get-ScmUnicodeConfiguration'
    ,'QueryServiceConfigW'
    ,'QueryServiceConfig2W'
    ,'ExactBaseConfiguration'
    ,'relay_uninstall_scm_self_test_unicode_base_configuration_not_used'
    ,'recoveryRootExistedBeforeLock'
    ,'lockedManifestTarget'
    ,'Assert-WslLocalSystemContext \(\[string\]\$incompleteWal\.Wal\.target\)'
  )) {
  Assert-Matches $windowsUninstall $pattern "Windows uninstaller contains $pattern"
}
Assert-Matches $windowsUninstall '(?s)Get-CompletedDrainProof.*Stop-ExactService\s+\$AgentServiceName.*Get-CompletedDrainProof.*Assert-SameDrainFence.*Stop-ExactService\s+\$BrokerServiceName' `
  "Windows uninstall stops the agent between two fresh proofs and fences the same drained target before mutation"
Assert-NotMatches $windowsUninstall '(?m)^\s*&\s+\$(?:DockerExecutable|WslExecutable|dockerPath|wslPath)\b' `
  "Windows uninstaller never invokes Docker or WSL outside the bounded process runner"
Assert-NotMatches $windowsUninstall 'preflightManifest' `
  "Windows uninstaller does not classify live manifest state before the machine lock"
Assert-Matches $windowsUninstall '(?s)ShouldProcess\(.*?Enter-DeploymentLock.*?Initialize-OrValidateRecoveryRoot.*?Find-IncompleteUninstallWal.*?if \(-not \[IO\.File\]::Exists\(\$manifestPath\)\)' `
  "Windows uninstaller locks before recovery scanning and live manifest classification"
foreach ($pattern in @(
    'SelfTest', 'RecoveryRootMarkerName', 'Assert-DisjointManagedRoots',
    'Test-RecoveryRootDisposition', 'Initialize-OrValidateRecoveryRoot',
    'relay_uninstall_root_overlap_rejected',
    'relay_uninstall_recovery_marker_schema_invalid',
    'relay_uninstall_recovery_self_test_windows_accepted',
    'relay_uninstall_recovery_self_test_nested_roots_accepted',
    'relay_uninstall_recovery_self_test_forged_marker_accepted'
  )) {
  Assert-Matches $windowsUninstall $pattern "Windows uninstaller recovery-root gate contains $pattern"
}
foreach ($pattern in @(
    'Test-ExactDockerProductionSpec', '/usr/bin/turnserver',
    'no-new-privileges:true', 'Privileged', 'CapAdd', 'CapDrop',
    'NetworkMode', 'SecurityOpt', 'Config\.User', '65534:65534',
    'PidMode', 'IpcMode', 'UsernsMode', 'Devices', 'PublishAllPorts',
    'relay_uninstall_docker_spec_self_test_command_override_accepted',
    'relay_uninstall_docker_spec_self_test_extra_capability_accepted',
    'relay_uninstall_docker_spec_self_test_root_user_accepted',
    'relay_uninstall_docker_spec_self_test_host_pid_accepted',
    'relay_uninstall_docker_spec_self_test_device_accepted',
    'relay_uninstall_docker_spec_self_test_null_devices_rejected'
  )) {
  Assert-Matches $windowsUninstall $pattern "Windows uninstaller freezes exact Docker production spec: $pattern"
}
foreach ($pattern in @(
    'Assert-DockerMountSafeDataRoot',
    'relay_uninstall_docker_data_root_mount_syntax_invalid',
    '--terminate', '--list', '--running',
    'relay_uninstall_wsl_terminate_failed',
    'relay_uninstall_wsl_still_running',
    'Test-RunningWslDistribution',
    'relay_uninstall_wsl_running_self_test_false_match'
  )) {
  Assert-Matches $windowsUninstall $pattern "Windows uninstaller preserves exact target ownership: $pattern"
}
Assert-NotMatches $windowsUninstall '--unregister' "Windows uninstall preserves the WSL distribution"
Assert-NotMatches $windowsUninstall '(?s)CreateDirectory\(\$RecoveryRoot\).*?Set-SystemAdminDirectoryAcl\s+\$RecoveryRoot' `
  "Windows uninstaller never strips an arbitrary existing RecoveryRoot ACL"
foreach ($pattern in @(
    'ConvertFrom-ScServiceTranscript', 'Get-ExactScmSnapshot',
    'Restore-ExactScmSnapshot', 'Assert-ExactScmSnapshotEqual',
    'Write-UninstallWal', 'Restore-UninstallCheckpoint',
    '\[IO\.File\]::Replace',
    'deleted_services', 'moved_roots', 'relay_uninstall_scm_rollback_failed',
    'relay_uninstall_service_absence_readback_failed',
    'relay_uninstall_scm_marked_delete_timeout', '-lt 30',
    'Assert-UninstallRollbackPlanSelfTest',
    'FAILURE_ACTIONS_ON_NONCRASH_FAILURES: TRUE',
    'FAILURE_ACTIONS_ON_NONCRASH_FAILURES: FALSE',
    'relay_uninstall_scm_self_test_unknown_failureflag_accepted',
    'relay_uninstall_scm_self_test_partial_delete_restore_invalid'
    ,'Find-IncompleteUninstallWal'
    ,'Read-And-ValidateUninstallWal'
    ,'relay_uninstall_wal_schema_invalid'
    ,'relay_uninstall_incomplete_wal_recovered'
    ,'Stop-CurrentTargetForUninstall'
    ,'relay_uninstall_target_stop_readback_failed'
    ,'Wait-ServiceRunning'
    ,'relay_uninstall_service_start_timeout'
  )) {
  Assert-Matches $windowsUninstall $pattern "Windows uninstall transactional SCM recovery contains $pattern"
}
Assert-Matches $windowsUninstall '(?s)\$serviceStates\s*=.*?Get-ExactScmSnapshot.*?Write-UninstallWal.*?try\s*\{.*?Remove-ExactScmRegistration.*?catch\s*\{.*?Restore-UninstallCheckpoint' `
  "Windows uninstall writes exact SCM WAL before deletion and rolls back every failed phase"
Assert-Matches $windowsUninstall '(?s)Restore-UninstallCheckpoint.*?Restore-ExactScmSnapshot.*?Test-ServiceExists.*?relay_uninstall_service_absence_readback_failed' `
  "Windows uninstall rollback verifies services that were originally absent remain absent"
Assert-Matches $windowsUninstall '(?s)ShouldProcess\(.*?Enter-DeploymentLock.*?Initialize-OrValidateRecoveryRoot.*?Find-IncompleteUninstallWal.*?Restore-UninstallCheckpoint.*?return.*?if \(-not \[IO\.File\]::Exists\(\$manifestPath\)\)' `
  "Windows uninstall recovers a protected incomplete WAL before reading live install state or taking a new snapshot"
Assert-Matches $windowsUninstall '(?s)ShouldProcess\(.*?\)\)\s*\{\s*return\s*\}.*?Enter-DeploymentLock.*?Initialize-OrValidateRecoveryRoot\s+\$RecoveryRoot' `
  "Windows uninstall never creates RecoveryRoot when normal uninstall is declined or WhatIf"
Assert-Matches $windowsUninstall '(?s)Assert-SameDrainFence.*?Stop-ExactService\s+\$BrokerServiceName.*?Stop-CurrentTargetForUninstall.*?Remove-ExactScmRegistration.*?Move-Item\s+-LiteralPath' `
  "Windows uninstall stops and reads back the exact target before SCM deletion or root movement"
Assert-Matches $windowsUninstall '(?s)function Restore-UninstallCheckpoint.*?NativeCoturnServiceName.*?BrokerServiceName.*?AgentServiceName.*?Wait-ServiceRunning' `
  "Windows uninstall rollback restores running services in target, broker, agent dependency order with bounded readback"
Assert-Matches $windowsUninstall '(?s)function ConvertFrom-ScDependencies.*?DEPENDENCIES.*?\$continuation.*?Test-ScDependencyToken' `
  "Windows uninstall captures and validates multiline SCM dependencies"

$windowsVerify = $texts["windows/verify-relay-node.ps1"]
foreach ($pattern in @(
    'qsidtype',
    'qfailure',
    'restart/5000/restart/30000/none/0',
    '4294967295',
    '\$AgentServiceName\s*=\s*"mrd-relay-agent"',
    '\$BrokerServiceName\s*=\s*"mrd-relay-coturn-control"',
    '\$ControlPipeName\s*=\s*"\\\\\.\\pipe\\mrd-relay-coturn-control"',
    'ReparsePoint',
    'VerifiedNativeDrainWrapper',
    'Get-AuthenticodeSignature',
    'RestartPolicy',
    'Restart=no',
    'io\.mrd\.relay\.managed',
    'container_id',
    'target_config',
    'agent_service_sid',
    'broker_service_sid',
    'active_turn_secret_path',
    'control-state\.dpapi',
    'control-journal\.dpapi',
    'mirrored',
    'mrd-relay-agent\.exe',
    '"preflight"',
    'ConvertFrom-Json'
    'Assert-ExactAgentReadAcl'
    'Assert-TrustedManagedAncestorAcl'
    'Drained'
    'drain-proof'
    'relay_verify_drained_passed'
    'Invoke-BoundedNativeProcess'
    'ValidateSet\("Utf8",\s*"Utf16Le"\)'
    'Assert-CurrentProcessIsLocalSystem'
    'S-1-5-18'
  )) {
  Assert-Matches $windowsVerify $pattern "Windows verifier contains $pattern"
}
Assert-NotMatches $windowsVerify '(?im)ProtectedData\]::Unprotect' `
  "PowerShell verification never decrypts machine-scope relay secrets"
Assert-NotMatches $windowsVerify '(?im)docker-users' `
  "Windows verification never relies on docker-users"
Assert-NotMatches $windowsVerify '(?m)^\s*&\s+\$(?:DockerExecutable|WslExecutable|dockerPath|wslPath)\b' `
  "Windows verifier never invokes Docker or WSL outside the bounded process runner"
Assert-Matches $windowsVerify '(?s)Assert-ExactAgentReadAcl\s+\$agentConfigPath.*Assert-ExactAgentReadAcl\s+\$trustedCaPath' `
  "Windows verification proves config and trusted CA are agent-read-only"
foreach ($pattern in @(
    'SystemManagedAncestorAllowlist', 'WriteData', 'AppendData',
    'DeleteSubdirectoriesAndFiles', 'ChangePermissions', 'TakeOwnership',
    'PropagationFlags.*InheritOnly',
    'Test-AncestorAccessRuleAllowed',
    'relay_verify_acl_self_test_standard_ancestor_rejected',
    'relay_verify_acl_self_test_inherit_only_delete_rejected',
    'relay_verify_acl_self_test_effective_delete_accepted',
    'Assert-ExactSystemAdminBoundaryAcl',
    'relay_verify_ancestor_writer_invalid'
  )) {
  Assert-Matches $windowsVerify $pattern "Windows verifier ancestor ACL gate contains $pattern"
}
foreach ($pattern in @(
    'Get-ExpectedListeningIp',
    'relay_verify_listener_family_mismatch',
    'relay_verify_endpoint_listener_family_mismatch',
    'relay_verify_listener_self_test_ipv6_mismatch'
  )) {
  Assert-Matches $windowsVerify $pattern "Windows verifier binds listener family: $pattern"
}
foreach ($pattern in @(
    'Test-ExactDockerProductionSpec', '/usr/bin/turnserver',
    'no-new-privileges:true', 'Privileged', 'CapAdd', 'CapDrop',
    'NetworkMode', 'SecurityOpt', 'Config\.User', '65534:65534',
    'PidMode', 'IpcMode', 'UsernsMode', 'Devices', 'PublishAllPorts',
    'relay_verify_docker_spec_self_test_command_override_accepted',
    'relay_verify_docker_spec_self_test_extra_capability_accepted',
    'relay_verify_docker_spec_self_test_root_user_accepted',
    'relay_verify_docker_spec_self_test_host_pid_accepted',
    'relay_verify_docker_spec_self_test_device_accepted',
    'relay_verify_docker_spec_self_test_null_devices_rejected'
  )) {
  Assert-Matches $windowsVerify $pattern "Windows verifier freezes exact Docker production spec: $pattern"
}
foreach ($pattern in @(
    'Assert-DockerMountSafeDataRoot',
    'relay_verify_docker_data_root_mount_syntax_invalid'
  )) {
  Assert-Matches $windowsVerify $pattern "Windows verifier rejects ambiguous Docker mount roots: $pattern"
}

$linuxInstall = $texts["linux/install-relay-node.sh"]
Assert-Matches $linuxInstall 'public-ip-test-vectors\.json' `
  "Linux installer exercises the shared public-IP classifier vectors"
foreach ($pattern in @(
    'mrd-relay-drain-proof', 'first_drain_proof', 'second_drain_proof',
    'assert_same_drain_fence', 'coturn_was_active', 'coturn_was_enabled'
  )) {
  Assert-Matches $linuxInstall $pattern "Linux installer contains upgrade drain fence $pattern"
}
Assert-Matches $linuxInstall '(?s)first_drain_proof=.*mrd-relay-drain-proof.*systemctl stop mrd-relay-agent\.service.*second_drain_proof=.*mrd-relay-drain-proof.*assert_same_drain_fence.*systemctl stop mrd-relay-coturn-control\.socket.*systemctl stop mrd-coturn\.service' `
  "Linux upgrade obtains two matching proofs around the agent stop before stopping broker/coturn"
foreach ($pattern in @(
    'filesystem_mutation_started=false', 'agent_stop_attempted=true',
    'socket_stop_attempted=true', 'coturn_stop_attempted=true',
    'if \[\[ "\$filesystem_mutation_started" != true \]\]',
    'never stop a still-live drained coturn', 'relay_install_early_rollback_failed',
    'firewall_policy_remove_attempted=true',
    'mrd-relay-firewall verify', 'mrd-relay-firewall remove',
    'firewall_cleanup_succeeded=false',
    'relay_install_rollback_firewall_cleanup_failed',
    'relay_install_ufw_name_collision', 'relay_install_existing_ufw_ownership_invalid'
  )) {
  Assert-Matches $linuxInstall $pattern "Linux early upgrade rollback contains $pattern"
}
Assert-Matches $linuxInstall '(?s)agent_stop_attempted=true.*?stop mrd-relay-agent\.service.*?second_drain_proof=.*?assert_same_drain_fence.*?socket_stop_attempted=true.*?coturn_stop_attempted=true.*?filesystem_mutation_started=true.*?/usr/bin/install' `
  "Linux records every service transition before mutation and enters full rollback only at the first file replacement"
Assert-Matches $linuxInstall '(?s)if \[\[ "\$firewall_cleanup_succeeded" != true \]\].*?firewalld-added\.rules\|ufw-added\.rule.*?continue' `
  "Linux rollback preserves firewall helper state and provenance after cleanup failure"
Assert-Matches $linuxInstall '(?s)verify_arguments=\(--config.*?if \[\[ "\$existing_install" == true \]\].*?verify_arguments=\(.*?--drained.*?--expected-target.*?--expected-generation.*?--expected-secret-version.*?mrd-verify-relay-node "\$\{verify_arguments\[@\]\}"' `
  "Linux upgrade uses drained control-plane verification while fresh install alone uses live preflight"
foreach ($pattern in @(
    'public_ip_validator" listener',
    'listening-ip=\*\)',
    'relay_install_endpoint_listener_family_mismatch'
  )) {
  Assert-Matches $linuxInstall $pattern "Linux installer binds listener family: $pattern"
}
foreach ($pattern in @(
    'relay_verify_listener_family_mismatch',
    'relay_verify_endpoint_listener_family_mismatch'
  )) {
  Assert-Matches $linuxVerify $pattern "Linux verifier binds listener family: $pattern"
}
$linuxUninstall = $texts["linux/uninstall-relay-node.sh"]
Assert-Matches $linuxUninstall '(?s)first_drain_proof=.*mrd-relay-drain-proof.*systemctl stop mrd-relay-agent\.service.*second_drain_proof=.*mrd-relay-drain-proof.*assert_same_drain_fence.*systemctl disable.*mrd-relay-coturn-control\.socket.*systemctl stop mrd-coturn\.service' `
  "Linux uninstall fences drain before disabling control and stopping coturn"
foreach ($pattern in @(
    'agent_was_active=true', 'agent_stop_attempted=true',
    'drain_fence_confirmed=true', 'restore_early_agent_state_on_exit',
    'relay_uninstall_early_agent_restore_failed'
  )) {
  Assert-Matches $linuxUninstall $pattern "Linux uninstall early agent recovery contains $pattern"
}
Assert-Matches $linuxUninstall '(?s)trap restore_early_agent_state_on_exit EXIT.*?agent_stop_attempted=true.*?stop mrd-relay-agent\.service.*?second_drain_proof=.*?assert_same_drain_fence.*?drain_fence_confirmed=true' `
  "Linux uninstall restores an originally active agent when the second drain fence fails"
$linuxDrainProof = $texts["linux/mrd-relay-drain-proof"]
foreach ($pattern in @('runuser', '--user mrd-relay', 'openssl rand -hex 32', 'mrd-validate-drain-proof', '0640')) {
  Assert-Matches $linuxDrainProof $pattern "Linux drain proof helper contains $pattern"
}
Assert-Matches $linuxDrainProof "trap 'exit 130' HUP INT TERM" `
  "Linux drain proof helper terminates after signal cleanup"
foreach ($field in @(
    "schema_version", "scope", "target", "generation", "applied_secret_version",
    "challenge_sha256",
    "listener_reachable", "credential_authenticated", "allocation_created",
    "permission_created", "packets_sent", "packets_received", "bytes_sent",
    "bytes_received", "local_candidate_kind", "remote_candidate_kind", "proof_sha256"
  )) {
  Assert-Matches $windowsVerify $field "Windows verification requires $field evidence"
}
Assert-Matches $windowsVerify '(?:SelfTest|self.test)' `
  "Windows verifier has pure dynamic negative contract tests"
Assert-Matches $windowsVerify '(?:expectedKeys|ExpectedKeys)' `
  "Windows verifier enforces the exact preflight key set"
Assert-Matches $windowsVerify '(?:--challenge|challenge_sha256)' `
  "Windows verification binds evidence to a fresh challenge"
Assert-NotMatches $windowsVerify '(?im)\bTest-NetConnection\b' `
  "Windows verification does not mistake a port-open check for TURN evidence"

$readme = $texts["README.md"]
foreach ($pattern in @(
    'expiry:user_id:session_id:node_id',
    '(?i)per-node',
    '(?i)bootstrap.*disaster recovery.*no live consumer',
    '(?i)SIGUSR1',
    '(?i)minimum.*coturn.*4\.17\.2',
    '(?is)4\.17\.2.*IPv4-mapped.*IPv4-compatible.*6to4.*NAT64.*(?:normalize|normaliz|归一)',
    '(?i)Prometheus.*build',
    '(?i)UDP.*TCP.*TLS',
    '(?i)443.*conflict.*fail',
    '(?i)Native.*Docker.*WSL2',
    '(?i)native.*verified.*drain.*fail closed',
    '(?i)listener.*credential.*allocation.*permission.*bidirectional',
    '(?i)scope.?=.?local',
    '(?is)public.*Task 11.*INFRA_FAIL',
    '(?i)never.*log.*(?:secret|credential)',
    '(?i)raw.?32.*wire.*43.*(?:persisted|coturn)',
    '(?i)max_egress_bps.*bits/s.*coturn.*bytes/s',
    '(?i)recover'
    ,'(?i)coturn.*(?:Restart=no|restart policy.*no).*three.*budget'
    ,'(?is)Linux.*upgrade.*--drained.*zero-allocation.*coturn inactivity.*never considered evidence'
    ,'(?is)Windows uninstall.*protected atomic WAL.*marked-for-delete.*START_PENDING'
    ,'(?is)65534:65534.*private IPC.*no device.*PublishAllPorts=false'
  )) {
  Assert-Matches $readme $pattern "deployment README contains $pattern"
}

$regions = $texts["regions.example.yaml"]
foreach ($pattern in @(
    '(?m)^version: 1$',
    '(?m)^schema: mrd-relay-regions\.v1$',
    '(?m)^purpose: bootstrap_disaster_recovery_only$',
    '(?m)^live_consumer: none$',
    '(?m)^regions:$',
    '(?m)^\s+- node_id:',
    '(?m)^\s+failure_domain:',
    '(?m)^\s+max_allocations:',
    '(?m)^\s+max_egress_bps:'
  )) {
  Assert-Matches $regions $pattern "regions bootstrap contains $pattern"
}
Assert-NotMatches $regions '(?i)(?:secret|password|credential)\s*:' `
  "regions bootstrap never embeds credential material"

Write-Output "deploy/turn static deployment contracts passed"
