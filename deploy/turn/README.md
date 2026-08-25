# MRD multi-region TURN relay deployment

This directory is the host deployment contract for an MRD relay node. The
control plane, rather than this directory, performs live multi-region node
selection, capacity admission, draining, and failover. `regions.example.yaml`
is bootstrap disaster recovery inventory only, with no live consumer; the
database and signed control-plane directory remain authoritative.

## Frozen credential and capacity boundaries

TURN REST usernames have exactly this form:
`expiry:user_id:session_id:node_id`. Each relay has a per-node REST secret; a
secret must never be copied to another node.

The repository template uses a visible operator-source placeholder, but both
installers render the installed baseline to the exact closed sentinel
`__MRD_BROKER_SECRET_V1__`. Only the broker may replace that sentinel from its
bound active-secret store; an installed baseline containing `CHANGE_ME` fails.

The agent-to-broker secret is raw-32 wire data; the 43-character persisted/coturn representation is canonical base64url without padding.
Linux secret source files are root-owned mode `0600`; every installer input and
ancestor is root-owned and not group/world writable. On Windows the signed
agent provisions the enrollment and bootstrap TURN blobs with machine-scope
DPAPI plus purpose/node/canonical-path binding. Their exact protected DACL is
SYSTEM, Administrators, and the restricted `mrd-relay-agent` service SID
(never the shared LocalService identity). The broker's active TURN secret,
control state, and journal are separate bound stores whose exact DACL uses the
restricted broker service SID. Never log a secret, credential, token, DPAPI
plaintext, generated coturn configuration, or credential-bearing URL.

`max_egress_bps` is bits/s in the agent/backend, while coturn `max-bps` and `bps-capacity` are bytes/s.
Deployment requires divisibility by eight and
renders `bps-capacity=max_egress_bps/8`; for example, 1,000,000,000 bit/s is
125,000,000 byte/s. `max-bps` is the per-allocation byte/s ceiling and must not
exceed the node byte/s capacity. The 49160–49260 range has 101 ports, so this
baseline caps `total-quota` and `max_allocations` at 100 to preserve headroom.

## coturn compatibility and network surface

The minimum supported coturn is 4.17.2. Installation fails if the version is
older or if the installed Prometheus build lacks the required loopback metrics
options. The node exposes TURN over UDP and TCP on 3478 and TLS on 5349, plus
TCP and UDP relay ports 49160–49260. Prometheus is bound only to
`127.0.0.1:9641`. DTLS is not enabled by this baseline.
Coturn 4.17.2 unauthenticated 401 throttling is explicitly enabled with
`unauthorized-ratelimit` and `unauthorized-ratelimit-rps=10`; the deployment
does not depend on the disabled upstream default.
The 4.17.2 minimum is also a peer-ACL security contract: that implementation
normalizes IPv4-mapped IPv6, IPv4-compatible IPv6, 6to4, and NAT64 addresses
to the embedded IPv4 address before applying the IPv4 denied ranges. Do not
lower the minimum version without an executable equivalent normalization test.

TLS on 443 is explicit, and any 443 listener conflict makes installation fail fast.
Linux grants `CAP_NET_BIND_SERVICE` only through the 443 drop-in;
the default 5349 unit has no capabilities. TLS certificate, TLS private key,
REST secret, and generated configuration remain root-only sources and enter
coturn through systemd credentials; no group-readable plaintext copy exists.

The Linux installer requires an explicit `nftables`, `firewalld`, or `ufw`
backend. Unknown, unavailable, or inactive firewalls fail closed. Its managed,
reversible rules cover 3478 UDP/TCP, the TLS TCP port, and the complete relay
range for UDP/TCP. Windows creates the equivalent exact firewall rules. Site
firewalls, cloud security groups, NAT, and public routing are separate gates.
In particular, the standalone nftables table proves the managed rules exist
exactly but cannot prove that a later host base chain will not drop traffic;
public Task 11 reachability remains mandatory.
The nftables backend accepts an existing `mrd_relay` table only when its exact
rules and `mrd-relay-owner-v1` ownership chain match; an unknown same-name table
fails closed and uninstall never deletes it. Install and uninstall share a
nonblocking global deployment lock, so two package operations cannot race.
The firewall unit is a non-resident oneshot: every coturn start pulls a fresh
`apply` followed by `verify`, and a missing configuration or drifted live rule
fails the coturn start job. Firewalld records the exact zone and per-port
`pending_add`, `owned`, or `pending_remove` state in a protected provenance
file. UFW records the equivalent rule-level state and can also record
`ambiguous`. Every transition is written with a file fsync, atomic replacement,
and parent-directory fsync before the corresponding backend mutation. The
helper then classifies the manager's own mutation result under `LC_ALL=C`:
firewalld `ALREADY_ENABLED` and UFW's complete "Skipping adding existing rule"
result are collisions, while mixed UFW IPv4/IPv6 results and unknown/failing
manager results are ambiguous. A pending or ambiguous record blocks verify,
repair, and automatic removal, so a crash or an external-manager race cannot
turn an administrator replacement rule into product-owned state. UFW also
requires the exact product profile and refuses any pre-existing same-name
profile or application rule on a fresh install or backend switch.
Removal/read-back errors retain provenance and fail closed; they are never
suppressed. If install rollback cannot remove an applied firewall rule, it
preserves the installed helper, configuration, profile, and provenance instead
of erasing the only recovery evidence.
The Linux installer is an
upgrade transaction: it stops the old agent/socket only after a drain proof,
backs up exact files and service state, and rolls back files, rules, enablement,
and prior active services if any later validation fails. Fresh installs alone
run the allocation/permission/bidirectional-relay preflight. An upgrade instead
keeps coturn inactive and runs the verifier's `--drained` path: static gates,
an active control socket/broker probe, and a fresh zero-allocation `drain-proof`
must match the pre-mutation target, generation, and applied secret version.
Unknown broker state fails closed, and successful upgrade reports
`relay_install_complete_drained` without resuming traffic.
Both upgrade and uninstall obtain a fresh challenge-bound drain proof, stop
the agent, obtain a second fresh proof, and require the exact same target,
generation, and applied secret version before stopping the control socket or
coturn. The root maintenance helper copies only the non-secret config to a
temporary root:mrd-relay `0640` file and runs the closed proof CLI as the exact
mrd-relay UID, so the second proof remains available after the agent unit (and
its systemd credential directory) stops. Rollback restores the broker journal,
control state, agent, socket, and firewall state. Failures before the first file
replacement use a phase-aware rollback which never stops a still-live drained
coturn merely because the second fence failed. Once coturn has stopped, rollback
deliberately leaves its restart to the restored agent/broker state machine and
never starts it directly.

## Lifecycle and privileged broker

The unprivileged agent never controls coturn through sudo or a shell command.
On Linux it connects to
`/run/mrd-relay-coturn-control/control.sock`, a root:mrd-relay `0660` socket.
systemd passes each accepted connection as FD 3 to the root-owned fixed helper
`/usr/local/libexec/mrd-relay-coturn-control --socket-activated`. The binary
checks `SO_PEERCRED`, accepts only the exact mrd-relay UID, serializes all
operations with a global lock, bounds every frame and response, and implements
only `snapshot`, `restart`, `apply-secret`, `set-draining`, and `probe`.

The secret is never argv, environment, or log data. `apply-secret` journals a
pending transaction, atomically replaces the root-only secret envelope and
generated config, restarts the exact coturn target, binds generation to the new
invocation, and commits. A failed restart rolls back both files and restores
the previous coturn invocation. Static-auth-secret changes are restarts, not
hot reloads.

coturn `SIGUSR1` is one-way drain: it refuses new allocations and exits after
the allocation count reaches zero. Resume is not an inverse signal; only the
broker may start a new invocation after observing zero allocations. Linux
coturn uses `Restart=no`; this prevents coturn recovery from bypassing the agent's bounded three-attempt budget.
Windows native coturn and Docker also use restart policy no, and no WSL2 outer restart loop exists. The Linux
agent has bounded systemd start limits. Windows SCM recovery is crash-only and
finite: restart after 5 seconds, restart after 30 seconds, then none, with an
INFINITE reset period. Fatal policy/config exits stop normally and therefore do
not trigger crash recovery.

A fresh Linux install starts the control socket, firewall, and agent only. It
does not enable or start `mrd-coturn.service`. Initial enrollment supplies
secret version 1, after which the agent asks the broker to atomically apply the
secret and start coturn. The same broker owns all later restarts and drains.

## Linux installation

Prepare these absolute, canonical inputs:

- signed/reviewed `mrd-relay-agent` and `mrd-relay-coturn-control` binaries;
- an inline-secret-free agent JSON configuration;
- a 40–512 byte printable enrollment token file, root:root `0600`;
- a canonical 43-byte per-node TURN secret file, root:root `0600`;
- a root-owned, non-writable trusted backend CA bundle;
- a TLS certificate and root:root `0600` private key; and
- coturn 4.17.2 or newer with the required Prometheus build.

Before changing any managed file or service, the installer proves any existing
`mrd-relay` and `mrd-coturn` NSS identities from `getent passwd`, `shadow`, and
`group`. Each must have a nonzero UID inside the unambiguous
`SYS_UID_MIN..SYS_UID_MAX` range from root-owned `/etc/login.defs`, a locked
shadow password, `/usr/sbin/nologin`, home `/nonexistent`, a same-name private
primary group, no supplementary group, and no explicit group members. Newly
created identities are read back through the same check before use.

The installer rewrites the two agent credential paths to
`/run/credentials/mrd-relay-agent.service/enrollment-token` and
`/run/credentials/mrd-relay-agent.service/turn-rest-secret`, and rewrites the
trusted CA path to `/run/credentials/mrd-relay-agent.service/trusted-ca`. The
unit loads all three root-only sources with `LoadCredential`; `run --config`
receives only the absolute credential-backed config path.

Example for the default TLS port and nftables:

```bash
sudo ./linux/install-relay-node.sh \
  --agent-binary /root/release/mrd-relay-agent \
  --coturn-helper-binary /root/release/mrd-relay-coturn-control \
  --agent-config /root/bootstrap/agent.json \
  --enrollment-token-file /root/bootstrap/enrollment-token \
  --turn-secret-file /root/bootstrap/turn-rest-secret \
  --trusted-ca /root/bootstrap/backend-ca.pem \
  --tls-cert /root/bootstrap/fullchain.pem \
  --tls-key /root/bootstrap/privkey.pem \
  --realm relay.example.net \
  --server-name relay-hkg-1.example.net \
  --external-ip 198.20.0.10/10.0.0.10 \
  --relay-ip 10.0.0.10 \
  --firewall-backend nftables
```

Use `--firewall-backend firewalld --firewalld-zone public` or
`--firewall-backend ufw` only when that backend is active. Add
`--tls-port 443` only after reserving 443 for this node.

The installer rejects symlink ancestors, unsafe existing destinations,
duplicate or unknown coturn directives, active `CHANGE_ME` values, inline
secrets, `no-auth`, loopback-peer allowances, mismatched TLS keys, insecure
secret source modes, quota/range mismatches, and bit/byte rounding.
Linux and Windows exercise the same versioned vectors in
`public-ip-test-vectors.json`. The classifier rejects IANA non-global space,
IPv4-mapped/compatible literals, 6to4, documentation ranges, and local-use
NAT64; the well-known NAT64 prefix is accepted only when its embedded IPv4 is
global. The listed IETF IPv6 anycast/AMT/AS112/ORCHID exceptions remain global.
For `external-ip PUBLIC[/PRIVATE]`, PUBLIC, PRIVATE, and a nonempty `relay-ip`
must use one address family. When PRIVATE is present, `relay-ip` is mandatory
and must be the exact same literal (including IPv6 spelling); without PRIVATE,
`relay-ip` may differ but must remain in PUBLIC's address family.
The rendered listener is single-stack and bound to PUBLIC's family:
`listening-ip=0.0.0.0` for IPv4 and `listening-ip=::` for IPv6. An endpoint that
is an IP literal must use that family; a DNS endpoint is not resolved or assumed
to have either family locally, and its public behavior remains a Task 11 gate.

Run the pure parser/evidence negative checks without touching services:

```bash
./linux/verify-relay-node.sh --self-test
```

The live verification uses a transient systemd credential sandbox as
mrd-relay. It first executes `validate`, then the read-only broker `preflight`;
it never starts a second agent run loop and never writes identity, runtime, or
sequence state.

The installer's Linux upgrade verification never calls that live allocation
preflight after coturn is stopped. It calls `verify-relay-node.sh --drained`
with the authenticated fence values captured before mutation. That path still
proves the broker/socket is serving a fresh challenge and reports exactly zero
allocations; coturn inactivity by itself is never considered evidence.

Uninstall is recoverable and drain-gated:

```bash
sudo ./linux/uninstall-relay-node.sh
```

It performs the same two-proof fence, then stops the exact
agent/socket/coturn/firewall units and moves exact files and state into a
root-only recovery directory. It never recursively deletes secrets; coturn is
stopped only after the broker-authenticated zero-allocation fence.
If stopping an originally active agent succeeds but the second proof or exact
fence comparison fails, the uninstaller restores that agent before exiting;
the socket and coturn have not yet been touched in this early failure window.
An alternate `--archive-root` is canonicalized and rejected before the first
drain proof if it equals, contains, or is contained by any managed source root;
this prevents self-archiving paths such as `/etc/mrd-relay-agent/removals`.

## Windows installation targets

`windows/install-relay-node.ps1` supports Native, Docker, and WSL2. It installs
two services: restricted LocalService `mrd-relay-agent` and restricted
LocalSystem `mrd-relay-coturn-control`. The broker owns the named pipe
`\\.\pipe\mrd-relay-coturn-control`; its ACL permits only SYSTEM,
Administrators, and `NT SERVICE\mrd-relay-agent`, and it checks the connecting
client token twice. The agent never invokes a target manager directly.

Install and uninstall serialize on the same fixed machine-level lock beneath
the OS-resolved CommonApplicationData `MRD` boundary. The lock path is never
derived from caller-supplied install, data, recovery, or `ProgramData` values;
its exact content, owner, DACL, and non-reparse ancestry are verified before an
exclusive no-sharing handle is held. After `ShouldProcess` approves the
operation, that lock is acquired before existing-install classification,
recovery-WAL discovery, drain proofs, snapshots, or service mutation and is
held through commit or rollback. A declined operation and `-WhatIf` make no
filesystem changes.

All input executables require absolute safe paths, a matching SHA-256, and a
valid Authenticode signature. UNC, device, ADS, and reparse paths fail closed.
The installer also requires an explicitly hashed and signed OpenSSL executable;
before any service or data-root mutation it rejects a leaf certificate expiring
within 24 hours, an encrypted/unreadable private key, or a certificate/private
key public-key mismatch.
The installer receives enrollment and TURN material only through protected
source file paths. It creates the restricted services first, resolves their
numeric service SIDs, writes the exact current `ProductionAgentConfigWire` and
target contract under `C:\ProgramData\MRD\RelayAgent`, and streams each source
file byte-for-byte to the signed agent's closed
`provision-windows --config ABSOLUTE_PATH --purpose enrollment|turn` command.
PowerShell never implements the DPAPI envelope and never puts plaintext in argv
or environment variables. Verification checks the exact schema, paths, service
SIDs, metadata, and DACLs but never calls DPAPI Unprotect.
Immutable `agent.json` and the trusted CA are controlled by SYSTEM and
Administrators; the agent service SID has read/execute only. Mutable agent and
broker bound stores use the corresponding exact service SID with Full Control.
The verifier checks protected DACLs, owners, and the managed ancestor chain.
Every managed ancestor rejects delete-child/delete, attribute writes, and
ACL/owner-changing allow ACEs for identities other than SYSTEM,
Administrators, or TrustedInstaller. On the drive root and `ProgramData`, the
only untrusted write exception is this-folder-only file/directory creation;
an OI/CI propagation flag makes that ACE invalid. `C:\ProgramData\MRD` is
created as a protected SYSTEM/Administrators boundary, and custom missing or
untrusted parents fail closed.

Target-specific contracts:

- Native requires a signed `VerifiedNativeDrainWrapper`; Native without a verified drain wrapper must fail closed.
  The exact native service has no automatic
  recovery and only the broker may control it.
- Docker pins
  `coturn/coturn:4.17.2@sha256:aa68aab64a3b929d57fc2924c98ea447bf996cf8dade2508e7b71eaf23f1f14e`,
  label `io.mrd.relay.managed=true`, read-only root and mounts, restart=no,
  exact port mappings, and loopback-only host metrics. Its complete immutable
  runtime specification is entrypoint `/usr/bin/turnserver`, arguments exactly
  `--config /run/mrd/turnserver.conf`, bridge networking, all capabilities
  dropped, `no-new-privileges:true`, user exactly `65534:65534`, empty PID and
  user namespaces, private IPC, no device mappings, `PublishAllPorts=false`,
  non-privileged execution, read-only root, and no extra labels, mounts,
  security options, or ports. ProgramData mount
  roots containing `,` or `=` are rejected to prevent `--mount` ambiguity.
  A fresh install atomically creates the read-only mount source as the exact
  secret-free disabled placeholder `# MRD broker placeholder v1; no TURN
  listener` followed by `no-udp`, `no-tcp`, `no-tls`, and `no-dtls`, using LF
  UTF-8 without BOM and an exact protected broker ACL. The broker verifies this
  fence before container creation and replaces it only after binding container
  identity. Upgrades treat an existing broker-owned envelope as opaque: the
  installer checks only its canonical path, reparse-free leaf, and exact ACL
  after the two-proof drain fence, and never reads or logs its secret content.
  The broker updates the
  read-only mounted envelope and performs exact inspect/restart/signal actions;
  it persists and rechecks the exact 64-hex container ID plus image ID before
  every action, and it does not assume systemd or a helper exists in the container.
- WSL2 requires a broker-owned `MRDRelay` distribution under LocalSystem,
  mirrored networking, systemd, `IPAccounting=yes`, and a live UDP/range
  probe. Per-user distributions, NAT mode, missing systemd/accounting, or
  incomplete relay-range parity are unsupported and return INFRA_FAIL. There
  is no external restart loop. This installer does not safely import such a
  distribution, so a fresh `-Target Wsl2` install fails closed and requires a
  separately authenticated, system-owned provisioning workflow. Same-target
  upgrades may use only an already verified installation. Uninstall invokes the
  manifest-bound, signed `wsl.exe --terminate MRDRelay`, verifies the distro is
  no longer running, and preserves it; it never unregisters the distro.

Every WSL2 install, upgrade, verification, and uninstall entrypoint requires
the caller token to be exactly LocalSystem (`S-1-5-18`); an elevated
administrator is not equivalent. Docker and WSL manager invocations use a
bounded process runner with timeout and output-byte limits. Docker output is
strict UTF-8; `wsl.exe` output is strict UTF-16LE with even-length and NUL
checks, including when no BOM is emitted.

Production host acceptance is performed in Docker or WSL2 mode unless the
Native verified drain boundary is independently qualified. Merely installing
a service is not acceptance.

Run portable verifier negative tests in Windows PowerShell 5.1 and pwsh 7:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\verify-relay-node.ps1 -SelfTest
pwsh -NoProfile -File .\windows\verify-relay-node.ps1 -SelfTest
```

Live verification selects the installed target and calls only:

```text
mrd-relay-agent.exe preflight --config ABSOLUTE_PATH --challenge HEX64
```

Windows uninstall also fails closed until drain is complete. It stops and
deletes only the exact SCM registrations, removes only the five exact firewall
rules, and moves Program Files and ProgramData trees intact into a recovery
archive. Before SCM deletion or root movement it stops and reads back the exact
Native service, bound Docker container, or WSL distribution; an unknown target
identity leaves the protected checkpoint intact. A protected atomic WAL records
the exact `qc`, `qfailure`, normalized `qfailureflag`, `qsidtype`, running state,
firewall state, each completed service deletion, and each root move. On any
failure it restores roots and firewall first, recreates/configures and reads
back exact SCM definitions (including a bounded marked-for-delete wait), then
restores running services in Native/broker/agent dependency order with a bounded
`START_PENDING` readback. On the next invocation, any unique incomplete WAL is
strictly ACL/schema/path/target bound and is rolled back before live state is
read or a new uninstall snapshot is taken; corrupt, ambiguous, or unbound WALs
fail closed. Docker containers
and WSL distributions remain stopped/preserved instead of being destroyed.
Upgrade and uninstall never accept a hand-written marker or merely a stopped
process as drain evidence. Before mutation they run the signed installed agent's
`drain-proof --config ABSOLUTE_PATH --challenge HEX64`; its single-line exact
JSON must be fresh-challenge bound, match the target/current nonzero generation
and secret version, and report `draining=true`, `active_allocations=0`, and
`drain_completed=true`. Unknown/unavailable allocation telemetry fails closed.
They then stop only the agent, repeat the proof with a new challenge, and fence
the same target/generation/version before the broker or target is stopped.

A same-target Windows upgrade preserves the bound identity, runtime, active
secret, broker control state/journal, and (for Docker) exact container identity
and read-only `docker-envelope`. Target switching and a changed coturn baseline
require an explicit migration/secret-rotation workflow and fail closed here.
The upgraded services remain drained: verification uses static gates plus
`drain-proof`, reports `relay_install_complete_drained`, and never attempts a
TURN allocation. Fresh installs alone run allocation preflight. Resuming
traffic is a later explicit broker action followed by live verification.

Every Windows install/upgrade creates a protected
`UPGRADE-RECOVERY.json` checkpoint before moving either managed root. It records
the exact old program/data backup paths, prior service existence/running state,
and the full five-rule firewall specification. If installation fails after the
checkpoint, the installer automatically keeps failed new roots as a separate
protected quarantine, restores the two exact backup directories with
`Move-Item -LiteralPath`, restores only recorded SCM/firewall/running state,
and leaves the recovery checkpoint intact. Before moving either root during
rollback it first stops and reads back the exact changed Native/Docker/WSL
target; failure to prove that stop aborts root movement and preserves the
checkpoint. Existing SCM definitions are captured before mutation with
wide-character base configuration plus bounded strict `qc`, `qfailure`,
`qfailureflag`, and `qsidtype` structural snapshots; rollback restores every
changed definition, reads it back exactly, and only then restores recorded
running states. The localized
`qfailureflag` label is ignored, while its canonical ASCII `TRUE`/`FALSE` value
is strictly normalized to `1`/`0` for checkpoint comparison and `sc failureflag`
replay; unknown values fail closed. Never recursively delete a failed
root or a recovery checkpoint.

SCM snapshot parsing preserves continuation-line dependencies emitted by
`sc.exe qc`, accepts only bounded legal dependency tokens, rejects control and
path-separator characters, and compares the complete ordered dependency set
after restore. `sc.exe` text remains a bounded structural cross-check only.
The authoritative binary path, service account, start type, delayed-auto flag,
and dependency `MULTI_SZ` come from the wide-character
`QueryServiceConfigW`/`QueryServiceConfig2W` APIs, so Windows PowerShell 5.1
code-page conversion cannot corrupt Unicode install paths, accounts, spaces,
`$`, group prefixes, or non-ASCII service names. Each
checkpoint phase is atomically replaced before the first
root move governed by that phase, so recovery never infers progress from a
partially moved directory tree.

Install, data, and recovery roots must be component-wise disjoint. Recovery
roots have an exact path-bound product marker and protected SYSTEM/Administrators
ACL; an existing unmarked or forged directory is never re-owned or modified.

## Acceptance semantics

Every local verifier creates a fresh CSPRNG 32-byte challenge and requires one
single-line JSON object with the exact frozen key set. It recomputes
`challenge_sha256`, rejects extra keys (especially secret or credential
fields), requires nonzero generation and applied secret version, checks the
target, and requires listener, credential, allocation, permission, and
bidirectional relayed packet evidence with positive packet/byte counters and a
relay/relay candidate pair. The broker proof binds the fresh challenge,
generation, secret version, target, and evidence, so a fixed-shape or replayed
response fails.

This evidence is explicitly `scope=local`; it proves listener, credential, allocation, permission, and bidirectional relay traffic.
It does not claim public readiness. Public UDP/TCP/TLS/SNI/relay-range testing belongs to Task 11, and missing public Task 11 evidence is INFRA_FAIL rather than a pass.
Port-open or process-running checks alone are never TURN acceptance.

## Regional bootstrap and disaster recovery

`regions.example.yaml` is versioned and contains node IDs, regions, failure
domains, endpoints, and capacity only. It contains no credentials. During
disaster recovery it can seed the control-plane database after operator review;
normal agents and backends do not watch or consume it. Update capacity in the
database and signed directory first, then keep the bootstrap file consistent
for the next recovery exercise.
