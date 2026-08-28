# Rdesk-Server

FastAPI management server for Rdesk devices, sessions, and multi-region relay control.

## Quick start

1. Create a PostgreSQL database and a dedicated application user.
2. Create a virtual environment and install dependencies.

```bash
cd apps/Rdesk-Server
python -m venv .venv
# Linux/macOS: . .venv/bin/activate
# Windows PowerShell: .\\.venv\\Scripts\\Activate.ps1
python -m pip install -r requirements.txt
```

3. Copy `.env.example` to `.env`, then inject deployment-specific database,
   JWT, enrollment, and relay signing secrets. Production rejects checked-in
   development defaults.
4. Optionally configure all bootstrap variables for the first administrator;
   no built-in administrator credential is created.
5. Start the API.

```bash
python -m app.main
```

Development reload is opt-in through `RDESK_DEVELOPMENT_RELOAD=true`.

## Runtime topology

| Service | Default address | Purpose |
|---|---|---|
| Rdesk-Server | `127.0.0.1:9530` | Management API and relay directory |
| Rdesk web UI | `127.0.0.1:9531` | Local frontend development |
| realtime-server | `127.0.0.1:9542` | Signaling and service health |
| mrd-service Web Bridge | `127.0.0.1:9533` | Optional browser bridge |

Relay node endpoints require a dedicated mTLS-terminating proxy listed in
`RDESK_TRUSTED_MTLS_PROXY`. Keep Uvicorn proxy-header rewriting disabled
(`--no-proxy-headers` when not using `python -m app.main`) and configure the
terminator to strip every client-supplied `Forwarded`, `X-Forwarded-*`, and
relay authentication header before adding its verified metadata. Relay agents
can run on ordinary Linux or Windows hosts; their node credentials and
capacity/region heartbeats are stored in PostgreSQL.

## Tests

Install the development dependency set when running backend tests. It includes
runtime requirements plus asynchronous repository and TestClient support.

```bash
cd apps/Rdesk-Server
python -m pip install -r requirements-dev.txt
python -m pytest tests -q
```

The repository's cross-platform workflow also compiles the backend and runs
these tests on Linux, Windows, and macOS.

## API

- `POST /api/v1/auth/login`
- `GET /api/v1/devices`
- `GET /api/v1/devices/{id}`
- `POST /api/v1/sessions/request`
- Relay enrollment, heartbeat, directory, access, and migration endpoints under
  `/api/v1/relays`
