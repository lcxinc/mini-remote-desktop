# Rdesk-Server

FastAPI management server for Rdesk devices and session requests.

Current product path: `apps/Rdesk-Server`

## Quick Start

1. Create PostgreSQL database:

```sql
CREATE DATABASE rdesk_server;
```

2. Install runtime dependencies:

```powershell
cd G:\Project\mini-remote-desktop\apps\Rdesk-Server
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

3. Configure environment:

```powershell
Copy-Item .env.example .env
```

4. Run server:

```powershell
python -m app.main
```

Relay node endpoints require a dedicated mTLS-terminating proxy listed in
`RDESK_TRUSTED_MTLS_PROXY`. Keep Uvicorn proxy-header rewriting disabled
(`--no-proxy-headers` when not using `python -m app.main`) and configure the
terminator to strip every client-supplied `Forwarded`, `X-Forwarded-*`, and
relay authentication header before adding its verified metadata.

## Tests

Install the development dependency set when running backend tests. It includes
the runtime requirements plus FastAPI/Starlette `TestClient` support.

```powershell
cd G:\Project\mini-remote-desktop\apps\Rdesk-Server
pip install -r requirements-dev.txt
python -m unittest discover -s tests
```

## API

- `POST /api/v1/auth/login`
- `GET /api/v1/devices`
- `GET /api/v1/devices/{id}`
- `POST /api/v1/sessions/request`
