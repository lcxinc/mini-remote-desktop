from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="RDESK_",
        extra="ignore",
    )

    server_host: str = "0.0.0.0"
    server_port: int = 9530
    db_url: str = "postgresql+asyncpg://postgres:519223@127.0.0.1:5432/rdesk_server"
    jwt_secret: str = "change_me_for_production"
    jwt_expire_minutes: int = 60 * 24 * 7
    signaling_ws_url: str = "ws://127.0.0.1:9532/ws"
    realtime_server_health_url: str = "http://127.0.0.1:9532/health"
    realtime_server_command: str = "cargo"
    realtime_server_args: str = "run -p realtime-server --manifest-path G:/Project/mini-remote-desktop/Cargo.toml"
    realtime_server_workdir: str = "G:/Project/mini-remote-desktop"
    cors_origins: str = "http://localhost:9531,http://127.0.0.1:9531"
    turn_urls: str = "turn:127.0.0.1:3478?transport=udp,turn:127.0.0.1:3478?transport=tcp,turns:127.0.0.1:5349?transport=tcp"
    turn_auth_secret: str = ""
    turn_credential_ttl_seconds: int = 600
    # Empty means fail closed: relay management traffic is accepted only from
    # explicit IP addresses/networks of the terminating mTLS proxy.
    trusted_mtls_proxy: str = ""
    relay_max_clock_skew_seconds: int = 30
    relay_enrollment_token_pepper: str = ""
    relay_ca_certificate_pem: str = ""
    relay_ca_private_key_pem: str = ""
    relay_certificate_validity_seconds: int = 3600


settings = Settings()
