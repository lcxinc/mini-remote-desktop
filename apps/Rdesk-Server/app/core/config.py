from pydantic import SecretStr
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
    jwt_secret: SecretStr = SecretStr("")
    jwt_issuer: str = ""
    jwt_audience: str = ""
    jwt_expire_minutes: int = 60
    jwt_max_lifetime_minutes: int = 60 * 24
    jwt_future_iat_skew_seconds: int = 60
    device_enrollment_token_pepper: SecretStr = SecretStr("")
    device_enrollment_ttl_seconds: int = 300
    password_pbkdf2_iterations: int = 600_000
    bootstrap_admin_enabled: bool = False
    bootstrap_admin_username: str = ""
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: SecretStr = SecretStr("")
    signaling_ws_url: str = "ws://127.0.0.1:9532/ws"
    realtime_server_health_url: str = "http://127.0.0.1:9532/health"
    realtime_server_command: str = "cargo"
    realtime_server_args: str = "run -p realtime-server --manifest-path G:/Project/mini-remote-desktop/Cargo.toml"
    realtime_server_workdir: str = "G:/Project/mini-remote-desktop"
    cors_origins: str = "http://localhost:9531,http://127.0.0.1:9531"
    turn_urls: str = "turn:127.0.0.1:3478?transport=udp,turn:127.0.0.1:3478?transport=tcp,turns:127.0.0.1:5349?transport=tcp"
    turn_auth_secret: SecretStr = SecretStr("")
    turn_credential_ttl_seconds: int = 600
    legacy_turn_credentials_enabled: bool = False
    relay_directory_ttl_seconds: int = 30
    relay_directory_signing_key_id: str = ""
    relay_directory_signing_private_key: SecretStr = SecretStr("")
    relay_turn_secret_encryption_key: SecretStr = SecretStr("")
    relay_turn_secret_encryption_key_id: str = "active"
    session_grant_ttl_seconds: int = 600
    relay_policy_ttl_seconds: int = 600
    relay_policy_revision: int = 1
    relay_allowed_regions: str = ""
    relay_preferred_regions: str = ""
    relay_accepted_transports: str = "udp,tcp,tls"
    # Empty means fail closed: relay management traffic is accepted only from
    # explicit IP addresses/networks of the terminating mTLS proxy.
    trusted_mtls_proxy: str = ""
    relay_max_clock_skew_seconds: int = 30
    relay_enrollment_token_pepper: SecretStr = SecretStr("")
    relay_ca_certificate_pem: str = ""
    relay_ca_private_key_pem: SecretStr = SecretStr("")
    relay_ca_private_key_password: SecretStr = SecretStr("")
    relay_certificate_validity_seconds: int = 3600
    relay_enrollment_receipt_ttl_seconds: int = 86_400
    relay_certificate_renew_before_seconds: int = 86_400
    relay_previous_auth_grace_seconds: int = 300
    relay_renewal_record_retention_seconds: int = 86_400


settings = Settings()
