from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


_DEV_DB_URL = "postgresql+asyncpg://postgres@127.0.0.1:5432/rdesk_server"
_DEV_JWT_SECRET = "development-only-secret-change-before-production"
_EXAMPLE_DB_URL = "postgresql+asyncpg://rdesk:replace-me@127.0.0.1:5432/rdesk_server"
_EXAMPLE_JWT_SECRET = "replace-with-at-least-32-random-bytes"


def _repository_root() -> str:
    return str(Path(__file__).resolve().parents[4])


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="RDESK_",
        extra="ignore",
    )

    environment: Literal["development", "test", "production"] = "development"
    server_host: str = "127.0.0.1"
    server_port: int = 9530
    db_url: str = _DEV_DB_URL
    # Keep the JWT secret a string for compatibility with PyJWT consumers;
    # security-sensitive logging paths never expose its value.
    jwt_secret: str = ""
    jwt_issuer: str = ""
    jwt_audience: str = ""
    jwt_expire_minutes: int = 60
    jwt_max_lifetime_minutes: int = 60 * 24
    jwt_future_iat_skew_seconds: int = 60
    device_jwt_audience: str = ""
    device_jwt_expire_minutes: int = 60
    device_enrollment_token_pepper: SecretStr = SecretStr("")
    device_serial_pepper: SecretStr = SecretStr("")
    device_enrollment_ttl_seconds: int = 300
    password_pbkdf2_iterations: int = 600_000
    bootstrap_admin_enabled: bool = False
    bootstrap_admin_username: str = ""
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: SecretStr = SecretStr("")
    signaling_ws_url: str = "ws://127.0.0.1:9542/ws"
    realtime_server_health_url: str = "http://127.0.0.1:9542/health"
    realtime_server_command: str = "cargo"
    realtime_server_args: str = "run -p realtime-server"
    realtime_server_workdir: str = Field(default_factory=_repository_root)
    cors_origins: str = "http://localhost:9531,http://127.0.0.1:9531"
    turn_urls: str = "turn:127.0.0.1:3478?transport=udp,turn:127.0.0.1:3478?transport=tcp,turns:127.0.0.1:5349?transport=tcp"
    turn_auth_secret: SecretStr = SecretStr("")
    turn_credential_ttl_seconds: int = 600
    development_reload: bool = False
    initial_admin_username: str | None = None
    initial_admin_email: str | None = None
    initial_admin_password: str | None = None
    seed_demo_data: bool = False
    legacy_turn_credentials_enabled: bool = False
    relay_directory_ttl_seconds: int = 30
    relay_directory_signing_key_id: str = ""
    relay_directory_signing_private_key: SecretStr = SecretStr("")
    relay_turn_secret_encryption_key: SecretStr = SecretStr("")
    relay_turn_secret_encryption_key_id: str = "active"
    relay_turn_secret_encryption_read_keys: SecretStr = SecretStr("{}")
    relay_turn_secret_encryption_legacy_key_id: str = ""
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

    @model_validator(mode="after")
    def validate_security_boundary(self) -> "Settings":
        admin_fields = (
            self.initial_admin_username,
            self.initial_admin_email,
            self.initial_admin_password,
        )
        if any(admin_fields) and not all(admin_fields):
            raise ValueError(
                "RDESK_INITIAL_ADMIN_USERNAME, RDESK_INITIAL_ADMIN_EMAIL, and "
                "RDESK_INITIAL_ADMIN_PASSWORD must be configured together"
            )
        if self.initial_admin_password and len(self.initial_admin_password) < 12:
            raise ValueError("RDESK_INITIAL_ADMIN_PASSWORD must contain at least 12 characters")

        if self.environment == "production":
            if self.db_url in {"", _DEV_DB_URL, _EXAMPLE_DB_URL}:
                raise ValueError("RDESK_DB_URL must be configured for production")
            if self.jwt_secret in {"", _DEV_JWT_SECRET, _EXAMPLE_JWT_SECRET} or len(
                self.jwt_secret.encode("utf-8")
            ) < 32:
                raise ValueError(
                    "RDESK_JWT_SECRET must be a production-specific secret of at least 32 bytes"
                )

        return self


settings = Settings()
