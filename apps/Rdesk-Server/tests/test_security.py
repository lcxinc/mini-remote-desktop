from unittest import TestCase
from unittest.mock import patch

import jwt

from app.core.config import settings
from app.core.security import create_access_token


class SecurityTests(TestCase):
    def test_access_token_roundtrip_with_pyjwt(self) -> None:
        secret = "vY7!qP2@kL9#sX4$mR8%tN6&wC3*eH5-zB1+uD0="
        issuer = "https://auth.rdesk.test"
        audience = "rdesk-api"
        with patch.dict(
            settings.__dict__,
            {
                "jwt_secret": secret,
                "jwt_issuer": issuer,
                "jwt_audience": audience,
                "jwt_max_lifetime_minutes": 60,
                "jwt_future_iat_skew_seconds": 60,
            },
        ):
            token = create_access_token("device-user", "tester", "user")

        payload = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            issuer=issuer,
            audience=audience,
        )

        self.assertEqual(payload["sub"], "device-user")
        self.assertEqual(payload["username"], "tester")
        self.assertEqual(payload["role"], "user")
