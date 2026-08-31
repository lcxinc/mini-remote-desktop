import json
import re
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def _version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def _requirement_pin(package: str) -> str:
    requirements = (
        REPOSITORY_ROOT / "apps" / "Rdesk-Server" / "requirements.txt"
    ).read_text(encoding="utf-8")
    match = re.search(rf"(?m)^{re.escape(package)}==([^\s]+)$", requirements)
    assert match is not None, f"{package} must use an exact production pin"
    return match.group(1)


class DependencySecurityTests(unittest.TestCase):
    def test_backend_security_dependencies_stay_above_advisory_floors(self) -> None:
        self.assertGreaterEqual(
            _version_tuple(_requirement_pin("cryptography")), (50, 0, 0)
        )
        self.assertGreaterEqual(
            _version_tuple(_requirement_pin("python-multipart")), (0, 0, 31)
        )

    def test_backend_avoids_unmaintained_python_ecdsa_stack(self) -> None:
        requirements = (
            REPOSITORY_ROOT / "apps" / "Rdesk-Server" / "requirements.txt"
        ).read_text(encoding="utf-8")
        self.assertNotRegex(
            requirements,
            r"(?mi)^(?:python-jose(?:\[[^\]]+\])?|ecdsa)\s*[=<>~!]",
            "Use the production PyJWT/cryptography stack instead of python-jose/ecdsa",
        )

    def test_rdesk_postcss_override_stays_above_the_source_map_fix(self) -> None:
        workspace = (
            REPOSITORY_ROOT / "apps" / "Rdesk" / "pnpm-workspace.yaml"
        ).read_text(encoding="utf-8")
        match = re.search(r"(?m)^  postcss: ([^\s]+)$", workspace)
        self.assertIsNotNone(
            match, "Rdesk must override every transitive PostCSS copy"
        )
        assert match is not None
        self.assertGreaterEqual(_version_tuple(match.group(1)), (8, 5, 23))

    def test_historical_web_client_vite_stays_above_windows_path_fixes(self) -> None:
        package = json.loads(
            (REPOSITORY_ROOT / "junk" / "web-client" / "package.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertGreaterEqual(
            _version_tuple(package["devDependencies"]["vite"]), (8, 0, 16)
        )


if __name__ == "__main__":
    unittest.main()
