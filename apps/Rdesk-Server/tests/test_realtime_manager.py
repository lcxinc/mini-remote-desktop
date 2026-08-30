import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, BrokenBarrierError, Lock
from unittest.mock import MagicMock, patch

from app.services.realtime_manager import RealtimeSidecarManager


def _health_response(payload: bytes) -> MagicMock:
    response = MagicMock()
    response.read.return_value = payload
    context = MagicMock()
    context.__enter__.return_value = response
    context.__exit__.return_value = False
    return context


class RealtimeManagerTests(unittest.TestCase):
    def manager(self) -> RealtimeSidecarManager:
        return RealtimeSidecarManager(
            health_url="http://127.0.0.1:9542/health",
            command=["realtime-server"],
            workdir=".",
        )

    @patch("app.services.realtime_manager.urlopen")
    def test_accepts_expected_service_and_protocol(self, urlopen: MagicMock) -> None:
        urlopen.return_value = _health_response(
            b'{"status":"ok","service":"realtime-server","protocol_version":1}'
        )
        status = self.manager().status()
        self.assertTrue(status.reachable)
        self.assertEqual(status.status, "ok")

    @patch("app.services.realtime_manager.urlopen")
    def test_rejects_health_response_from_wrong_local_service(
        self, urlopen: MagicMock
    ) -> None:
        urlopen.return_value = _health_response(
            b'{"status":"ok","service":"mrd-service","protocol_version":1}'
        )
        status = self.manager().status()
        self.assertFalse(status.reachable)
        self.assertEqual(status.status, "unexpected-service")

    @patch("app.services.realtime_manager.urlopen")
    def test_rejects_incompatible_protocol_version(self, urlopen: MagicMock) -> None:
        urlopen.return_value = _health_response(
            b'{"status":"ok","service":"realtime-server","protocol_version":2}'
        )
        status = self.manager().status()
        self.assertFalse(status.reachable)
        self.assertEqual(status.status, "unexpected-service")

    @patch("app.services.realtime_manager.urlopen")
    def test_rejects_non_object_health_payload(self, urlopen: MagicMock) -> None:
        urlopen.return_value = _health_response(b"[]")
        status = self.manager().status()
        self.assertFalse(status.reachable)
        self.assertEqual(status.status, "unexpected-service")

    @patch("app.services.realtime_manager.urlopen")
    def test_concurrent_starts_spawn_at_most_one_process(
        self, urlopen: MagicMock
    ) -> None:
        urlopen.return_value = _health_response(
            b'{"status":"ok","service":"realtime-server","protocol_version":1}'
        )
        rendezvous = Barrier(2)
        calls: list[object] = []
        calls_lock = Lock()

        def spawn(_command: list[str], _cwd: Path):
            process = MagicMock()
            process.poll.return_value = None
            process.pid = 4200 + len(calls)
            with calls_lock:
                calls.append(process)
            try:
                rendezvous.wait(timeout=0.2)
            except BrokenBarrierError:
                pass
            return process

        manager = RealtimeSidecarManager(
            health_url="http://127.0.0.1:9542/health",
            command=["realtime-server"],
            workdir=".",
            spawner=spawn,
        )
        with ThreadPoolExecutor(max_workers=2) as executor:
            statuses = list(executor.map(lambda _: manager.start(), range(2)))

        self.assertEqual(len(calls), 1)
        self.assertTrue(all(status.running for status in statuses))


if __name__ == "__main__":
    unittest.main()
