from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol
from urllib.error import URLError
from urllib.request import urlopen
import json
import subprocess
import threading


EXPECTED_SERVICE = "realtime-server"
EXPECTED_PROTOCOL_VERSION = 1


class ProcessHandle(Protocol):
    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def kill(self) -> None: ...


SpawnProcess = Callable[[list[str], Path], ProcessHandle]


@dataclass
class RealtimeStatus:
    running: bool
    reachable: bool
    status: str
    pid: int | None = None


def _spawn_process(command: list[str], cwd: Path) -> ProcessHandle:
    return subprocess.Popen(command, cwd=str(cwd))


class RealtimeSidecarManager:
    def __init__(
        self,
        *,
        health_url: str,
        command: list[str],
        workdir: str,
        spawner: SpawnProcess | None = None,
    ) -> None:
        self.health_url = health_url
        self.command = command
        self.workdir = Path(workdir)
        self.spawner = spawner or _spawn_process
        self._process: ProcessHandle | None = None
        self._lifecycle_lock = threading.RLock()

    def status(self) -> RealtimeStatus:
        with self._lifecycle_lock:
            process = self._process
            running = bool(process and process.poll() is None)
            reachable = False
            health_status = "unreachable"

            try:
                with urlopen(self.health_url, timeout=1.5) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                    if (
                        isinstance(payload, dict)
                        and payload.get("status") == "ok"
                        and payload.get("service") == EXPECTED_SERVICE
                        and payload.get("protocol_version") == EXPECTED_PROTOCOL_VERSION
                    ):
                        reachable = True
                        health_status = "ok"
                    else:
                        health_status = "unexpected-service"
            except (
                URLError,
                OSError,
                TimeoutError,
                json.JSONDecodeError,
                UnicodeDecodeError,
            ):
                reachable = False

            pid = getattr(process, "pid", None) if running else None
            return RealtimeStatus(
                running=running,
                reachable=reachable,
                status=health_status,
                pid=pid,
            )

    def start(self) -> RealtimeStatus:
        with self._lifecycle_lock:
            if self._process and self._process.poll() is None:
                return self.status()
            if not self.workdir.is_dir():
                raise RuntimeError(
                    f"realtime-server workdir does not exist: {self.workdir}"
                )

            self._process = self.spawner(self.command, self.workdir)
            return self.status()

    def stop(self) -> RealtimeStatus:
        with self._lifecycle_lock:
            if not self._process or self._process.poll() is not None:
                self._process = None
                return self.status()

            self._process.terminate()
            try:
                self._process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=3)

            self._process = None
            return self.status()

    def restart(self) -> RealtimeStatus:
        with self._lifecycle_lock:
            self.stop()
            return self.start()
