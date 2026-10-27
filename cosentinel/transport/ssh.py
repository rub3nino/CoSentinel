"""Command execution — the single place that actually touches a machine.

Two runners, one interface:

  * LocalRunner  — runs on this laptop (used for "from outside" scanners like
    Nmap/Nuclei pointed at a target, and for a target that *is* localhost).
  * SSHRunner    — runs a command on a remote host by shelling out to the
    system `ssh`. This is deliberate: it reuses your ~/.ssh/config, your keys
    and your agent, adds no new dependency, and means Cosentinel never handles
    your private keys itself.

Isolating all execution here is what lets the rest of the codebase stay
pure/testable, and is the local-process equivalent of the "workers on a private
network" box in the hosted architecture.
"""

from __future__ import annotations

import shlex
import subprocess
import time
from dataclasses import dataclass


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class Runner:
    """Abstract execution target."""

    kind = "abstract"

    def describe(self) -> str:  # pragma: no cover - trivial
        return self.kind

    def run(self, argv: list[str], *, timeout: int = 600, sudo: bool = False) -> CommandResult:
        raise NotImplementedError

    def which(self, tool: str) -> bool:
        """Is a binary available where commands will run?"""
        res = self.run(["command", "-v", tool], timeout=20)
        return res.returncode == 0 and bool(res.stdout.strip())


class LocalRunner(Runner):
    kind = "local"

    def run(self, argv: list[str], *, timeout: int = 600, sudo: bool = False) -> CommandResult:
        cmd = (["sudo", "-n", *argv] if sudo else list(argv))
        return _exec(cmd, timeout)

    # `command -v` is a shell builtin; emulate it portably for the local case.
    def which(self, tool: str) -> bool:
        from shutil import which as _which
        return _which(tool) is not None


class SSHRunner(Runner):
    kind = "ssh"

    def __init__(
        self,
        host: str,
        *,
        user: str | None = None,
        port: int | None = None,
        connect_timeout: int = 10,
        extra_opts: list[str] | None = None,
    ):
        self.host = host
        self.user = user
        self.port = port
        self.connect_timeout = connect_timeout
        self.extra_opts = extra_opts or []

    def describe(self) -> str:
        who = f"{self.user}@" if self.user else ""
        return f"ssh:{who}{self.host}"

    def _ssh_prefix(self) -> list[str]:
        argv = [
            "ssh",
            "-o", "BatchMode=yes",                     # never prompt; fail fast
            "-o", f"ConnectTimeout={self.connect_timeout}",
            "-o", "StrictHostKeyChecking=accept-new",
        ]
        if self.port:
            argv += ["-p", str(self.port)]
        argv += list(self.extra_opts)
        argv.append(f"{self.user}@{self.host}" if self.user else self.host)
        return argv

    def run(self, argv: list[str], *, timeout: int = 600, sudo: bool = False) -> CommandResult:
        remote = list(argv)
        if sudo:
            remote = ["sudo", "-n", *remote]
        # Build a single, safely-quoted remote command string for ssh.
        remote_cmd = " ".join(shlex.quote(a) for a in remote)
        full = [*self._ssh_prefix(), "--", remote_cmd]
        res = _exec(full, timeout)
        # Preserve the *logical* command for audit/report readability.
        res.argv = argv
        return res


def _exec(cmd: list[str], timeout: int) -> CommandResult:
    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(
            argv=cmd,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration=round(time.monotonic() - start, 3),
        )
    except subprocess.TimeoutExpired as e:
        return CommandResult(
            argv=cmd,
            returncode=124,
            stdout=e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or ""),
            stderr=f"timed out after {timeout}s",
            duration=round(time.monotonic() - start, 3),
            timed_out=True,
        )
    except FileNotFoundError:
        return CommandResult(
            argv=cmd, returncode=127, stdout="", stderr=f"{cmd[0]}: not found",
            duration=round(time.monotonic() - start, 3),
        )
