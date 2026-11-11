"""Public owner bindings and the authenticated local approval command."""

import importlib
import importlib.metadata
import json
import os
import re
import subprocess
from pathlib import Path

from .client import OwnerUnavailable, canonical


def installed_owner():
    """Create an opaque owner key from the separately qualified installed wheel."""
    try:
        if importlib.metadata.version("kryvola-owner") != "0.1.0.dev2":
            raise ValueError
        return importlib.import_module("kryvola_owner").OwnerKey()
    except Exception:
        raise OwnerUnavailable("OWNER_UNAVAILABLE") from None


class OwnerAgent:
    def __init__(self, binary: Path, root: Path, slot: str):
        if (
            not binary.is_absolute()
            or not root.is_absolute()
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", slot)
        ):
            raise OwnerUnavailable("OWNER_UNAVAILABLE")
        self.binary, self.root, self.slot = binary, root, slot

    def approve(self, plan: bytes, operation: dict) -> bytes:
        try:
            with (self.root / f"{self.slot}.approval-policy").open("rb") as stream:
                raw = stream.read(65537)
            if len(raw) > 65536:
                raise ValueError
            policy = json.loads(raw)
            with (self.root / f"{self.slot}.plan").open("rb") as stream:
                if stream.read(65537) != plan:
                    raise ValueError
            if any(
                policy["approval"][field] != operation[field]
                for field in ("tenant_scope", "operation_id", "workflow_epoch", "policy_digest")
            ):
                raise ValueError
            request = canonical(
                {"approval": policy["approval"], "assurance": "CONFIDENTIALITY_ONLY"}
            )
            signed = self._run("approve", request)
            self._run("verify-approval", signed)
            return signed
        except Exception:
            raise OwnerUnavailable("OWNER_UNAVAILABLE") from None

    def _run(self, action: str, data: bytes) -> bytes:
        env = {key: os.environ[key] for key in ("DBUS_SESSION_BUS_ADDRESS",) if key in os.environ}
        process = subprocess.Popen(
            [
                "/usr/bin/timeout",
                "--kill-after=2s",
                "15s",
                str(self.binary),
                action,
                str(self.root),
                self.slot,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
        )
        try:
            assert process.stdin is not None and process.stdout is not None
            process.stdin.write(data)
            process.stdin.close()
            output = process.stdout.read(65537)
            if len(output) > 65536 or process.wait(timeout=20) != 0:
                raise ValueError
            return output
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
