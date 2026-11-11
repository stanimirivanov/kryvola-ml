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


class ResultOpener:
    """Adapt the owner agent's same-UID Unix-stream opening protocol."""

    def __init__(self, binary: Path, root: Path, python: Path, slot: str, credential):
        self.agent = OwnerAgent(binary, root, slot)
        if not python.is_absolute():
            raise OwnerUnavailable("OWNER_UNAVAILABLE")
        self.python, self.credential = python, credential

    def open_result(self, output) -> bytes:
        import secrets
        import socket
        import stat

        from .submission import PAIR_MAX, checked, commitment

        process = None
        directory = None
        try:
            scope = checked("ReadReleasedOutputRequest", json.loads(output.scope))
            if (
                not 0 < len(output.ciphertext) <= PAIR_MAX
                or len(output.manifest) > 65536
                or commitment("manifest", 2, output.manifest) != scope["output_manifest_digest"]
            ):
                raise ValueError
            manifest = checked("ManifestV2", json.loads(output.manifest))
            if commitment("blob", 1, output.ciphertext) != manifest["full_blob_digest"]:
                raise ValueError
            root = self.agent.root
            if root.resolve() != root:
                raise ValueError
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            meta = os.fstat(directory)
            if meta.st_uid != os.geteuid() or stat.S_IMODE(meta.st_mode) != 0o700:
                raise ValueError

            def read(suffix, maximum):
                descriptor = os.open(
                    f"{self.agent.slot}.{suffix}",
                    os.O_RDONLY | os.O_NOFOLLOW,
                    dir_fd=directory,
                )
                with os.fdopen(descriptor, "rb") as stream:
                    meta = os.fstat(stream.fileno())
                    if (
                        not stat.S_ISREG(meta.st_mode)
                        or meta.st_uid != os.geteuid()
                        or meta.st_mode & 0o077
                        or meta.st_nlink != 1
                    ):
                        raise ValueError
                    raw = stream.read(maximum + 1)
                    if len(raw) > maximum:
                        raise ValueError
                    return raw

            release = checked("ReleaseAuthorizationV3", json.loads(read("release", 65536)))
            identity = {
                "schema_version": "1",
                **{
                    key: release[key]
                    for key in (
                        "tenant_scope",
                        "logical_job_id",
                        "output_stage",
                        "recipient",
                        "disclosure_index",
                    )
                },
            }
            if (
                any(
                    release[key] != scope[key]
                    for key in (
                        "tenant_scope",
                        "recipient",
                        "output_manifest_digest",
                    )
                )
                or commitment("disclosure-identity", 3, canonical(identity))
                != scope["disclosure_id"]
            ):
                raise ValueError
            # Publish complete owner-only ciphertext without replacing custody documents.
            temporary = f".{self.agent.slot}.{secrets.token_hex(16)}.ciphertext"
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(output.ciphertext)
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    os.link(
                        temporary,
                        f"{self.agent.slot}.ciphertext",
                        src_dir_fd=directory,
                        dst_dir_fd=directory,
                        follow_symlinks=False,
                    )
                    os.fsync(directory)
                except FileExistsError:
                    if read("ciphertext", PAIR_MAX) != output.ciphertext:
                        raise ValueError from None
            finally:
                os.unlink(temporary, dir_fd=directory)
            token = self.credential(json.loads(output.scope))
            if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
                raise ValueError
            env = {
                key: os.environ[key] for key in ("DBUS_SESSION_BUS_ADDRESS",) if key in os.environ
            }
            caller, child = socket.socketpair()
            with caller, child:
                caller.settimeout(80)
                process = subprocess.Popen(
                    [
                        "/usr/bin/timeout",
                        "--kill-after=2s",
                        "75s",
                        str(self.agent.binary),
                        "open-result",
                        str(root),
                        str(self.python),
                        self.agent.slot,
                    ],
                    stdin=child.fileno(),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=env,
                )
                child.close()
                caller.sendall(token.encode())
                caller.shutdown(socket.SHUT_WR)
                result = bytearray()
                while len(result) < 3:
                    part = caller.recv(3 - len(result))
                    if not part:
                        break
                    result.extend(part)
                if process.wait(timeout=5) != 0 or len(result) != 2:
                    raise ValueError
                return bytes(result)
        except Exception:
            raise OwnerUnavailable("OWNER_UNAVAILABLE") from None
        finally:
            if directory is not None:
                os.close(directory)
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
