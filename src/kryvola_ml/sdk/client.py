"""Bounded workload TLS requests over the published Fabric API."""

import http.client
import json
import re
import ssl
from collections.abc import Callable
from typing import Any


class SubmissionError(Exception):
    """A fixed SDK failure code without request or transport diagnostics."""


class SubmissionUnavailable(SubmissionError):
    pass


class RateLimited(SubmissionError):
    pass


class OwnerUnavailable(SubmissionError):
    pass


class UnsupportedAssurance(SubmissionError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class Client:
    def __init__(
        self,
        host: str,
        port: int,
        tls: ssl.SSLContext,
        server_spiffe_id: str,
        credential: Callable[[str, dict], str],
    ):
        if tls.verify_mode != ssl.CERT_REQUIRED or not server_spiffe_id.startswith("spiffe://"):
            raise SubmissionError("SUBMISSION_REJECTED")
        self.host, self.port, self.tls = host, port, tls
        self.peer, self.credential = server_spiffe_id, credential

    def request(self, method: str, path: str, body: bytes, action: str, target: dict) -> bytes:
        return self._request(method, path, body, action, target)

    def read_output(self, scope: dict, part_index: int | None = None) -> bytes:
        from .submission import checked

        scope = checked("ReadReleasedOutputRequest", scope)
        if part_index is not None and (type(part_index) is not int or not 0 <= part_index < 1024):
            raise SubmissionError("SUBMISSION_REJECTED")
        suffix = "manifest" if part_index is None else f"parts/{part_index}"
        return self._request(
            "POST",
            f"/v1/released-outputs/{suffix}",
            canonical(scope),
            "CONSUMER_READ",
            {"scope": scope, "part_index": part_index},
            binary_limit=65536 if part_index is None else 4194304,
        )

    def _request(
        self,
        method: str,
        path: str,
        body: bytes,
        action: str,
        target: dict,
        *,
        binary_limit: int | None = None,
    ) -> bytes:
        connection = http.client.HTTPSConnection(self.host, self.port, context=self.tls, timeout=5)
        try:
            token = self.credential(action, json.loads(canonical(target)))
            if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
                raise SubmissionError("SUBMISSION_REJECTED")
            connection.connect()
            cert = connection.sock.getpeercert() if connection.sock else None
            names = cert.get("subjectAltName", ()) if cert else ()
            if not isinstance(names, tuple) or [item for item in names if item[0] == "URI"] != [
                ("URI", self.peer)
            ]:
                raise SubmissionError("SUBMISSION_REJECTED")
            connection.request(
                method,
                path,
                body,
                {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": (
                        "application/octet-stream" if method == "PUT" else "application/json"
                    ),
                },
            )
            response = connection.getresponse()
            if response.status == 429:
                raise RateLimited("RATE_LIMITED")
            if response.status >= 500:
                raise SubmissionUnavailable("SUBMISSION_UNAVAILABLE")
            expected = 204 if method == "PUT" else 201 if path == "/v1/input-uploads" else 200
            if response.status != expected:
                raise SubmissionError("SUBMISSION_REJECTED")
            limit = binary_limit if binary_limit is not None else 65536
            if binary_limit is not None:
                length = response.getheader("Content-Length")
                if (
                    not length
                    or not re.fullmatch(r"0|[1-9][0-9]{0,7}", length)
                    or int(length) > limit
                    or response.getheader("Content-Type") != "application/octet-stream"
                    or response.getheader("Cache-Control") != "no-store"
                    or response.getheader("Content-Encoding") is not None
                    or response.getheader("Transfer-Encoding") is not None
                ):
                    raise SubmissionError("SUBMISSION_REJECTED")
            data = response.read(limit + 1)
            if len(data) > limit or (response.status == 204 and data):
                raise SubmissionError("SUBMISSION_REJECTED")
            if binary_limit is not None and len(data) != int(length):
                raise SubmissionError("SUBMISSION_REJECTED")
            return data
        except SubmissionError:
            raise
        except OSError, http.client.HTTPException:
            raise SubmissionUnavailable("SUBMISSION_UNAVAILABLE") from None
        except Exception:
            raise SubmissionError("SUBMISSION_REJECTED") from None
        finally:
            connection.close()
