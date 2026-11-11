import json
import unittest

from test_submission import prepared_fixture

from kryvola_ml.sdk.client import (
    SubmissionError,
    SubmissionUnavailable,
    UnsupportedAssurance,
    canonical,
)
from kryvola_ml.sdk.lifecycle import Lifecycle, State
from kryvola_ml.sdk.submission import commitment


def example():
    _, prepared = prepared_fixture()
    operation = json.loads(prepared.admission)["operation"]
    item = prepared.artifacts[1]
    scope = {
        "schema_version": "1",
        "tenant_scope": operation["tenant_scope"],
        "recipient": operation["disclosure_identity"]["recipient"],
        "disclosure_id": commitment(
            "disclosure-identity", 3, canonical(operation["disclosure_identity"])
        ),
        "output_manifest_digest": commitment("manifest", 2, item.manifest),
    }
    return operation, item, scope


class RecordedTransport:
    def __init__(self, operation, item, states):
        self.operation, self.item, self.states = operation, item, iter(states)
        self.requests, self.reads = [], []
        self.cancellations = iter(["CANCELLATION_PENDING", "CANCELLED"])

    def request(self, method, path, body, action, target):
        self.requests.append((method, path, body, action, canonical(target)))
        if action == "CANCEL_OPERATION":
            outcome = next(self.cancellations)
            return canonical(
                {
                    "schema_version": "1",
                    "outcome": outcome,
                    **({"fence": "7"} if outcome == "CANCELLED" else {}),
                }
            )
        state = next(self.states)
        if isinstance(state, Exception):
            raise state
        return canonical(
            {"schema_version": "1", "operation": self.operation, "public_status": state}
        )

    def read_output(self, scope, part_index=None):
        self.reads.append((canonical(scope), part_index))
        return self.item.manifest if part_index is None else self.item.data


class LifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_resume_wait_preserves_all_observed_states_and_identity(self):
        operation, item, _ = example()
        trace = RecordedTransport(
            operation,
            item,
            [
                None,
                "COMPUTE_SELECTED",
                "EVIDENCE_PENDING",
                "EVIDENCE_VERIFIED",
                SubmissionUnavailable("SUBMISSION_UNAVAILABLE"),
                "RELEASED",
            ],
        )
        run = Lifecycle(trace, operation)
        observed = [run.inspect().state for _ in range(4)]
        self.assertEqual(
            observed,
            [
                State.RUNNING,
                State.COMPUTE_SELECTED,
                State.EVIDENCE_PENDING,
                State.EVIDENCE_VERIFIED,
            ],
        )
        resumed = Lifecycle(trace, operation)
        self.assertEqual((await resumed.wait(timeout=1, poll_interval=0.001)).state, State.RELEASED)
        self.assertEqual(len({entry[4] for entry in trace.requests}), 1)
        self.assertTrue(all(entry[2] == b"" for entry in trace.requests))
        self.assertEqual(trace.reads, [])

    async def test_cancellation_pending_is_not_terminal_and_retries_same_key(self):
        operation, item, _ = example()
        trace = RecordedTransport(operation, item, ["COMPUTE_SELECTED", "CANCELLED"])
        run = Lifecycle(trace, operation)
        pending = run.cancel("cancel-17")
        self.assertEqual(pending.outcome, "CANCELLATION_PENDING")
        self.assertIsNone(pending.fence)
        self.assertFalse(run.inspect().terminal)
        committed = Lifecycle(trace, operation).cancel("cancel-17")
        self.assertEqual(committed.outcome, "CANCELLED")
        self.assertEqual(committed.fence, "7")
        self.assertEqual((await run.wait(timeout=1)).state, State.CANCELLED)
        cancels = [entry for entry in trace.requests if entry[3] == "CANCEL_OPERATION"]
        self.assertEqual(cancels[0], cancels[1])
        with self.assertRaises(SubmissionError):
            run.cancel("different-key")

    async def test_wait_timeout_and_unsupported_proof_do_not_mutate_operation(self):
        operation, item, _ = example()
        with self.assertRaises(UnsupportedAssurance):
            Lifecycle(RecordedTransport(operation, item, []), operation, assurance="PROVEN")
        trace = RecordedTransport(operation, item, ["EVIDENCE_PENDING"] * 100)
        with self.assertRaises(TimeoutError):
            await Lifecycle(trace, operation).wait(timeout=0.01, poll_interval=0.002)
        self.assertTrue(all(entry[0] == "GET" for entry in trace.requests))
        for state in ("EVIDENCE_FAILED", "EXPIRED"):
            run = Lifecycle(RecordedTransport(operation, item, [state]), operation)
            self.assertTrue((await run.wait(timeout=1)).terminal)

    async def test_unreleased_or_wrong_scope_never_reads_or_opens(self):
        operation, item, scope = example()
        for state in (
            None,
            "COMPUTE_SELECTED",
            "EVIDENCE_PENDING",
            "EVIDENCE_VERIFIED",
            "CANCELLED",
            "EVIDENCE_FAILED",
            "EXPIRED",
        ):
            trace = RecordedTransport(operation, item, [state])
            with self.assertRaises(SubmissionError):
                Lifecycle(trace, operation).fetch(scope)
            self.assertEqual(trace.reads, [])

        for field in ("tenant_scope", "recipient", "disclosure_id"):
            trace = RecordedTransport(operation, item, ["RELEASED"])
            bad = {**scope, field: "f" * 64}
            with self.assertRaises(SubmissionError):
                Lifecycle(trace, operation).fetch(bad)
            self.assertEqual(trace.reads, [])

    async def test_changed_workflow_response_is_not_adopted_on_reconnect(self):
        operation, item, _ = example()
        trace = RecordedTransport({**operation, "workflow_epoch": "999"}, item, ["RELEASED"])
        with self.assertRaisesRegex(SubmissionError, "LIFECYCLE_REJECTED"):
            Lifecycle(trace, operation).inspect()
        self.assertEqual(trace.reads, [])

    async def test_fetch_repeats_exact_release_scope_and_rejects_tampered_bytes(self):
        operation, item, scope = example()
        trace = RecordedTransport(operation, item, ["RELEASED"] * 3)
        run = Lifecycle(trace, operation)
        first, second = run.fetch(scope), run.fetch(scope)
        self.assertEqual(first.ciphertext, item.data)
        self.assertEqual(first, second)
        self.assertEqual(trace.reads, [(canonical(scope), None), (canonical(scope), 0)] * 2)
        self.assertNotIn("encrypted pair", repr(first))
        trace.item = type(item)(item.manifest, b"tampered", item.reservation)
        with self.assertRaises(SubmissionError):
            run.fetch(scope)

    async def test_disconnected_owner_does_not_turn_release_into_plaintext(self):
        from pathlib import Path

        from kryvola_ml.sdk.client import OwnerUnavailable
        from kryvola_ml.sdk.owner import ResultOpener

        operation, item, scope = example()
        trace = RecordedTransport(operation, item, ["RELEASED"])
        opener = ResultOpener(
            Path("/missing/owner-agent"),
            Path("/missing/root"),
            Path("/missing/python"),
            "slot",
            lambda scope: "a" * 64,
        )
        with self.assertRaises(OwnerUnavailable):
            Lifecycle(trace, operation).open_result(scope, opener)


class BinaryClientTests(unittest.TestCase):
    def test_binary_response_has_strict_framing_and_bound(self):
        import ssl
        from unittest.mock import MagicMock, patch

        from kryvola_ml.sdk.client import Client

        _, _, scope = example()
        connection = MagicMock()
        connection.sock.getpeercert.return_value = {
            "subjectAltName": (("URI", "spiffe://test/fabric"),)
        }
        response = connection.getresponse.return_value
        response.status = 200
        headers = {
            "Content-Length": "3",
            "Content-Type": "application/octet-stream",
            "Cache-Control": "no-store",
        }
        response.getheader.side_effect = lambda name: headers.get(name)
        response.read.return_value = b"abc"
        client = Client(
            "test",
            443,
            ssl.create_default_context(),
            "spiffe://test/fabric",
            lambda action, target: "a" * 64,
        )
        with patch("http.client.HTTPSConnection", return_value=connection):
            self.assertEqual(client.read_output(scope, 0), b"abc")
            for name, value in (
                ("Content-Length", "4"),
                ("Content-Length", "4194305"),
                ("Content-Type", "text/html"),
                ("Cache-Control", "public"),
                ("Content-Encoding", "gzip"),
                ("Transfer-Encoding", "chunked"),
            ):
                changed = {**headers, name: value}
                response.getheader.side_effect = lambda name, headers=changed: headers.get(name)
                with self.assertRaises(SubmissionError):
                    client.read_output(scope, 0)


class OwnerProtocolTests(unittest.TestCase):
    def test_local_socket_opening_is_bound_and_repeated_without_replacing_files(self):
        import os
        import sys
        import tempfile
        from pathlib import Path

        from kryvola_ml.sdk.client import OwnerUnavailable
        from kryvola_ml.sdk.lifecycle import FetchedOutput
        from kryvola_ml.sdk.owner import ResultOpener

        operation, item, scope = example()
        output = FetchedOutput(canonical(scope), item.manifest, item.data)
        release = {
            **operation["disclosure_identity"],
            "schema_version": "3",
            "object_type": "release-authorization",
            "operation_id": operation["operation_id"],
            "execution_id": "execution-1",
            "assurance": "CONFIDENTIALITY_ONLY",
            **dict.fromkeys(
                (
                    "workflow_epoch",
                    "policy_epoch",
                    "session_epoch",
                    "attempt_epoch",
                    "fence",
                    "valid_from_unix_ms",
                    "expires_unix_ms",
                ),
                "1",
            ),
            **dict.fromkeys(
                (
                    "plan_digest",
                    "key_context_digest",
                    "policy_digest",
                    "consent_digest",
                    "model_digest",
                    "program_digest",
                    "evidence_policy_digest",
                    "approval_digest",
                    "receipt_digest",
                ),
                "0" * 64,
            ),
            "output_manifest_digest": scope["output_manifest_digest"],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "slot.release").write_bytes(canonical(release))
            (root / "slot.release").chmod(0o600)
            agent = root / "agent"
            # Controlled command fixture: assert kernel peer identity and private protocol.
            agent.write_text(
                f"#!{sys.executable}\n"
                + """import os, socket, struct, sys
assert sys.argv[1] == 'open-result'
s = socket.socket(fileno=0)
pid, uid, gid = struct.unpack('3i', s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
assert uid == os.geteuid()
data = b''
while True:
    part = s.recv(65)
    if not part: break
    data += part
assert data == b'a' * 64
s.sendall(bytes([16, 23]))
"""
            )
            agent.chmod(0o700)
            scopes = []

            def credential(request):
                scopes.append(canonical(request))
                return "a" * 64

            opener = ResultOpener(agent, root, Path(sys.executable), "slot", credential)
            self.assertEqual(opener.open_result(output), bytes([16, 23]))
            inode = (root / "slot.ciphertext").stat().st_ino
            self.assertEqual(opener.open_result(output), bytes([16, 23]))
            self.assertEqual((root / "slot.ciphertext").stat().st_ino, inode)
            self.assertEqual(scopes, [canonical(scope)] * 2)
            wrong = {**scope, "recipient": "wrong"}
            with self.assertRaises(OwnerUnavailable):
                opener.open_result(FetchedOutput(canonical(wrong), item.manifest, item.data))
            self.assertEqual(len(scopes), 2)
            agent.write_text(agent.read_text() + "s.sendall(b'x')\n")
            with self.assertRaises(OwnerUnavailable):
                opener.open_result(output)
            (root / "slot.ciphertext").unlink()
            os.symlink(root / "slot.release", root / "slot.ciphertext")
            with self.assertRaises(OwnerUnavailable):
                opener.open_result(output)
