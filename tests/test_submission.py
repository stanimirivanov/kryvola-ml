import json
import unittest
from importlib.resources import files

from test_planner import descriptor

from kryvola_ml.sdk.submission import SubmissionError, prepare_submission


def fixture(name):
    return json.loads(files("kryvola_ml").joinpath("_spec/fixtures/" + name).read_bytes())


class SubmissionTests(unittest.TestCase):
    def test_unsupported_assurance_is_typed(self):
        from kryvola_ml.sdk.client import UnsupportedAssurance

        with self.assertRaisesRegex(UnsupportedAssurance, "UNSUPPORTED_ASSURANCE"):
            prepare_submission(None, None, {}, {}, {}, {}, assurance="PROVEN")

    def test_prepared_identity_does_not_depend_on_delivery(self):
        class Owner:
            calls = 0

            def evaluation_key(self):
                return b"public evaluation key"

            def encrypt_pair(self, values):
                self.calls += 1
                self.assertion = values
                return b"encrypted pair"

        owner = Owner()
        control = fixture("control.json")
        key = next(
            item["value"]
            for item in fixture("canonical-corpus.json")["objects"]
            if item["kind"] == "key-context"
        )
        key["evaluation_key_blob_digest"] = "0" * 64
        with self.assertRaisesRegex(SubmissionError, "SUBMISSION_REJECTED"):
            prepare_submission(
                owner,
                None,
                descriptor(),
                control["Operation"],
                key,
                fixture("fhe-q1-consent.json"),
                values=bytes([7, 9]),
            )
        self.assertEqual(owner.calls, 0)


def prepared_fixture():
    from base64 import urlsafe_b64encode

    from kryvola_ml.sdk.client import canonical
    from kryvola_ml.sdk.submission import commitment

    class Owner:
        encryptions = 0

        def evaluation_key(self):
            return b"public evaluation key"

        def encrypt_pair(self, values):
            self.encryptions += 1
            assert values == bytes([7, 9])
            return b"encrypted pair"

    owner = Owner()
    control = fixture("control.json")
    operation = control["Operation"]
    context = next(
        item["value"]
        for item in fixture("canonical-corpus.json")["objects"]
        if item["kind"] == "key-context"
    )
    context["tenant_scope"] = operation["tenant_scope"]
    context["native_codec_version"] = "tfhe-rs-1.8.1"
    context["parameters"]["parameter_set_digest"] = descriptor()["workload"]["parameter_set_digest"]
    context["evaluation_key_blob_digest"] = commitment("blob", 1, owner.evaluation_key())
    reference = operation["key_context_ref"]
    reference.update({key: context[key] for key in ("key_context_id", "key_epoch")})
    reference["key_context_digest"] = commitment("key-context", 1, canonical(context))

    def approve(plan, operation):
        plan = json.loads(plan)
        corpus = fixture("canonical-approval-receipt-v3.json")
        approval = next(item["value"] for item in corpus["objects"] if item["kind"] == "approval")
        for field in (
            "tenant_scope",
            "logical_job_id",
            "operation_id",
            "workflow_epoch",
            "policy_digest",
        ):
            approval[field] = operation[field]
        for field in ("recipient", "output_stage", "disclosure_index"):
            approval[field] = operation["disclosure_identity"][field]
        for field in (
            "model_digest",
            "program_digest",
            "key_context_digest",
            "consent_digest",
            "evidence_policy_digest",
        ):
            approval[field] = plan[field]
        approval.update(
            purpose="COMPUTE",
            subject_kind="plan",
            plan_digest=operation["plan_ref"]["plan_digest"],
            subject_digest=operation["plan_ref"]["plan_digest"],
        )
        # This controlled provider stands in for an independently authenticated owner agent.
        envelope = {
            "schema_version": "3",
            "algorithm": "Ed25519",
            "payload_kind": "approval",
            "payload_digest": commitment("approval", 3, canonical(approval)),
            "signer": "owner",
            "key_id": "test",
            "key_epoch": "1",
            "signature": urlsafe_b64encode(bytes(64)).rstrip(b"=").decode(),
        }
        return canonical(
            {"assurance": "CONFIDENTIALITY_ONLY", "approval": approval, "envelope": envelope}
        )

    prepared = prepare_submission(
        owner,
        approve,
        descriptor(),
        operation,
        context,
        fixture("fhe-q1-consent.json"),
        values=bytes([7, 9]),
    )
    return owner, prepared


class RecordedServerTests(unittest.TestCase):
    def test_lost_admission_response_preserves_encryption_and_identity(self):
        import http.server
        import socket
        import ssl
        import subprocess
        import tempfile
        import threading
        from pathlib import Path

        from kryvola_ml.sdk.client import Client, RateLimited, SubmissionUnavailable, canonical
        from kryvola_ml.sdk.submission import submit

        owner, prepared = prepared_fixture()
        calls, artifacts, reservations, admitted = [], {}, {}, []
        limited = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *_args):
                pass

            def do_PUT(self):
                self.handle_call()

            def do_POST(self):
                self.handle_call()

            def handle_call(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                calls.append((self.command, self.path, body))
                assert self.connection.getpeercert()
                assert self.headers["Authorization"] == "Bearer " + "a" * 64
                if limited:
                    self.send_response(429)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.command == "PUT":
                    assert artifacts.setdefault(self.path, body) == body
                    status, reply = 204, b""
                else:
                    value = json.loads(body)
                    if self.path == "/v1/key-contexts":
                        reply = value["key_context_ref"]
                    elif self.path == "/v1/input-uploads":
                        key = value["idempotency_key"]
                        upload = reservations.setdefault(key, f"{len(reservations) + 1:032x}")
                        reply = {"schema_version": "1", "upload_id": upload}
                    elif self.path.endswith("/finalize"):
                        reply = {"schema_version": "1", "manifest_digest": value["manifest_digest"]}
                    elif self.path == "/v1/compute-approvals":
                        reply = {"schema_version": "1", "approval_digest": value["approval_digest"]}
                    else:
                        assert self.path == "/v1/operations/admit"
                        admitted.append(body)
                        if len(admitted) == 1:
                            self.connection.shutdown(socket.SHUT_RDWR)
                            self.connection.close()
                            return
                        assert admitted[0] == body
                        reply = {
                            "schema_version": "1",
                            "operation": value["operation"],
                            "public_status": None,
                        }
                    status = 201 if self.path == "/v1/input-uploads" else 200
                    reply = canonical(reply)
                self.send_response(status)
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

        with tempfile.TemporaryDirectory() as directory:
            cert, key = (Path(directory) / name for name in ("cert.pem", "key.pem"))
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-nodes",
                    "-subj",
                    "/CN=fixture",
                    "-addext",
                    "subjectAltName=URI:spiffe://fixture.test/fabric",
                    "-days",
                    "1",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(cert, key)
            tls.load_verify_locations(cert)
            tls.verify_mode = ssl.CERT_REQUIRED
            client_tls = ssl.create_default_context(cafile=cert)
            client_tls.check_hostname = False
            client_tls.load_cert_chain(cert, key)
            with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
                server.socket = tls.wrap_socket(server.socket, server_side=True)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                scopes = []

                def credential(action, target):
                    scopes.append((action, canonical(target)))
                    return "a" * 64

                client = Client(
                    "127.0.0.1",
                    server.server_port,
                    client_tls,
                    "spiffe://fixture.test/fabric",
                    credential,
                )
                try:
                    wrong_peer = Client(
                        "127.0.0.1",
                        server.server_port,
                        client_tls,
                        "spiffe://fixture.test/untrusted",
                        credential,
                    )
                    with self.assertRaisesRegex(SubmissionError, "SUBMISSION_REJECTED"):
                        submit(wrong_peer, prepared)
                    self.assertEqual(calls, [])
                    with self.assertRaisesRegex(SubmissionUnavailable, "SUBMISSION_UNAVAILABLE"):
                        submit(client, prepared)
                    result = submit(client, prepared)
                    self.assertEqual(
                        result["operation"], json.loads(prepared.admission)["operation"]
                    )
                    self.assertEqual(len(reservations), 2)
                    self.assertEqual(owner.encryptions, 1)
                    self.assertEqual(admitted, [prepared.admission] * 2)
                    for method, _path, body in calls:
                        if method == "POST":
                            self.assertNotIn(b"encrypted pair", body)
                            self.assertNotIn(b"public evaluation key", body)
                        self.assertNotIn(b"Bearer", body)
                    limited.append(True)
                    with self.assertRaisesRegex(RateLimited, "RATE_LIMITED"):
                        submit(client, prepared)
                    self.assertEqual(owner.encryptions, 1)
                finally:
                    server.shutdown()
                    thread.join()


class PreparedSnapshotTests(unittest.TestCase):
    def test_changed_references_are_rejected_before_any_network_call(self):
        from dataclasses import replace

        from kryvola_ml.sdk.client import canonical
        from kryvola_ml.sdk.submission import submit

        owner, prepared = prepared_fixture()
        admission = json.loads(prepared.admission)
        admission["input_manifest_digests"] = ["f" * 64]
        calls = []

        class Transport:
            def request(self, method, path, body, action, target):
                calls.append((method, path, body, action, target))
                return b"{}"

        with self.assertRaisesRegex(SubmissionError, "SUBMISSION_REJECTED"):
            submit(Transport(), replace(prepared, admission=canonical(admission)))
        self.assertEqual(calls, [])
        self.assertEqual(owner.encryptions, 1)
        self.assertNotIn("encrypted pair", repr(prepared))
        self.assertNotIn("encrypted pair", repr(prepared.artifacts[1]))

    def test_unavailable_local_owner_agent_has_a_fixed_error(self):
        from pathlib import Path

        from kryvola_ml.sdk.client import OwnerUnavailable
        from kryvola_ml.sdk.owner import OwnerAgent

        with self.assertRaisesRegex(OwnerUnavailable, "OWNER_UNAVAILABLE"):
            OwnerAgent(Path("/missing/agent"), Path("/missing/owner"), "slot").approve(b"{}", {})
