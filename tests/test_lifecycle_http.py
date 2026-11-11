"""Recorded HTTP trace over real workload TLS, including a lost cancellation reply."""

import asyncio
import http.server
import json
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from test_lifecycle import example

from kryvola_ml.sdk.client import Client, SubmissionUnavailable, canonical
from kryvola_ml.sdk.lifecycle import Lifecycle, State


class LifecycleHttpTests(unittest.TestCase):
    def test_resume_read_and_cancel_over_workload_tls(self):
        operation, item, scope = example()
        statuses = iter(
            [
                "COMPUTE_SELECTED",
                "EVIDENCE_PENDING",
                "RELEASED",
                "RELEASED",
                "RELEASED",
                "CANCELLED",
            ]
        )
        requests, cancels, grants = [], [], []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *_args):
                pass

            def reply(self, data, binary=False):
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.send_header(
                    "Content-Type", "application/octet-stream" if binary else "application/json"
                )
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)

            def record(self, body):
                assert self.connection.getpeercert()
                requests.append((self.command, self.path, body, self.headers["Authorization"]))

            def do_GET(self):
                self.record(b"")
                assert self.path.endswith(operation["operation_id"])
                self.reply(
                    canonical(
                        {
                            "schema_version": "1",
                            "operation": operation,
                            "public_status": next(statuses),
                        }
                    )
                )

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                self.record(body)
                if self.path == "/v1/operations/cancel":
                    cancels.append(body)
                    if len(cancels) == 2:
                        # Cancellation committed; the caller receives no acknowledgement.
                        self.connection.shutdown(socket.SHUT_RDWR)
                        self.connection.close()
                        return
                    outcome = "CANCELLATION_PENDING" if len(cancels) == 1 else "CANCELLED"
                    self.reply(
                        canonical(
                            {
                                "schema_version": "1",
                                "outcome": outcome,
                                **({"fence": "7"} if outcome == "CANCELLED" else {}),
                            }
                        )
                    )
                else:
                    assert json.loads(body) == scope
                    assert self.path in (
                        "/v1/released-outputs/manifest",
                        "/v1/released-outputs/parts/0",
                    )
                    self.reply(item.manifest if self.path.endswith("manifest") else item.data, True)

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
                    "subjectAltName=URI:spiffe://test/fabric",
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

            def credential(action, target):
                grants.append((action, canonical(target)))
                return f"{len(grants):064x}"

            with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
                server.socket = tls.wrap_socket(server.socket, server_side=True)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                client = Client(
                    "127.0.0.1", server.server_port, client_tls, "spiffe://test/fabric", credential
                )
                try:
                    run = Lifecycle(client, operation)
                    self.assertEqual(run.inspect().state, State.COMPUTE_SELECTED)
                    self.assertEqual(
                        asyncio.run(run.wait(timeout=2, poll_interval=0.001)).state, State.RELEASED
                    )
                    self.assertEqual(run.fetch(scope).ciphertext, item.data)
                    self.assertEqual(
                        Lifecycle(client, operation).fetch(scope).ciphertext, item.data
                    )
                    self.assertEqual(run.cancel("cancel-17").outcome, "CANCELLATION_PENDING")
                    with self.assertRaises(SubmissionUnavailable):
                        run.cancel("cancel-17")
                    self.assertEqual(
                        Lifecycle(client, operation).cancel("cancel-17").outcome, "CANCELLED"
                    )
                    self.assertEqual(run.inspect().state, State.CANCELLED)
                    self.assertEqual(cancels, [cancels[0]] * 3)
                    self.assertEqual(len(set(record[3] for record in requests)), len(requests))
                    for _method, _path, body, _token in requests:
                        self.assertNotIn(item.data, body)
                        self.assertNotIn(b"Bearer", body)
                    reads = [target for action, target in grants if action == "CONSUMER_READ"]
                    self.assertEqual(
                        reads,
                        [
                            canonical({"scope": scope, "part_index": index})
                            for index in (None, 0, None, 0)
                        ],
                    )
                finally:
                    server.shutdown()
                    thread.join()
