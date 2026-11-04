"""Read-only dashboard boundary tests using synthetic service data."""

from copy import deepcopy
import unittest

from werkzeug.test import EnvironBuilder, run_wsgi_app

from ransomlab.dashboard import create_app


LAB_ID = "00000000-0000-4000-8000-000000000001"
TOKEN = "dashboard-test-token-0123456789abcdef0123456789abcdef"


class FakeService:
    def __init__(self):
        self.calls = []
        self.data = {
            "lab_id": LAB_ID,
            "name": "<script>alert('lab')</script>",
            "state": "prepared",
            "fixture_count": 2,
            "bytes_total": 8192,
            "created_at": "2026-11-04T10:00:00+00:00",
            "last_run": None,
            "recovery": None,
            "alerts": [],
            "events": [{"sequence": 1, "kind": "lab.created", "source": "core",
                        "severity": "info", "created_at": "2026-11-04T10:00:00+00:00",
                        "fixture_id": None, "details": {"count": 2}, "outcome": "success"}],
            "fixtures": [{"id": "fixture-001", "name": "sample_001.bin", "size": 4096,
                          "sha256": "a" * 64, "current_sha256": "a" * 64, "status": "unchanged"}],
            "machines": [{"name": "Windows lab", "role": "Execution", "status": "declared"}],
        }

    def list_labs(self):
        self.calls.append("list")
        return [deepcopy(self.data)]

    def status(self, lab_id):
        self.calls.append(("status", lab_id))
        return deepcopy(self.data)

    def report(self, lab_id):
        self.calls.append(("report", lab_id))
        return {"lab_id": lab_id, "summary": "Synthetic verified report"}


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.service = FakeService()
        self.app = create_app(self.service, access_token=TOKEN)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.auth = {"Authorization": f"Bearer {TOKEN}"}

    def test_locked_shell_does_not_query_or_disclose_service(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"local session.", response.data)
        self.assertNotIn(LAB_ID.encode(), response.data)
        self.assertEqual(self.service.calls, [])

    def test_api_requires_authentication(self):
        for route in ("/api/labs", f"/api/labs/{LAB_ID}/status", f"/api/labs/{LAB_ID}/report"):
            with self.subTest(route=route):
                response = self.client.get(route)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json["error"], "authentication_required")
        self.assertEqual(self.service.calls, [])

    def test_bearer_reads_shared_service(self):
        response = self.client.get(f"/api/labs/{LAB_ID}/status", headers=self.auth)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, self.service.data)
        self.assertEqual(self.service.calls, [("status", LAB_ID)])

    def test_session_exchange_sets_private_cookie_and_does_not_return_token(self):
        response = self.client.post("/session", headers=self.auth)
        self.assertEqual(response.status_code, 204)
        cookie = response.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertNotIn(TOKEN, cookie)
        self.assertNotIn(TOKEN.encode(), response.data)
        self.assertEqual(self.client.get("/api/labs").status_code, 200)
        self.assertEqual(self.client.get("/session", headers=self.auth).status_code, 405)

    def test_invalid_bearer_is_rejected(self):
        self.assertEqual(self.client.post("/session", headers={"Authorization": "Bearer wrong"}).status_code, 401)
        self.assertEqual(self.client.get("/api/labs").status_code, 401)

    def test_query_token_is_not_supported(self):
        response = self.client.get("/?token=" + TOKEN)
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(TOKEN.encode(), response.data)

    def test_host_origin_and_remote_client_are_checked(self):
        bad = [
            {"Host": "evil.example"},
            {"Origin": "https://evil.example"},
            {"Origin": "http://localhost:6666"},
            {"Sec-Fetch-Site": "cross-site"},
        ]
        for headers in bad:
            with self.subTest(headers=headers):
                # Bypass the test client's own cookie URL parser so malformed
                # Host headers reach the WSGI application boundary.
                response = self.app.test_client(use_cookies=False).get("/api/labs", headers=self.auth | headers)
                self.assertIn(response.status_code, (400, 403))
        response = self.client.get("/api/labs", headers=self.auth,
                                   environ_overrides={"REMOTE_ADDR": "192.0.2.10"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.service.calls, [])

    def test_malformed_authority_is_rejected_at_wsgi_boundary(self):
        builder = EnvironBuilder(path="/api/labs", headers=self.auth,
                                 environ_overrides={"HTTP_HOST": "evil@localhost", "REMOTE_ADDR": "127.0.0.1"})
        try:
            _body, status, _headers = run_wsgi_app(self.app, builder.get_environ(), buffered=True)
        finally:
            builder.close()
        self.assertTrue(status.startswith("400"))
        self.assertEqual(self.service.calls, [])

    def test_loopback_hosts_and_same_origin_are_accepted(self):
        for host in ("127.0.0.1:8765", "localhost", "[::1]:8765"):
            response = self.client.get("/api/labs", headers=self.auth | {"Host": host, "Origin": "http://" + host})
            self.assertEqual(response.status_code, 200)

    def test_templates_escape_untrusted_names(self):
        response = self.client.get(f"/labs/{LAB_ID}", headers=self.auth)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"<script>alert", response.data)
        self.assertIn(b"&lt;script&gt;", response.data)
        self.assertIn(b"sample_001.bin", response.data)
        self.assertIn(b"SHA-256", response.data)

    def test_response_security_headers(self):
        for route in ("/", "/static/dashboard.css", "/api/labs"):
            response = self.client.get(route, headers=self.auth)
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
            self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
            self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
            self.assertNotIn("unsafe-inline", response.headers["Content-Security-Policy"])
            response.close()

    def test_read_routes_have_no_mutation_methods(self):
        for route in ("/", f"/labs/{LAB_ID}", "/api/labs", f"/api/labs/{LAB_ID}/status"):
            with self.subTest(route=route):
                self.assertEqual(self.client.post(route, headers=self.auth).status_code, 405)

    def test_invalid_lab_id_never_reaches_service(self):
        for lab_id in ("not-a-uuid", "00000000000040008000000000000001"):
            response = self.client.get(f"/api/labs/{lab_id}/status", headers=self.auth)
            self.assertEqual(response.status_code, 400)
        self.assertEqual(self.service.calls, [])

    def test_unknown_query_fields_are_rejected(self):
        response = self.client.get("/api/labs?path=C:/", headers=self.auth)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.service.calls, [])

    def test_json_report_delegates_to_service(self):
        response = self.client.get(f"/api/labs/{LAB_ID}/report", headers=self.auth)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["summary"], "Synthetic verified report")
        self.assertEqual(self.service.calls, [("report", LAB_ID)])

    def test_recent_event_pagination_is_bounded(self):
        response = self.client.get(f"/api/labs/{LAB_ID}/events?limit=1&after=0", headers=self.auth)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["items"], self.service.data["events"])
        self.assertEqual(response.json["window"], "recent")
        self.assertEqual(response.json["last_sequence"], 1)
        for query in ("limit=0", "limit=201", "after=-1", "after=1.5", "limit=1&limit=2"):
            with self.subTest(query=query):
                self.assertEqual(self.client.get(f"/api/labs/{LAB_ID}/events?{query}", headers=self.auth).status_code, 400)

    def test_session_does_not_accept_uploaded_content(self):
        response = self.client.post("/session", headers=self.auth, data=b"unneeded content")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.client.get("/api/labs").status_code, 401)

    def test_service_errors_do_not_reflect_internal_paths(self):
        from ransomlab.core.errors import LabError
        def unavailable(_lab_id):
            raise LabError("sensitive-local-path")
        self.service.status = unavailable
        response = self.client.get(f"/api/labs/{LAB_ID}/status", headers=self.auth)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json, {"error": "lab_unavailable"})
        self.assertNotIn(b"sensitive-local-path", response.data)

    def test_small_auth_tokens_are_refused(self):
        with self.assertRaises(ValueError):
            create_app(self.service, access_token="short")

    def test_core_recovery_state_does_not_reuse_historical_verification(self):
        self.service.data["recovery"] = {"state": "verification_lost", "verified": False, "historical_verified": True}
        self.service.data["state"] = "verification_lost"
        self.service.data["fixtures"][0]["status"] = "intact"
        response = self.client.get(f"/labs/{LAB_ID}", headers=self.auth)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Recovery status: verification lost.', response.data)
        self.assertIn(b'class="badge large danger"', response.data)
        self.assertIn(b'class="badge success">intact', response.data)


if __name__ == "__main__":
    unittest.main()
