from django.test import RequestFactory, SimpleTestCase, override_settings

from apps.core.utils import get_client_ip


class HealthAndHeadersTests(SimpleTestCase):
    def test_health_ok_and_secure_headers(self):
        response = self.client.get("/api/v1/health/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertIn("frame-ancestors 'none'", response["Content-Security-Policy"])
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response["X-Frame-Options"], "DENY")
        self.assertEqual(response["Referrer-Policy"], "no-referrer")

    def test_unsafe_methods_not_allowed(self):
        self.assertEqual(self.client.post("/api/v1/health/").status_code, 405)


class ClientIpTests(SimpleTestCase):
    def setUp(self):
        self.rf = RequestFactory()

    def test_forwarded_header_ignored_by_default(self):
        req = self.rf.get("/", REMOTE_ADDR="10.0.0.9", HTTP_X_FORWARDED_FOR="6.6.6.6")
        self.assertEqual(get_client_ip(req), "10.0.0.9")  # spoofed header cannot change the IP

    @override_settings(TRUSTED_PROXY_COUNT=1)
    def test_trusted_proxy_uses_rightmost_entry(self):
        req = self.rf.get("/", REMOTE_ADDR="10.0.0.1", HTTP_X_FORWARDED_FOR="6.6.6.6, 203.0.113.7")
        self.assertEqual(get_client_ip(req), "203.0.113.7")  # attacker-prepended value is ignored

    @override_settings(TRUSTED_PROXY_COUNT=1)
    def test_invalid_forwarded_value_falls_back(self):
        req = self.rf.get("/", REMOTE_ADDR="10.0.0.1", HTTP_X_FORWARDED_FOR="not-an-ip")
        self.assertEqual(get_client_ip(req), "10.0.0.1")
