import json
import threading
import tempfile
import unittest
from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import patch

import password_wallet


class VerificationTests(unittest.TestCase):
    def test_saved_password_uses_a_salted_one_way_verifier(self):
        verifier = password_wallet.hash_secret("correct horse battery staple")

        self.assertTrue(password_wallet.verify_secret("correct horse battery staple", verifier))
        self.assertFalse(password_wallet.verify_secret("wrong-password", verifier))
        self.assertNotEqual(verifier, password_wallet.hash_secret("correct horse battery staple"))

    def test_malformed_verifiers_are_rejected(self):
        self.assertFalse(password_wallet.verify_secret("password", "not-valid-base64"))

    def test_master_password_is_not_stored_verbatim(self):
        password = "master-password"

        verifier = password_wallet.hash_master(password)

        self.assertNotIn(password, verifier)
        self.assertNotEqual(verifier, password_wallet.hash_master("wrong-password"))

    def test_master_password_preserves_leading_and_trailing_spaces(self):
        password = " master-password "
        verifier = password_wallet.hash_master(password)

        self.assertTrue(password_wallet.verify_master(password, verifier))
        self.assertFalse(password_wallet.verify_master(password.strip(), verifier))


class GeneratorTests(unittest.TestCase):
    def test_generator_honors_length_and_character_requirements(self):
        password = password_wallet.generate_password(24, True, True, True, True)

        self.assertEqual(len(password), 24)
        self.assertRegex(password, r"[A-Z]")
        self.assertRegex(password, r"[a-z]")
        self.assertRegex(password, r"[0-9]")
        self.assertRegex(password, r"[^A-Za-z0-9]")

    def test_generator_handles_disabled_options(self):
        password = password_wallet.generate_password(12, False, True, False, False)

        self.assertEqual(len(password), 12)
        self.assertRegex(password, r"^[a-z]+$")

    def test_generator_falls_back_when_no_options_are_selected(self):
        password = password_wallet.generate_password(10, False, False, False, False)

        self.assertEqual(len(password), 10)
        self.assertRegex(password, r"^[A-Za-z0-9]+$")


class StorageTests(unittest.TestCase):
    def test_missing_store_starts_with_empty_vault(self):
        with tempfile.TemporaryDirectory() as directory:
            wallet_file = Path(directory) / "wallet.json"
            with patch.object(password_wallet, "WALLET_FILE", str(wallet_file)):
                self.assertEqual(
                    password_wallet.load_store(),
                    {"verifier": None, "entries": []},
                )

    def test_store_round_trip_preserves_verifier_data(self):
        store = {
            "verifier": password_wallet.hash_master("master-password"),
            "entries": [{
                "id": "abc123",
                "data": {
                    "title": "GitHub",
                    "password_verifier": password_wallet.hash_secret("secret"),
                    "password_length": 6,
                },
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            wallet_file = Path(directory) / "wallet.json"
            with patch.object(password_wallet, "WALLET_FILE", str(wallet_file)):
                password_wallet.save_store(store)
                loaded = password_wallet.load_store()
                self.assertNotIn("secret", wallet_file.read_text())

        self.assertEqual(loaded, store)

    def test_legacy_wallet_format_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            wallet_file = Path(directory) / "wallet.json"
            wallet_file.write_text(json.dumps({
                "verifier": "legacy",
                "entries": [{"id": "old", "data": "old-format"}],
            }))
            with patch.object(password_wallet, "WALLET_FILE", str(wallet_file)):
                with self.assertRaisesRegex(ValueError, "unsupported legacy format"):
                    password_wallet.load_store()


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.wallet_file = Path(self.directory.name) / "wallet.json"
        self.wallet_patch = patch.object(password_wallet, "WALLET_FILE", str(self.wallet_file))
        self.wallet_patch.start()
        self.server = password_wallet.ThreadingHTTPServer(("127.0.0.1", 0), password_wallet.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.wallet_patch.stop()
        self.directory.cleanup()

    def request(self, path, payload):
        connection = HTTPConnection("127.0.0.1", self.server.server_port)
        connection.request("POST", path, json.dumps(payload), {"Content-Type": "application/json"})
        response = connection.getresponse()
        data = json.loads(response.read())
        connection.close()
        return response.status, data

    def raw_request(self, path, body):
        connection = HTTPConnection("127.0.0.1", self.server.server_port)
        connection.request("POST", path, body, {"Content-Type": "application/json"})
        response = connection.getresponse()
        data = json.loads(response.read())
        connection.close()
        return response.status, data

    def test_entry_lifecycle_hides_verifier_and_verifies_password(self):
        status, result = self.request("/api/unlock", {"master_password": "demo-master"})
        self.assertEqual((status, result), (200, {"ok": True}))

        entry = {
            "master_password": "demo-master",
            "title": "GitHub",
            "username": "demo@example.com",
            "password": "Correct-123!",
            "category": "web",
        }
        status, result = self.request("/api/entries/create", entry)
        self.assertEqual(status, 200)
        entry_id = result["id"]

        status, entries = self.request("/api/entries", {"master_password": "demo-master"})
        self.assertEqual(status, 200)
        self.assertNotIn("password_verifier", entries["entries"][0])
        self.assertNotIn("password", entries["entries"][0])

        status, result = self.request("/api/entries/verify", {
            "master_password": "demo-master", "id": entry_id, "password": "Correct-123!"
        })
        self.assertEqual((status, result), (200, {"valid": True}))
        status, result = self.request("/api/entries/verify", {
            "master_password": "demo-master", "id": entry_id, "password": "wrong"
        })
        self.assertEqual((status, result), (200, {"valid": False}))

        status, result = self.request("/api/entries/update", {
            "master_password": "demo-master", "id": entry_id,
            "title": "GitHub Updated", "password": "", "category": "web"
        })
        self.assertEqual((status, result), (200, {"ok": True, "id": entry_id}))

        status, result = self.request("/api/entries/delete", {
            "master_password": "demo-master", "id": entry_id
        })
        self.assertEqual((status, result), (200, {"ok": True}))

    def test_invalid_generation_and_missing_entries_return_client_errors(self):
        status, result = self.raw_request("/api/generate", "not-json")
        self.assertEqual((status, result), (400, {"error": "Request body must be valid JSON."}))

        status, result = self.request("/api/generate", {"length": "not-a-number"})
        self.assertEqual((status, result), (400, {"error": "Length must be a number."}))

        status, result = self.request("/api/entries/delete", {
            "master_password": "not-created", "id": "missing"
        })
        self.assertEqual(status, 403)

    def test_entry_metadata_rejects_unsafe_types_and_url_schemes(self):
        self.assertEqual(
            self.request("/api/unlock", {"master_password": "demo-master"}),
            (200, {"ok": True}),
        )
        base_entry = {
            "master_password": "demo-master",
            "title": "Example",
            "username": "user@example.com",
            "password": "Correct-123!",
            "category": "web",
        }

        invalid_type = {**base_entry, "notes": {"unexpected": "object"}}
        status, result = self.request("/api/entries/create", invalid_type)
        self.assertEqual((status, result), (400, {"error": "Title and password are required."}))

        unsafe_url = {**base_entry, "url": "javascript:alert(1)"}
        status, result = self.request("/api/entries/create", unsafe_url)
        self.assertEqual((status, result), (400, {"error": "Title and password are required."}))


if __name__ == "__main__":
    unittest.main()
