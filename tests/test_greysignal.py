import unittest
from greysignal import validate_url


class URLValidationTests(unittest.TestCase):
    def test_accepts_http_and_https(self):
        self.assertEqual(validate_url("https://example.com"), "https://example.com")
        self.assertEqual(validate_url("http://localhost:8000"), "http://localhost:8000")

    def test_rejects_missing_scheme(self):
        with self.assertRaises(ValueError):
            validate_url("example.com")

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(ValueError):
            validate_url("https://user:password@example.com")


if __name__ == "__main__":
    unittest.main()
