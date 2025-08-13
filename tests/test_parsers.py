import unittest
from src.parsers import dummy

class TestDummyParser(unittest.TestCase):
    def test_syslog_line(self):
        log_line = "Aug 13 14:23 nginx[1024]: GET /"
        parsed = dummy.parse(log_line)
        self.assertIn("timestamp", parsed)
        self.assertIn("message", parsed)
        self.assertTrue(parsed["message"].startswith("nginx"))

    def test_json_line(self):
        log_line = '{"user":42,"action":"login"}'
        parsed = dummy.parse(log_line)
        self.assertEqual(parsed["user"], 42)
        self.assertEqual(parsed["action"], "login")

if __name__ == "__main__":
    unittest.main()
