import unittest
from parsers.dummy import parse_log

class TestDummyParser(unittest.TestCase):
    def test_parse_log(self):
        log_line = "Test log entry"
        parsed = parse_log(log_line)
        self.assertEqual(parsed["message"], "Test log entry")
        self.assertEqual(parsed["length"], len(log_line))
        self.assertEqual(parsed["source"], "dummy-parser")

if __name__ == "__main__":
    unittest.main()
