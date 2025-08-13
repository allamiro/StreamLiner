import unittest
from src.connectors import elastic

class TestElasticConnector(unittest.TestCase):
    def test_send_event(self):
        connector = elastic.ElasticConnector(url="http://localhost:9200", index="logs-test")
        # For now just test it doesn't raise
        try:
            connector.send({"message": "test event"})
        except Exception as e:
            self.fail(f"Connector send raised an exception: {e}")

if __name__ == "__main__":
    unittest.main()
