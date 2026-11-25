import unittest
from analyzer.detector import detect

class TestDetector(unittest.TestCase):
    def test_bruteforce(self):
        events=[{"event_id":4625,"time":f"2026-01-01T00:0{i}:00","username":"admin","source_ip":"198.51.100.5"} for i in range(5)]
        self.assertTrue(any(a["rule"]=="POSSIBLE_BRUTE_FORCE" for a in detect(events)))
    def test_below_threshold(self):
        events=[{"event_id":4625,"time":f"2026-01-01T00:0{i}:00","username":"admin","source_ip":"198.51.100.5"} for i in range(4)]
        self.assertFalse(any(a["rule"]=="POSSIBLE_BRUTE_FORCE" for a in detect(events)))
    def test_log_cleared(self):
        self.assertTrue(any(a["event_id"]==1102 for a in detect([{"event_id":1102,"time":"2026-01-01T00:00:00"}])))
if __name__=="__main__": unittest.main()
