"""Automated tests for password_analyzer.py  (run: python -m unittest -v)"""
import os, tempfile, unittest
from password_analyzer import (analyze_password, generate_password,
    generate_passphrase, PasswordHistory, has_sequence, has_repeats)

class TestAnalyzer(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        self.assertEqual(analyze_password("password")["rating"], "VERY WEAK")
    def test_leet_common_password_is_weak(self):
        self.assertIn(analyze_password("P@ssw0rd")["rating"], ("VERY WEAK", "WEAK"))
    def test_short_password_weak(self):
        self.assertIn(analyze_password("Ab1!")["rating"], ("VERY WEAK", "WEAK"))
    def test_sequence_and_repeat_detection(self):
        self.assertTrue(has_sequence("xxabcxx"))
        self.assertTrue(has_sequence("myqwerty"))
        self.assertTrue(has_repeats("hellooo!"))
        self.assertFalse(has_sequence("Tr9#kPm2"))
    def test_long_random_is_strong(self):
        self.assertIn(analyze_password("vK7#mQ2$xL9!pR4&")["rating"], ("STRONG", "VERY STRONG"))
    def test_generated_passwords_are_strong(self):
        for _ in range(50):
            self.assertIn(analyze_password(generate_password())["rating"], ("STRONG", "VERY STRONG"))
    def test_passphrase_format(self):
        self.assertGreaterEqual(len(generate_passphrase().split("-")), 5)

class TestHistory(unittest.TestCase):
    def test_reuse_detection_and_isolation(self):
        d = tempfile.mkdtemp(); db = os.path.join(d, "h.db")
        h = PasswordHistory(db)
        h.add("alice", "Old-Pass-123!")
        self.assertTrue(h.was_used("alice", "Old-Pass-123!"))
        self.assertFalse(h.was_used("alice", "New-Pass-456!"))
        self.assertFalse(h.was_used("bob", "Old-Pass-123!"))
        self.assertFalse(h.was_used("x' OR '1'='1", "Old-Pass-123!"))
        h.close()
        with open(db, "rb") as f:
            raw = f.read()
        self.assertNotIn(b"Old-Pass-123!", raw)   # never stored in plain text

if __name__ == "__main__":
    unittest.main()
