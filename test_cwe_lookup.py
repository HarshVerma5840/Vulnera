"""
test_cwe_lookup.py

Tests the CWE plain-English translation module.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from cwe_lookup import CWELookup

class TestCWELookup(unittest.TestCase):
    
    def setUp(self):
        self.lookup = CWELookup()

    def test_known_cwe(self):
        """Test looking up a known CWE like SQL Injection."""
        # Test with "CWE-89"
        result1 = self.lookup.get_plain_english("CWE-89")
        self.assertEqual(result1["title"], "SQL Injection")
        self.assertEqual(result1["severity_context"], "CRITICAL")
        self.assertIn("database", result1["plain_english"].lower())
        
        # Test with just "89"
        result2 = self.lookup.get_plain_english("89")
        self.assertEqual(result2["title"], "SQL Injection")

    def test_unknown_cwe(self):
        """Test fallback logic for an unknown CWE."""
        result = self.lookup.get_plain_english("CWE-999999")
        self.assertEqual(result["title"], "Security Vulnerability Detected")
        self.assertEqual(result["severity_context"], "REVIEW")
        
    def test_missing_cwe(self):
        """Test fallback logic for missing/invalid inputs."""
        result_none = self.lookup.get_plain_english(None)
        self.assertEqual(result_none["title"], "Security Vulnerability Detected")
        
        result_empty = self.lookup.get_plain_english("")
        self.assertEqual(result_empty["title"], "Security Vulnerability Detected")
        
        # ZAP often uses "-1" for informational alerts without a CWE
        result_minus_one = self.lookup.get_plain_english("-1")
        self.assertEqual(result_minus_one["title"], "Security Vulnerability Detected")

if __name__ == "__main__":
    unittest.main()
