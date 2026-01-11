import unittest
import io
import sys
import os

# We will import the module 'normalize' from bin/ (which doesn't exist yet)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../bin')))

# Mocking the target script location for import
# We will create bin/normalize.py later.

class TestRuleNormalization(unittest.TestCase):
    def setUp(self):
        # Import the module dynamically or ensure it's reloadable if we were iterating
        try:
            import normalize
            self.normalize = normalize
        except ImportError:
            self.fail("Could not import bin/normalize.py - Script does not exist yet (TDD Phase 1)")

    def test_append_default_policy(self):
        """Should append default policy if missing."""
        line = "DOMAIN-SUFFIX,example.com"
        result = self.normalize.process_line(line, default_policy="REJECT")
        self.assertEqual(result, "DOMAIN-SUFFIX,example.com,REJECT")

    def test_preserve_existing_policy(self):
        """Should keep existing policy if present."""
        line = "DOMAIN-SUFFIX,example.com,DIRECT"
        result = self.normalize.process_line(line, default_policy="REJECT")
        self.assertEqual(result, "DOMAIN-SUFFIX,example.com,DIRECT")

    def test_preserve_complex_policy(self):
        """Should handle proxy groups or REJECT-DROP."""
        line = "DOMAIN,test.com,REJECT-DROP"
        result = self.normalize.process_line(line, default_policy="REJECT")
        self.assertEqual(result, "DOMAIN,test.com,REJECT-DROP")

    def test_handle_lan_cidr(self):
        """Should handle IP-CIDR without policy (The Bug Fix)."""
        line = "IP-CIDR,192.168.0.0/16"
        result = self.normalize.process_line(line, default_policy="DIRECT")
        self.assertEqual(result, "IP-CIDR,192.168.0.0/16,DIRECT")

    def test_ignore_comments(self):
        """Should return None for comments."""
        self.assertIsNone(self.normalize.process_line("# This is a comment", "REJECT"))
        self.assertIsNone(self.normalize.process_line("   # Indented comment", "REJECT"))

    def test_ignore_empty(self):
        """Should return None for empty lines."""
        self.assertIsNone(self.normalize.process_line("", "REJECT"))
        self.assertIsNone(self.normalize.process_line("   ", "REJECT"))

    def test_handle_raw_domain(self):
        """Should upgrade raw domain to DOMAIN-SUFFIX and append policy."""
        line = "google.com"
        result = self.normalize.process_line(line, default_policy="REJECT")
        self.assertEqual(result, "DOMAIN-SUFFIX,google.com,REJECT")

if __name__ == '__main__':
    unittest.main()
