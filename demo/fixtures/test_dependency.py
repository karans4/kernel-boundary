import unittest
from slug_dependency import normalize_slug, VERSION

class DependencyTests(unittest.TestCase):
    def test_whitespace_and_case(self):
        self.assertEqual(normalize_slug("  Hello  "), "hello")
    def test_path_separator_rejected(self):
        for value in ("../secrets", "a/b", "a" + chr(92) + "b"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError): normalize_slug(value)
    def test_empty_rejected(self):
        with self.assertRaises(ValueError): normalize_slug("   ")
    def test_version(self):
        self.assertEqual(VERSION, "1.0.1")
if __name__ == "__main__": unittest.main(verbosity=2)

