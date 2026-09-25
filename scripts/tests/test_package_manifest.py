import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "package_manifest.py"
SPEC = importlib.util.spec_from_file_location("package_manifest", SCRIPT)
MANIFEST = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MANIFEST)


class ManifestTests(unittest.TestCase):
    def test_inventory_is_stable_and_detects_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.txt").write_text("one", encoding="utf-8")
            first = MANIFEST.inventory(root)
            self.assertEqual(first[0]["path"], "a.txt")
            (root / "a.txt").write_text("two", encoding="utf-8")
            self.assertNotEqual(first, MANIFEST.inventory(root))

    def test_rejects_escaping_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bad").symlink_to("../outside")
            with self.assertRaisesRegex(ValueError, "unsafe"):
                MANIFEST.inventory(root)


if __name__ == "__main__":
    unittest.main()
