import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("checksums", ROOT / "scripts/make_release_checksums.py")
module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(module)


class ReleaseChecksumsTests(unittest.TestCase):
    def test_closed_manifest_detects_tamper_and_extra_assets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "KonsolLink-1.0.0.zip").write_bytes(b"release")
            module.create(root)
            module.verify(root)
            manifest = json.loads((root / "release-manifest.json").read_text())
            self.assertEqual(manifest["version"], "1.0.0")
            (root / "KonsolLink-1.0.0.zip").write_bytes(b"tampered")
            with self.assertRaises(SystemExit):
                module.verify(root)
            (root / "KonsolLink-1.0.0.zip").write_bytes(b"release")
            (root / "extra.json").write_text("{}")
            with self.assertRaises(SystemExit):
                module.verify(root)

    def test_unexpected_extension_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "payload.exe").write_bytes(b"MZ")
            with self.assertRaises(SystemExit):
                module.create(root)


if __name__ == "__main__":
    unittest.main()
