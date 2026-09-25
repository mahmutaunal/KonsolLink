import importlib.util
import json
import os
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_metadata", ROOT / "scripts/generate_release_metadata.py")
module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(module)


class ReleaseMetadataTests(unittest.TestCase):
    def test_engine_inventory_is_closed_and_hashed(self):
        components, licenses = module.engine_components()
        self.assertEqual({item["name"] for item in components}, {"go-pcap2socks", "zapret-tpws", "GoodbyeDPI", "WinDivert"})
        self.assertTrue(all(item["license"] != "NOASSERTION" for item in licenses))
        self.assertTrue(next(item for item in components if item["name"] == "GoodbyeDPI")["hashes"])

    def test_generated_sbom_is_cyclonedx_1_6_and_complete(self):
        previous = os.environ.get("SOURCE_DATE_EPOCH")
        os.environ["SOURCE_DATE_EPOCH"] = "1789948800"
        try:
            self.assertEqual(module.main(), 0)
        finally:
            if previous is None:
                os.environ.pop("SOURCE_DATE_EPOCH", None)
            else:
                os.environ["SOURCE_DATE_EPOCH"] = previous
        sbom = json.loads((module.OUT / "konsollink-1.0.0.cdx.json").read_text())
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["specVersion"], "1.6")
        self.assertGreater(len(sbom["components"]), 100)
        refs = [item["bom-ref"] for item in sbom["components"]]
        self.assertEqual(len(refs), len(set(refs)))
        licenses = json.loads((module.OUT / "licenses.json").read_text())
        self.assertEqual(licenses["unknown_licenses"], [])


if __name__ == "__main__":
    unittest.main()
