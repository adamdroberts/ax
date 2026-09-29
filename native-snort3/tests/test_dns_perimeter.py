"""Data-only perimeter configuration failures; native enforcement is replayed separately."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

NATIVE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("dns_perimeter", NATIVE / "generate_dns_perimeter.py")
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((NATIVE / "dns-perimeter.example.json").read_text())

    def test_canonical_inputs_and_profiles(self):
        for version in (4, 6, None):
            config = copy.deepcopy(self.policy)
            if version:
                for key in ("agent_networks", "dns_proxy_addresses", "broker_addresses"):
                    config[key] = [value for value in config[key] if (":" in value) == (version == 6)]
            config["dns_port"], config["broker_ports"] = 5353, [8443, 443]
            validated = generator.validate(config)
            self.assertEqual(validated["broker_ports"], [443, 8443])
            for http in (False, True):
                rendered = generator.render(config, http)
                self.assertNotIn("\npass ", rendered)
                self.assertIn('ips.variables.ports.AX_DNS_PORT = "5353"', rendered)
                self.assertEqual(rendered.count("sid:9121001;"), 2)  # Definition and enabled state.
                self.assertNotIn("sid:9101001;", rendered)

    def test_invalid_policy_rejected(self):
        replacements = {
            "schema_version": [True, 0, 2, "1", None],
            "agent_networks": [[], ["any"], ["0.0.0.0/0"], ["10.20.0.1/24"], ["10.20.0.0/24", "10.20.0.0/25"],
                               ["::ffff:a14:0/120"], ["fe80::/64"], ["127.0.0.0/8"], ["ff00::/8"], [None]],
            "dns_proxy_addresses": [[], ["dns.company.example"], ["10.30.0.53/32"], ["10.30.0.53", "10.30.0.53"],
                                    ["10.30.0.10", "fd00:30::53"], ["10.20.0.53", "fd00:30::53"],
                                    ["127.0.0.1"], ["0.0.0.0"], ["255.255.255.255"], ["224.0.0.1"],
                                    ["fd00:30::53%en0"], ["::ffff:10.30.0.53"], ["FD00:30::53"], [123]],
            "broker_addresses": [[], ["10.30.0.10"], ["fd00:30::10"], ["10.30.0.53", "fd00:30::10"]],
            "dns_port": [0, -1, 65536, True, "53", "53; pass ip any any -> any any", None],
            "broker_ports": [[], [443, 443], [0], [65536], [True], ["443"], list(range(1, 10))],
        }
        for field, values in replacements.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    config = copy.deepcopy(self.policy)
                    config[field] = value
                    with self.assertRaises((ValueError, TypeError)):
                        generator.validate(config)
        for field in self.policy:
            config = copy.deepcopy(self.policy)
            del config[field]
            with self.assertRaises(ValueError):
                generator.validate(config)
        with self.assertRaises(ValueError):
            generator.validate(self.policy | {"ignored_security_setting": True})

    def test_file_bounds_duplicate_keys_and_path_escaping(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            for text in ('{"schema_version":1,"schema_version":1}', " " * 16385):
                path.write_text(text)
                with self.assertRaises(ValueError):
                    generator.load(path)
            for name in ('quoted"directory', "directory\\name", "directoryé"):
                directory = Path(temporary) / name
                directory.mkdir()
                (directory / "protocol-ips.lua").write_text("-- test path only")
                self.assertIn("include(" + json.dumps(str(directory.resolve() / "protocol-ips.lua"), ensure_ascii=False) + ")",
                              generator.render(self.policy, native_dir=directory))
            with self.assertRaises(ValueError):
                generator.render(self.policy, native_dir=Path(temporary) / "bad\npath")


if __name__ == "__main__":
    unittest.main()
