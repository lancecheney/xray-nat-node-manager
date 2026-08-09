import tempfile
import unittest
from pathlib import Path

import node_manager as nm


class ConfigTests(unittest.TestCase):
    def test_supported_os_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "os-release"
            cases = {
                'ID=alpine\n': {"os": "alpine", "init": "openrc"},
                'ID=debian\n': {"os": "debian", "init": "systemd"},
                'NAME="Ubuntu"\nID=ubuntu\n': {"os": "ubuntu", "init": "systemd"},
            }
            for content, expected in cases.items():
                path.write_text(content)
                self.assertEqual(nm.detect_system(path), expected)

    def test_service_definitions_match_init_system(self):
        alpine = {"os": "alpine", "init": "openrc"}
        debian = {"os": "debian", "init": "systemd"}
        openrc = nm.service_definition(alpine, "xray-hy2-direct", Path("/etc/test.json"))
        systemd = nm.service_definition(debian, "xray-hy2-direct", Path("/etc/test.json"))
        self.assertIn("#!/sbin/openrc-run", openrc)
        self.assertIn('command_args="run -c /etc/test.json"', openrc)
        self.assertIn("[Service]", systemd)
        self.assertIn("ExecStart=/usr/local/bin/xray run -c /etc/test.json", systemd)

    def test_atomic_write_replaces_complete_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            nm.write_atomic(path, "old", 0o600)
            nm.write_atomic(path, "new", 0o600)
            self.assertEqual(path.read_text(), "new")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_atomic_copy_replaces_complete_file(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            target = Path(directory) / "target"
            source.write_bytes(b"new-binary")
            target.write_bytes(b"old")
            nm.copy_atomic(source, target, 0o755)
            self.assertEqual(target.read_bytes(), b"new-binary")
            self.assertEqual(target.stat().st_mode & 0o777, 0o755)

    def test_two_roles_are_isolated_and_use_bbr_standard(self):
        credentials = {
            "direct": ("direct-auth", "direct-obfs"),
            "relay": ("relay-auth", "relay-obfs"),
        }
        configs = {}
        for role, spec in nm.SERVICE_SPECS.items():
            auth, obfs = credentials[role]
            configs[role] = nm.hy2_config(
                domain="node.example.com",
                port=5201 if role == "direct" else 24443,
                cert="/cert.pem",
                key="/key.pem",
                auth=auth,
                obfs_password=obfs,
                spec=spec,
            )

        direct = configs["direct"]["inbounds"][0]
        relay = configs["relay"]["inbounds"][0]
        self.assertNotEqual(direct["port"], relay["port"])
        self.assertNotEqual(direct["settings"]["clients"][0]["auth"], relay["settings"]["clients"][0]["auth"])
        self.assertNotEqual(direct["tag"], relay["tag"])
        for inbound in (direct, relay):
            quic = inbound["streamSettings"]["finalmask"]["quicParams"]
            self.assertEqual(quic["congestion"], "bbr")
            self.assertEqual(quic["bbrProfile"], "standard")
            self.assertEqual(inbound["streamSettings"]["tlsSettings"]["alpn"], ["h3"])

    def test_each_inbound_has_explicit_direct_route(self):
        for spec in nm.SERVICE_SPECS.values():
            config = nm.hy2_config(
                domain="node.example.com", port=12345, cert="/cert.pem", key="/key.pem",
                auth="auth", obfs_password="obfs", spec=spec,
            )
            rules = config["routing"]["rules"]
            self.assertIn(
                {"type": "field", "inboundTag": [spec["tag"]], "outboundTag": "direct"},
                rules,
            )


if __name__ == "__main__":
    unittest.main()
