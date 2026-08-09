import io
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import node_manager as nm


class ConfigTests(unittest.TestCase):
    def test_install_questions_are_grouped_and_tls_precedes_ports(self):
        answers = iter([
            "node.example.com", "/cert.pem", "/key.pem",
            "5201", "45066", "24443", "58350", "5201", "45066",
        ])
        output = io.StringIO()
        with mock.patch("builtins.input", side_effect=lambda _: next(answers)), \
                mock.patch.object(nm, "validate_cert_paths") as validate, redirect_stdout(output):
            result = nm.collect_install_answers()

        validate.assert_called_once_with("/cert.pem", "/key.pem", "node.example.com")
        rendered = output.getvalue()
        headings = ["[1/4] 节点身份与 TLS", "[2/4] HY2 直连端口", "[3/4] HY2 中转落地端口", "[4/4] Agent 管理端口"]
        positions = [rendered.index(heading) for heading in headings]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(result["ports"]["relay_external_udp"], 58350)

    def test_node_identity_accepts_domains_and_ips(self):
        self.assertEqual(nm.normalize_node_identity("Node.Example.com."), "node.example.com")
        self.assertEqual(nm.normalize_node_identity("192.0.2.10"), "192.0.2.10")
        self.assertEqual(nm.normalize_node_identity("2001:db8::1"), "2001:db8::1")
        self.assertEqual(nm.uri_host("2001:db8::1"), "[2001:db8::1]")
        with self.assertRaises(nm.InstallError):
            nm.normalize_node_identity("not_a_domain")

    def test_certificate_identity_and_private_key_are_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            cert = Path(directory) / "cert.pem"
            key = Path(directory) / "key.pem"
            other_key = Path(directory) / "other-key.pem"
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "1", "-nodes",
                "-subj", "/CN=node.example.com", "-addext", "subjectAltName=DNS:node.example.com",
                "-keyout", str(key), "-out", str(cert),
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run([
                "openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                "-out", str(other_key),
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            nm.validate_cert_paths(str(cert), str(key), "node.example.com")
            with self.assertRaisesRegex(nm.InstallError, "SAN"):
                nm.validate_cert_paths(str(cert), str(key), "other.example.com")
            with self.assertRaisesRegex(nm.InstallError, "不匹配"):
                nm.validate_cert_paths(str(cert), str(other_key), "node.example.com")

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
