import io
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import node_manager as nm


class ConfigTests(unittest.TestCase):
    def test_bbr_already_enabled_reports_status_without_prompting(self):
        output = io.StringIO()
        status = {
            "congestion_control": "bbr",
            "available": "reno cubic bbr",
            "default_qdisc": "fq",
        }
        with mock.patch.object(nm, "linux_tcp_bbr_status", return_value=status), \
                mock.patch("builtins.input") as user_input, redirect_stdout(output):
            nm.check_linux_tcp_bbr()

        user_input.assert_not_called()
        self.assertIn("Linux TCP BBR：已开启", output.getvalue())
        self.assertIn("HY2 使用独立的 QUIC BBR", output.getvalue())

    def test_bbr_missing_qdisc_is_described_as_host_not_exposed(self):
        status = {
            "congestion_control": "bbr",
            "available": "reno cubic bbr",
            "default_qdisc": None,
        }
        output = io.StringIO()
        with mock.patch.object(nm, "linux_tcp_bbr_status", return_value=status), redirect_stdout(output):
            nm.check_linux_tcp_bbr()
        self.assertIn("宿主机未暴露（NAT/LXC 常见）", output.getvalue())

    def test_bbr_disabled_can_be_skipped_and_install_continues(self):
        output = io.StringIO()
        status = {
            "congestion_control": "cubic",
            "available": "reno cubic bbr",
            "default_qdisc": "fq_codel",
        }
        with mock.patch.object(nm, "linux_tcp_bbr_status", return_value=status), \
                mock.patch("builtins.input", return_value="n"), \
                mock.patch.object(nm, "enable_linux_tcp_bbr") as enable, redirect_stdout(output):
            nm.check_linux_tcp_bbr()

        enable.assert_not_called()
        self.assertIn("已跳过 Linux TCP BBR，继续安装", output.getvalue())

    def test_bbr_enable_uses_managed_sysctl_file_and_verifies_runtime(self):
        before = {
            "congestion_control": "cubic",
            "available": "reno cubic bbr",
            "default_qdisc": "fq_codel",
        }
        after = {
            "congestion_control": "bbr",
            "available": "reno cubic bbr",
            "default_qdisc": "fq",
        }
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "99-bbr.conf"
            completed = subprocess.CompletedProcess([], 0, stdout="applied\n")
            with mock.patch.object(nm, "linux_tcp_bbr_status", side_effect=[before, after]), \
                    mock.patch.object(nm, "run", return_value=completed) as run_command:
                result = nm.enable_linux_tcp_bbr(config)

            self.assertEqual(result, after)
            self.assertEqual(
                config.read_text(),
                "# Managed by xray-nat-node-manager\n"
                "net.core.default_qdisc=fq\n"
                "net.ipv4.tcp_congestion_control=bbr\n",
            )
            run_command.assert_called_once_with(
                ["sysctl", "-p", str(config)], check=False, capture=True,
            )

    def test_bbr_failed_apply_restores_previous_file_and_runtime(self):
        before = {
            "congestion_control": "cubic",
            "available": "reno cubic bbr",
            "default_qdisc": "fq_codel",
        }
        after = {**before}
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "99-bbr.conf"
            config.write_text("old-setting=1\n")
            failed = subprocess.CompletedProcess([], 1, stdout="permission denied\n")
            with mock.patch.object(nm, "linux_tcp_bbr_status", side_effect=[before, after]), \
                    mock.patch.object(nm, "run", return_value=failed), \
                    mock.patch.object(nm, "restore_bbr_runtime") as restore:
                with self.assertRaisesRegex(nm.InstallError, "permission denied"):
                    nm.enable_linux_tcp_bbr(config)

            self.assertEqual(config.read_text(), "old-setting=1\n")
            restore.assert_called_once_with(before)

    def test_base_setup_stops_before_node_and_agent_ports(self):
        answers = iter(["1", "node.example.com", "1", "3", "/cert.pem", "/key.pem"])
        output = io.StringIO()
        with mock.patch("builtins.input", side_effect=lambda _: next(answers)), \
                mock.patch.object(nm, "detect_public_ip", return_value=None), \
                mock.patch.object(nm, "validate_cert_paths") as validate, redirect_stdout(output):
            result = nm.collect_base_answers()

        validate.assert_called_once_with("/cert.pem", "/key.pem", "node.example.com")
        rendered = output.getvalue()
        headings = ["[1/3] 节点地址", "[2/3] 端口方式", "[3/3] TLS 证书"]
        positions = [rendered.index(heading) for heading in headings]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("HY2 直连端口", rendered)
        self.assertNotIn("Agent 管理端口", rendered)
        self.assertEqual(result["ports"], {})
        self.assertEqual(result["network"]["mode"], "mapped")

    def test_each_component_collects_only_its_own_ports(self):
        mapped_answers = iter(["12001", "22001"])
        with mock.patch("builtins.input", side_effect=lambda _: next(mapped_answers)):
            self.assertEqual(
                nm.collect_service_ports("HY2 直连", "UDP", {"mode": "mapped"}),
                (12001, 22001),
            )
        with mock.patch("builtins.input", return_value="12002"):
            self.assertEqual(
                nm.collect_service_ports("HY2 中转落地", "UDP", {"mode": "direct"}),
                (12002, 12002),
            )

    def test_node_address_explicitly_selects_domain_or_detected_ip(self):
        domain_answers = iter(["1", "Node.Example.com"])
        with mock.patch("builtins.input", side_effect=lambda _: next(domain_answers)), \
                mock.patch.object(nm, "detect_public_ip", return_value="69.42.222.160"):
            self.assertEqual(nm.collect_node_identity(), "node.example.com")

        ip_answers = iter(["2", "y"])
        with mock.patch("builtins.input", side_effect=lambda _: next(ip_answers)), \
                mock.patch.object(nm, "detect_public_ip", return_value="69.42.222.160"):
            self.assertEqual(nm.collect_node_identity(), "69.42.222.160")

    def test_old_flat_state_is_compatible_with_modular_components(self):
        state = {
            "domain": "node.example.com",
            "network": {"mode": "mapped"},
            "tls": {"method": "cloudflare"},
            "cert": None,
            "ports": {
                "direct_internal_udp": 10001,
                "direct_external_udp": 20001,
                "relay_internal_udp": 10002,
                "relay_external_udp": 20002,
                "agent_internal_tcp": 10003,
                "agent_external_tcp": 20003,
            },
        }
        self.assertEqual(nm.configured_roles(state), ["direct", "relay"])
        self.assertTrue(nm.agent_is_configured(state))

    def test_node_port_validation_only_compares_configured_peer(self):
        state = {
            "ports": {
                "direct_internal_udp": 10001,
                "direct_external_udp": 20001,
            },
            "tls": {},
        }
        nm.validate_component_ports(
            state, role="relay", internal=10002, external=20002, protocol="udp",
        )
        with self.assertRaisesRegex(nm.InstallError, "内部 UDP 端口"):
            nm.validate_component_ports(
                state, role="relay", internal=10001, external=20002, protocol="udp",
            )

    def test_existing_node_service_is_managed_from_central_panel(self):
        state = {
            "network": {"mode": "mapped"},
            "ports": {
                "direct_internal_udp": 10001,
                "direct_external_udp": 20001,
            },
        }
        output = io.StringIO()
        with mock.patch.object(nm, "require_root_supported", return_value={"init": "openrc"}), \
                mock.patch.object(nm, "load_state", return_value=state), \
                mock.patch.object(nm, "load_secrets", return_value={}), \
                mock.patch("builtins.input", return_value="1"), \
                mock.patch.object(nm, "collect_service_ports") as collect_ports, \
                redirect_stdout(output):
            nm.initialize_node_service()

        collect_ports.assert_not_called()
        self.assertIn("美国总 3x-ui 面板调整", output.getvalue())
        self.assertIn("NAT 服务商后台管理", output.getvalue())

    def test_mapping_renders_only_configured_components(self):
        state = {
            "network": {"mode": "mapped"},
            "tls": {},
            "ports": {
                "direct_internal_udp": 10001,
                "direct_external_udp": 20001,
            },
        }
        output = io.StringIO()
        with redirect_stdout(output):
            nm.show_mapping(state)
        rendered = output.getvalue()
        self.assertIn("UDP 20001 -> UDP 10001", rendered)
        self.assertNotIn("HY2 美国中转落地", rendered)
        self.assertNotIn("xui-agent", rendered)

    def test_http_validation_has_fixed_public_port_and_configurable_nat_port(self):
        answers = iter(["2", "18080", "y", "admin@example.com"])
        with mock.patch("builtins.input", side_effect=lambda _: next(answers)):
            tls = nm.collect_tls_answers("node.example.com", {"mode": "mapped"})
        self.assertEqual(tls["external_tcp"], 80)
        self.assertEqual(tls["internal_tcp"], 18080)

        answers = iter(["2", "admin@example.com"])
        with mock.patch("builtins.input", side_effect=lambda _: next(answers)):
            tls = nm.collect_tls_answers("node.example.com", {"mode": "direct"})
        self.assertEqual(tls["external_tcp"], 80)
        self.assertEqual(tls["internal_tcp"], 80)

    def test_cloudflare_prompt_explains_scoped_token_and_collects_zone_id(self):
        answers = iter(["1", "admin@example.com"])
        output = io.StringIO()
        with mock.patch("builtins.input", side_effect=lambda _: next(answers)), \
                mock.patch("getpass.getpass", side_effect=["secret-cloudflare-token-value", "a" * 32]), \
                redirect_stdout(output):
            tls = nm.collect_tls_answers("node.example.com", {"mode": "mapped"})

        self.assertEqual(tls["cf_zone_id"], "a" * 32)
        self.assertEqual(tls["_cf_token"], "secret-cloudflare-token-value")
        rendered = output.getvalue()
        self.assertIn("https://dash.cloudflare.com/profile/api-tokens", rendered)
        self.assertIn("Zone > DNS > Edit", rendered)
        self.assertIn("不要使用 Global API Key", rendered)

    def test_cloudflare_credentials_explain_when_token_and_zone_are_swapped(self):
        answers = iter(["1"])
        with mock.patch("builtins.input", side_effect=lambda _: next(answers)), \
                mock.patch("getpass.getpass", side_effect=["secret-cloudflare-token-value", "cfut_wrong-field"]):
            with self.assertRaisesRegex(nm.InstallError, "需要 Zone ID"):
                nm.collect_tls_answers("node.example.com", {"mode": "mapped"})

    def test_agent_setup_uses_public_port_and_https(self):
        output = io.StringIO()
        state = {
            "domain": "node.example.com",
            "ports": {"agent_internal_tcp": 5201, "agent_external_tcp": 45066},
        }
        with redirect_stdout(output):
            nm.show_agent_setup(state)
        rendered = output.getvalue()
        self.assertIn("node.example.com", rendered)
        self.assertIn("45066", rendered)
        self.assertIn("协议：https", rendered)
        self.assertIn("标准验证（verify", rendered)
        self.assertIn("基础路径：/", rendered)

    def test_agent_services_include_only_configured_nodes(self):
        state = {
            "ports": {
                "relay_internal_udp": 10002,
                "relay_external_udp": 20002,
            },
        }
        services = nm.agent_services(state, {"init": "openrc"})
        self.assertEqual([service["name"] for service in services], ["xray-hy2-relay"])
        self.assertTrue(services[0]["default"])

    def test_menu_exposes_modular_setup_actions(self):
        output = io.StringIO()
        with mock.patch("builtins.input", return_value="0"), redirect_stdout(output):
            nm.menu()
        rendered = output.getvalue()
        self.assertIn("1. 基础设置（首次使用）", rendered)
        self.assertIn("2. 初始化节点服务", rendered)
        self.assertIn("3. 查看节点连接", rendered)
        self.assertIn("5. 设置 Agent", rendered)
        self.assertIn("6. 查看 Agent 接入信息", rendered)

    def test_acme_modes_match_identity_type(self):
        cloudflare = nm.acme_validation_args("node.example.com", {"method": "cloudflare"})
        self.assertIn("dns_cf", cloudflare)
        self.assertNotIn("shortlived", cloudflare)

        ip_http = nm.acme_validation_args("192.0.2.10", {"method": "http", "internal_tcp": 8080})
        self.assertIn("--standalone", ip_http)
        self.assertIn("8080", ip_http)
        self.assertEqual(ip_http[-2:], ["--certificate-profile", "shortlived"])

    def test_certificate_reload_covers_hy2_and_agent(self):
        for system in ({"init": "openrc"}, {"init": "systemd"}):
            script = nm.certificate_reload_script(system)
            self.assertIn("xray-hy2-direct", script)
            self.assertIn("xray-hy2-relay", script)
            self.assertIn("xui-agent", script)

    def test_cloudflare_token_is_not_written_to_node_state(self):
        state = nm.state_without_secrets({
            "tls": {"method": "cloudflare", "_cf_token": "secret-token"},
        })
        self.assertNotIn("_cf_token", state["tls"])
        self.assertTrue(state["tls"]["token_configured"])

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
        with mock.patch.object(nm.shutil, "which", return_value=None):
            self.assertEqual(
                nm.service_disable_argv(alpine, "xray-hy2-direct"),
                ["/sbin/rc-update", "del", "xray-hy2-direct", "default"],
            )
            self.assertEqual(
                nm.service_disable_argv(debian, "xray-hy2-direct"),
                ["/bin/systemctl", "disable", "xray-hy2-direct"],
            )

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
