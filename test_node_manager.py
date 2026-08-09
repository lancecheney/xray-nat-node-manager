import io
import hashlib
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import node_manager as nm


class ConfigTests(unittest.TestCase):
    def test_successful_acme_output_is_replaced_with_short_progress(self):
        noisy = (
            "Adding TXT value: challenge-secret\n"
            "ACCOUNT_THUMBPRINT='thumbprint'\n"
            "-----BEGIN CERTIFICATE-----\nMIIBPUBLIC\n-----END CERTIFICATE-----\n"
            "Cert success.\n"
        )
        completed = subprocess.CompletedProcess([], 0, stdout=noisy)
        output = io.StringIO()
        with mock.patch.object(nm, "run", return_value=completed), redirect_stdout(output):
            nm.run_acme_step(["acme.sh"], "申请测试证书")
        rendered = output.getvalue()
        self.assertEqual(rendered, "申请测试证书...\n申请测试证书：完成\n")
        self.assertNotIn("CERTIFICATE", rendered)
        self.assertNotIn("challenge-secret", rendered)

    def test_failed_acme_output_keeps_error_but_redacts_details(self):
        noisy = (
            "Adding TXT value: challenge-secret\n"
            "CF_Token=cfut_super_secret\n"
            "Cloudflare API returned permission denied\n"
        )
        completed = subprocess.CompletedProcess([], 1, stdout=noisy)
        with mock.patch.object(nm, "run", return_value=completed):
            with self.assertRaisesRegex(nm.InstallError, "permission denied") as caught:
                nm.run_acme_step(["acme.sh"], "申请正式证书")
        self.assertNotIn("challenge-secret", str(caught.exception))
        self.assertNotIn("cfut_super_secret", str(caught.exception))

    def test_acme_installer_runs_from_extracted_source_directory(self):
        archive = b"fixture archive"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "acme.sh-3.1.4"
            source.mkdir()
            installer = source / "acme.sh"
            installer.write_text(
                "#!/bin/sh\n"
                "set -eu\n"
                "test -f ./acme.sh || { echo \"cp: can't stat 'acme.sh'\" >&2; exit 1; }\n"
                "home=\n"
                "while [ $# -gt 0 ]; do\n"
                "  if [ \"$1\" = --home ]; then shift; home=$1; fi\n"
                "  shift\n"
                "done\n"
                "mkdir -p \"$home\"\n"
                "cp ./acme.sh \"$home/acme.sh\"\n"
            )
            os.chmod(installer, 0o755)
            acme_home = root / "installed"
            config_home = root / "config"
            cert_home = root / "certs"
            response = io.BytesIO(archive)
            with mock.patch.object(nm, "ACME_ARCHIVE_SHA256", hashlib.sha256(archive).hexdigest()), \
                    mock.patch.object(nm, "ACME_HOME", acme_home), \
                    mock.patch.object(nm, "ACME_CONFIG_HOME", config_home), \
                    mock.patch.object(nm, "ACME_CERT_HOME", cert_home), \
                    mock.patch.object(nm.urllib.request, "urlopen", return_value=response), \
                    mock.patch.object(nm, "safe_extract_tar", return_value=source), \
                    mock.patch.object(nm, "ensure_cron_running"):
                nm.install_acme_client({"init": "openrc"}, "")

            self.assertTrue((acme_home / "acme.sh").is_file())

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

    def test_modifying_base_preserves_ports_and_credentials(self):
        state = {
            "domain": "old.example.com",
            "network": {"mode": "mapped"},
            "tls": {"method": "existing"},
            "cert": "/old-cert.pem",
            "key": "/old-key.pem",
            "ports": {
                "direct_internal_udp": 10001,
                "direct_external_udp": 20001,
            },
        }
        tls = {
            "method": "existing",
            "cert": "/new-cert.pem",
            "key": "/new-key.pem",
        }
        credentials = {"direct_auth": "auth", "direct_obfs_password": "obfs"}
        with mock.patch.object(nm, "yes_no", side_effect=[True, True]), \
                mock.patch.object(nm, "collect_node_identity", return_value="new.example.com"), \
                mock.patch.object(nm, "collect_tls_answers", return_value=tls), \
                mock.patch.object(nm, "load_secrets", return_value=credentials), \
                mock.patch.object(nm, "backup_paths", return_value=Path("/backup")), \
                mock.patch.object(nm, "refresh_tls_consumers") as refresh, \
                mock.patch.object(nm, "json_write") as write, \
                mock.patch.object(nm, "show_mapping"):
            nm.modify_base({"init": "openrc"}, state)

        updated = refresh.call_args.args[1]
        self.assertEqual(updated["domain"], "new.example.com")
        self.assertEqual(updated["cert"], "/new-cert.pem")
        self.assertEqual(updated["ports"], state["ports"])
        self.assertEqual(refresh.call_args.args[2], credentials)
        self.assertEqual(write.call_args_list[-1].args, (nm.STATE, updated))

    def test_modified_acme_port_cannot_collide_with_reality_or_agent(self):
        state = {
            "ports": {
                "reality_internal_tcp": 10443,
                "reality_external_tcp": 20443,
                "agent_internal_tcp": 10003,
                "agent_external_tcp": 20003,
            },
        }
        with self.assertRaisesRegex(nm.InstallError, "Reality"):
            nm.validate_tls_ports(
                state, {"method": "http", "internal_tcp": 10443, "external_tcp": 80},
            )
        with self.assertRaisesRegex(nm.InstallError, "Agent"):
            nm.validate_tls_ports(
                state, {"method": "http", "internal_tcp": 10003, "external_tcp": 80},
            )

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

    def test_tcp_reality_can_use_same_port_number_as_udp_hy2(self):
        state = {
            "ports": {
                "direct_internal_udp": 10001,
                "direct_external_udp": 20001,
            },
            "tls": {},
        }
        nm.validate_component_ports(
            state, role="reality", internal=10001, external=20001, protocol="tcp",
        )

    def test_two_independent_hy2_nodes_cannot_share_udp_port(self):
        state = {
            "ports": {
                "direct_internal_udp": 10001,
                "direct_external_udp": 20001,
            },
            "tls": {},
        }
        with self.assertRaisesRegex(nm.InstallError, "HY2 直连"):
            nm.validate_component_ports(
                state, role="relay", internal=10001, external=20001, protocol="udp",
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
            nm.create_node()

        collect_ports.assert_not_called()
        self.assertIn("3x-ui 总面板调整", output.getvalue())
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
        self.assertNotIn("HY2 中转落地", rendered)
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
        self.assertIn("3x-ui 主机设置中的端口：45066", rendered)
        self.assertIn("外部 TCP 45066 -> 内部 TCP 5201", rendered)
        self.assertIn("不要填 Agent 内部监听端口", rendered)
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

    def test_agent_services_support_reality_node(self):
        state = {
            "ports": {
                "reality_internal_tcp": 10443,
                "reality_external_tcp": 20443,
            },
        }
        services = nm.agent_services(state, {"init": "openrc"})
        self.assertEqual([service["name"] for service in services], ["xray-vless-reality"])

    def test_menu_exposes_modular_setup_actions(self):
        output = io.StringIO()
        with mock.patch("builtins.input", return_value="0"), redirect_stdout(output):
            nm.menu()
        rendered = output.getvalue()
        self.assertIn("1. 基础设置/修改域名证书", rendered)
        self.assertIn("2. 创建节点", rendered)
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
            self.assertNotIn("xray-vless-reality", script)
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

    def test_certificate_san_matching_supports_exact_wildcard_and_ip(self):
        self.assertTrue(nm.certificate_san_matches(
            {"subjectAltName": (("DNS", "node.example.com"),)}, "node.example.com",
        ))
        self.assertTrue(nm.certificate_san_matches(
            {"subjectAltName": (("DNS", "*.example.com"),)}, "node.example.com",
        ))
        self.assertFalse(nm.certificate_san_matches(
            {"subjectAltName": (("DNS", "*.example.com"),)}, "deep.node.example.com",
        ))
        self.assertTrue(nm.certificate_san_matches(
            {"subjectAltName": (("IP Address", "2001:db8::1"),)}, "2001:0db8::1",
        ))

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
            with mock.patch.object(nm.ssl, "match_hostname", new=None):
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
            if spec["protocol"] != "hy2":
                continue
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

    def test_reality_config_uses_vision_and_minimum_client_version(self):
        spec = nm.SERVICE_SPECS["reality"]
        config = nm.reality_config(
            port=10443,
            target="target.example.com",
            target_port=443,
            server_names=["target.example.com", "example.com"],
            client_id="11111111-1111-4111-8111-111111111111",
            private_key="private-key",
            public_key="public-key",
            short_id="0123456789abcdef",
            spider_x="/0123456789abcdef",
            spec=spec,
        )
        inbound = config["inbounds"][0]
        self.assertEqual(inbound["protocol"], "vless")
        self.assertEqual(inbound["settings"]["clients"][0]["flow"], "xtls-rprx-vision")
        self.assertEqual(inbound["settings"]["encryption"], "none")
        self.assertEqual(inbound["streamSettings"]["network"], "tcp")
        self.assertEqual(inbound["streamSettings"]["tcpSettings"]["header"], {"type": "none"})
        reality = inbound["streamSettings"]["realitySettings"]
        self.assertEqual(reality["target"], "target.example.com:443")
        self.assertEqual(reality["serverNames"], ["target.example.com", "example.com"])
        self.assertEqual(reality["minClientVer"], "1.0.0")
        self.assertEqual(reality["settings"]["publicKey"], "public-key")
        self.assertEqual(reality["settings"]["fingerprint"], "chrome")
        self.assertEqual(reality["settings"]["spiderX"], "/0123456789abcdef")

    def test_reality_key_parser_supports_current_xray_output(self):
        completed = subprocess.CompletedProcess(
            [], 0, stdout="PrivateKey: private-value\nPassword (PublicKey): public-value\n",
        )
        with mock.patch.object(nm, "run", return_value=completed):
            self.assertEqual(
                nm.generate_reality_key_pair(),
                ("private-value", "public-value"),
            )

    def test_reality_scan_uses_the_containing_27(self):
        self.assertEqual(str(nm.reality_scan_network("207.57.140.38")), "207.57.140.32/27")

    def test_reality_domain_filter_rejects_template_and_proxy_targets(self):
        self.assertTrue(nm.reality_domain_allowed("mirror.example.org"))
        self.assertFalse(nm.reality_domain_allowed("*.example.org"))
        self.assertFalse(nm.reality_domain_allowed("www.cloudflare.com"))
        self.assertFalse(nm.reality_domain_allowed("vless.example.org"))

    def test_reality_probe_requires_modern_openssl(self):
        old_help = subprocess.CompletedProcess(
            [], 0, stdout=b"-tls1_3 -alpn\n",
        )
        with mock.patch.object(nm.subprocess, "run", return_value=old_help):
            with self.assertRaisesRegex(nm.InstallError, "升级 OpenSSL"):
                nm.ensure_reality_probe_support()

    def test_reality_probe_accepts_verified_tls13_h2(self):
        output = (
            "Protocol: TLSv1.3\n"
            "ALPN protocol: h2\n"
            "Verify return code: 0 (ok)\n"
        ).encode()
        completed = subprocess.CompletedProcess([], 0, stdout=output)
        with mock.patch.object(nm.subprocess, "run", return_value=completed):
            result = nm.openssl_tls_probe(
                "192.0.2.1", domain="target.example.com", verify_hostname=True,
            )
        self.assertIsNotNone(result)

    def test_reality_target_selection_ranks_three_round_checks(self):
        network = nm.ipaddress.ip_network("207.57.140.32/27")

        def measured(domain, address, *, source, rounds=3, timeout=4.0):
            score = {"near.example.com": 30.0, "www.kernel.org": 60.0}.get(domain)
            if score is None:
                return None
            return {
                "target": domain,
                "address": address,
                "source": source,
                "median_ms": score,
                "max_ms": score + 5,
                "score": score + 5,
            }

        with mock.patch.object(
                nm, "ensure_reality_probe_support"), \
                mock.patch.object(
                nm, "reality_scan_ipv4", return_value="207.57.140.38"), \
                mock.patch.object(
                    nm, "nearby_reality_candidates",
                    return_value=(network, [("near.example.com", "207.57.140.40")]),
                ), \
                mock.patch.object(nm, "resolve_public_ipv4s", return_value=["192.0.2.1"]), \
                mock.patch.object(nm, "measure_reality_candidate", side_effect=measured):
            selected, selected_network = nm.select_reality_target(
                "node.example.com", scan_nearby=True,
            )
        self.assertEqual(selected["target"], "near.example.com")
        self.assertEqual(selected["source"], "附近 /27")
        self.assertEqual(selected_network, network)

    def test_reality_target_requires_successful_xray_tls_13_check(self):
        success = subprocess.CompletedProcess(
            [], 0, stdout="Handshake succeeded\nTLS Version: TLS 1.3\n",
        )
        selected = {
            "target": "www.kernel.org",
            "address": "192.0.2.1",
            "source": "成熟域名回退",
            "median_ms": 20.0,
            "max_ms": 25.0,
            "score": 25.0,
        }
        with mock.patch.object(nm, "reality_scan_ipv4", return_value=None), \
                mock.patch.object(nm, "select_reality_target", return_value=(selected, None)), \
                mock.patch.object(nm, "run", return_value=success):
            target = nm.collect_reality_target("node.example.com")
        self.assertEqual(target["target"], "www.kernel.org")
        self.assertEqual(
            target["server_names"],
            ["cdn.kernel.org", "kernel.org", "www.kernel.org"],
        )

        tls12 = subprocess.CompletedProcess(
            [], 0, stdout="Handshake succeeded\nTLS Version: TLS 1.2\n",
        )
        with mock.patch.object(nm, "reality_scan_ipv4", return_value=None), \
                mock.patch.object(nm, "select_reality_target", return_value=(selected, None)), \
                mock.patch.object(nm, "run", return_value=tls12):
            with self.assertRaisesRegex(nm.InstallError, "最终 TLS 检查失败"):
                nm.collect_reality_target("node.example.com")

    def test_reality_link_uses_public_nat_port(self):
        state = {
            "domain": "node.example.com",
            "ports": {"reality_internal_tcp": 10443, "reality_external_tcp": 20443},
            "reality": {"target": "target.example.com", "target_port": 443},
        }
        credentials = {
            "reality_client_id": "11111111-1111-4111-8111-111111111111",
            "reality_public_key": "public-key",
            "reality_short_id": "0123456789abcdef",
            "reality_spider_x": "/abcdef0123456789",
        }
        with mock.patch.object(nm, "load_state", return_value=state), \
                mock.patch.object(nm, "load_secrets", return_value=credentials):
            link = nm.reality_uri()
        self.assertIn("node.example.com:20443", link)
        self.assertIn("security=reality", link)
        self.assertIn("sni=target.example.com", link)
        self.assertIn("pbk=public-key", link)
        self.assertIn("spx=%2Fabcdef0123456789", link)

    def test_each_inbound_has_explicit_direct_route(self):
        for spec in nm.SERVICE_SPECS.values():
            if spec["protocol"] != "hy2":
                continue
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
