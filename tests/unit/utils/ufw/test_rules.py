from saltext.ufw.utils.ufw import rules as ufw_rules


class TestGetFirewallRules:
    def test_parses_forward_rules_and_interfaces(self, monkeypatch):
        comment_hex = "68656c6c6f"
        line = (
            "### tuple ### route:allow tcp 22 10.0.0.5 1024 192.168.1.1/32 in_eth0!out_eth1 "
            f"comment={comment_hex}"
        )
        monkeypatch.setattr(ufw_rules, "list_current_rules", lambda: [line])

        rules = ufw_rules.get_firewall_rules()

        assert len(rules) == 1
        parsed = rules[0]
        assert parsed["action"] == "allow"
        assert parsed["interface_in"] == "eth0"
        assert parsed["interface_out"] == "eth1"
        assert parsed["comment"] == "hello"
        assert parsed["direction"] == "forward"
        assert parsed["index"] == 1

    def test_decodes_apps_and_skips_invalid_lines(self, monkeypatch):
        valid_line = "### tuple ### deny udp 53 0.0.0.0/0 any 192.168.0.0/24 My%20App Other%20Service out_wlan0"
        invalid_line = "### tuple ### short"
        too_long_line = "### tuple ### " + "x " * 10
        monkeypatch.setattr(
            ufw_rules,
            "list_current_rules",
            lambda: [invalid_line, valid_line, too_long_line],
        )

        rules = ufw_rules.get_firewall_rules()

        assert len(rules) == 1
        parsed = rules[0]
        assert parsed["dapp"] == "My App"
        assert parsed["sapp"] == "Other Service"
        assert parsed["direction"] == "out"
        assert parsed["interface_out"] == "wlan0"
        assert parsed["interface_in"] == ""


class TestListCurrentRules:
    def test_reads_only_tuple_lines_from_files(self, tmp_path, monkeypatch):
        tuple_line_one = "### tuple ### allow tcp 22 0.0.0.0/0 any 192.168.1.1/32 in\n"
        tuple_line_two = "### tuple ### deny udp 53 0.0.0.0/0 any 192.168.1.1/32 out\n"
        mixed_content = f"{tuple_line_one}\nnot a tuple\n{tuple_line_two}\n"
        rules_file = tmp_path / "user.rules"
        rules_file.write_text(mixed_content, encoding="utf-8")
        missing_file = tmp_path / "missing.rules"

        monkeypatch.setattr(
            ufw_rules,
            "USER_RULES_FILES",
            [str(rules_file), str(missing_file)],
        )

        result = ufw_rules.list_current_rules()

        assert result == [tuple_line_one, tuple_line_two]
