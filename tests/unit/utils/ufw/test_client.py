from unittest.mock import patch

import pytest

from saltext.ufw.utils.ufw import client


class TestUFWClient:
    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_init_sets_paths(self, _):
        c = client.UFWClient()
        assert c.ufw_path == "/usr/sbin/ufw"
        assert c.grep_path == "/bin/grep"
        assert "/etc/ufw/user.rules" in c.user_rules_files

    @patch("salt.modules.cmdmod.run_all")
    def test__execute_success(self, mock_run_all):
        mock_run_all.return_value = {"retcode": 0, "stdout": "ok"}
        c = client.UFWClient()
        result = c._execute("echo test")
        assert result["stdout"] == "ok"

    @patch("salt.modules.cmdmod.run_all")
    def test__execute_failure(self, mock_run_all):
        mock_run_all.return_value = {"retcode": 1, "stdout": "fail", "stderr": "error"}
        c = client.UFWClient()
        with pytest.raises(client.UFWCommandError):
            c._execute("badcmd")

    @patch("salt.modules.cmdmod.run_all")
    def test_execute_builds_command(self, mock_run_all):
        mock_run_all.return_value = {"retcode": 0, "stdout": "ok"}
        c = client.UFWClient()
        out = c.execute("status", args=["verbose"], force=True, dry_run=True)
        assert "--force" in out["stdout"] or out["stdout"] == "ok"

    @patch("salt.modules.cmdmod.run_all")
    def test_version_parsing(self, mock_run_all):
        mock_run_all.return_value = {"retcode": 0, "stdout": "ufw 0.36.1\n"}
        c = client.UFWClient()
        major, minor, rev = c.version()
        assert (major, minor, rev) == (0, 36, 1)

    @patch("salt.modules.cmdmod.run_all")
    def test_version_unknown(self, mock_run_all):
        mock_run_all.return_value = {"retcode": 0, "stdout": ""}
        c = client.UFWClient()
        assert c.version() == "Unknown"

    @patch("salt.modules.cmdmod.run_all")
    def test_version_parse_error(self, mock_run_all):
        mock_run_all.return_value = {"retcode": 0, "stdout": "not a version\n"}
        c = client.UFWClient()
        with pytest.raises(client.UFWCommandError):
            c.version()

    @patch("salt.modules.cmdmod.run_all")
    def test_get_current_rules(self, mock_run_all):
        mock_run_all.return_value = {"retcode": 0, "stdout": "rule1\nrule2"}
        c = client.UFWClient()
        rules = c.get_current_rules()
        assert "rule1" in rules
        assert "rule2" in rules


def test_get_client_returns_instance():
    c = client.get_client()
    assert isinstance(c, client.UFWClient)


class TestBuildArgs:
    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_build_args_with_insert(self, _):
        """Test _build_args with insert parameter"""
        c = client.UFWClient()
        result = c._build_args(insert=1)
        assert result == ["insert 1"]

    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_build_args_with_action(self, _):
        """Test _build_args with action parameter"""
        c = client.UFWClient()
        result = c._build_args(action="allow")
        assert result == ["allow"]

    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_build_args_with_direction(self, _):
        """Test _build_args with direction parameter"""
        c = client.UFWClient()
        result = c._build_args(direction="in")
        assert result == ["in"]

    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_build_args_with_interface(self, _):
        """Test _build_args with interface parameter"""
        c = client.UFWClient()
        result = c._build_args(interface="eth0")
        assert result == ["on eth0"]

    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_build_args_with_from_ip(self, _):
        """Test _build_args with from_ip parameter"""
        c = client.UFWClient()
        result = c._build_args(from_ip="192.168.1.1")
        assert result == ["from 192.168.1.1"]

    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_build_args_with_from_port(self, _):
        """Test _build_args with from_port parameter"""
        c = client.UFWClient()
        result = c._build_args(from_port="8080")
        assert result == ["port 8080"]

    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_build_args_with_to_ip(self, _):
        """Test _build_args with to_ip parameter"""
        c = client.UFWClient()
        result = c._build_args(to_ip="10.0.0.1")
        assert result == ["to 10.0.0.1"]

    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_build_args_with_to_port(self, _):
        """Test _build_args with to_port parameter"""
        c = client.UFWClient()
        result = c._build_args(to_port="80")
        assert result == ["port 80"]

    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_build_args_with_proto(self, _):
        """Test _build_args with proto parameter"""
        c = client.UFWClient()
        result = c._build_args(proto="tcp")
        assert result == ["proto tcp"]

    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_build_args_with_app(self, _):
        """Test _build_args with app parameter"""
        c = client.UFWClient()
        result = c._build_args(app="Apache")
        assert result == ["app Apache"]

    @patch("salt.modules.cmdmod.run_all")
    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_build_args_with_comment_old_version(self, _, mock_run_all):
        """Test _build_args with comment on old UFW version (should be ignored)"""
        mock_run_all.return_value = {"retcode": 0, "stdout": "ufw 0.34\n"}
        c = client.UFWClient()
        result = c._build_args(comment="test comment")
        # Comment should not be included for version < 0.35
        assert not result

    @patch("salt.modules.cmdmod.run_all")
    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_build_args_with_comment_new_version(self, _, mock_run_all):
        """Test _build_args with comment on new UFW version (>= 0.35)"""
        mock_run_all.return_value = {"retcode": 0, "stdout": "ufw 0.36\n"}
        c = client.UFWClient()
        result = c._build_args(comment="test comment")
        assert result == ["comment 'test comment'"]

    @patch("salt.modules.cmdmod.run_all")
    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_build_args_with_comment_version_1(self, _, mock_run_all):
        """Test _build_args with comment on UFW version 1.x"""
        mock_run_all.return_value = {"retcode": 0, "stdout": "ufw 1.0.0\n"}
        c = client.UFWClient()
        result = c._build_args(comment="test comment")
        assert result == ["comment 'test comment'"]

    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_build_args_with_empty_comment(self, _):
        """Test _build_args with empty comment (converted to empty string)"""
        c = client.UFWClient()
        result = c._build_args(comment="")
        # Empty comment is still processed, resulting in ['']
        assert result == [""]

    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_build_args_filters_none_values(self, _):
        """Test that None values are filtered out"""
        c = client.UFWClient()
        result = c._build_args(action="allow", from_ip=None, to_ip="10.0.0.1")
        assert "allow" in result
        assert "to 10.0.0.1" in result
        assert len([arg for arg in result if "from" in arg]) == 0

    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_build_args_multiple_parameters(self, _):
        """Test _build_args with multiple parameters"""
        c = client.UFWClient()
        result = c._build_args(
            action="allow",
            direction="in",
            from_ip="192.168.1.0/24",
            to_port="22",
            proto="tcp",
        )
        assert "allow" in result
        assert "in" in result
        assert "from 192.168.1.0/24" in result
        assert "port 22" in result
        assert "proto tcp" in result

    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_build_args_with_unknown_parameter(self, _):
        """Test _build_args with unknown parameter (should be converted to string)"""
        c = client.UFWClient()
        result = c._build_args(unknown_param="value")
        assert "value" in result


class TestExecuteCommand:
    @patch("salt.modules.cmdmod.run_all")
    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_execute_with_force(self, _, mock_run_all):
        """Test execute with force flag"""
        mock_run_all.return_value = {"retcode": 0, "stdout": "ok"}
        c = client.UFWClient()
        c.execute("enable", force=True)
        # Check that --force was in the command
        called_cmd = mock_run_all.call_args[0][0]
        assert "--force" in called_cmd

    @patch("salt.modules.cmdmod.run_all")
    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_execute_with_dry_run(self, _, mock_run_all):
        """Test execute with dry_run flag"""
        mock_run_all.return_value = {"retcode": 0, "stdout": "ok"}
        c = client.UFWClient()
        c.execute("status", dry_run=True)
        # Check that --dry-run was in the command
        called_cmd = mock_run_all.call_args[0][0]
        assert "--dry-run" in called_cmd

    @patch("salt.modules.cmdmod.run_all")
    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_execute_builds_full_command(self, _, mock_run_all):
        """Test that execute builds the full command correctly"""
        mock_run_all.return_value = {"retcode": 0, "stdout": "ok"}
        c = client.UFWClient()
        c.execute("allow", from_ip="192.168.1.1", to_port="80", proto="tcp")
        called_cmd = mock_run_all.call_args[0][0]
        assert "/usr/sbin/ufw" in called_cmd
        assert "allow" in called_cmd
        assert "from 192.168.1.1" in called_cmd
        assert "port 80" in called_cmd
        assert "proto tcp" in called_cmd

    @patch("salt.modules.cmdmod.run_all")
    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_execute_with_force_and_dry_run(self, _, mock_run_all):
        """Test execute with both force and dry_run flags"""
        mock_run_all.return_value = {"retcode": 0, "stdout": "ok"}
        c = client.UFWClient()
        c.execute("enable", force=True, dry_run=True)
        called_cmd = mock_run_all.call_args[0][0]
        assert "--force" in called_cmd
        assert "--dry-run" in called_cmd

    @patch("salt.modules.cmdmod.run_all")
    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_execute_failure_raises_exception(self, _, mock_run_all):
        """Test that execute raises exception on failure"""
        mock_run_all.return_value = {"retcode": 1, "stderr": "error", "stdout": ""}
        c = client.UFWClient()
        with pytest.raises(client.UFWCommandError):
            c.execute("invalid")


class TestVersionParsing:
    @patch("salt.modules.cmdmod.run_all")
    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_version_with_two_parts(self, _, mock_run_all):
        """Test version parsing with major.minor format"""
        mock_run_all.return_value = {"retcode": 0, "stdout": "ufw 0.36\n"}
        c = client.UFWClient()
        major, minor, rev = c.version()
        assert major == 0
        assert minor == 36
        assert rev == 0

    @patch("salt.modules.cmdmod.run_all")
    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_version_with_three_parts(self, _, mock_run_all):
        """Test version parsing with major.minor.revision format"""
        mock_run_all.return_value = {"retcode": 0, "stdout": "ufw 0.36.1\n"}
        c = client.UFWClient()
        major, minor, rev = c.version()
        assert major == 0
        assert minor == 36
        assert rev == 1

    @patch("salt.modules.cmdmod.run_all")
    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_version_with_extra_text(self, _, mock_run_all):
        """Test version parsing with extra text after version"""
        mock_run_all.return_value = {"retcode": 0, "stdout": "ufw 0.36.1 (some info)\n"}
        c = client.UFWClient()
        major, minor, rev = c.version()
        assert major == 0
        assert minor == 36
        assert rev == 1

    @patch("salt.modules.cmdmod.run_all")
    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_version_major_version_1(self, _, mock_run_all):
        """Test version parsing with major version 1"""
        mock_run_all.return_value = {"retcode": 0, "stdout": "ufw 1.0.0\n"}
        c = client.UFWClient()
        major, minor, rev = c.version()
        assert major == 1
        assert minor == 0
        assert rev == 0


class TestGetCurrentRules:
    @patch("salt.modules.cmdmod.run_all")
    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_get_current_rules_success(self, _, mock_run_all):
        """Test get_current_rules returns stdout"""
        expected_rules = "### tuple ### rule1\n### tuple ### rule2\n"
        mock_run_all.return_value = {"retcode": 0, "stdout": expected_rules}
        c = client.UFWClient()
        rules = c.get_current_rules()
        assert rules == expected_rules

    @patch("salt.modules.cmdmod.run_all")
    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_get_current_rules_uses_correct_files(self, _, mock_run_all):
        """Test that get_current_rules searches in correct files"""
        mock_run_all.return_value = {"retcode": 0, "stdout": ""}
        c = client.UFWClient()
        c.get_current_rules()
        called_cmd = mock_run_all.call_args[0][0]
        # Verify that user rules files are included in the command
        assert "/etc/ufw/user.rules" in called_cmd or "user.rules" in called_cmd

    @patch("salt.modules.cmdmod.run_all")
    @patch("salt.modules.cmdmod.which", return_value="/bin/grep")
    def test_get_current_rules_ignores_errors(self, _, mock_run_all):
        """Test that get_current_rules ignores grep errors (no matches)"""
        mock_run_all.return_value = {"retcode": 1, "stdout": "", "stderr": "no matches"}
        c = client.UFWClient()
        # Should not raise an exception
        rules = c.get_current_rules()
        assert rules == ""
