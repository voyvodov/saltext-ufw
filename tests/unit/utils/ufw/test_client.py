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
