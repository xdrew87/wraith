import pytest
from click.testing import CliRunner
from unittest.mock import patch, AsyncMock


BASE_CONFIG = {
    "feeds": {
        "hibp": {"enabled": False, "api_key": ""},
        "dehashed": {"enabled": False, "email": "", "api_key": ""},
        "intelx": {"enabled": False, "api_key": ""},
        "pastebin": {"enabled": False},
        "github": {"enabled": False, "token": ""},
    },
    "monitor": {"max_concurrent_feeds": 5},
    "database": {"sqlite_path": ":memory:"},
    "logging": {"level": "ERROR", "file": "logs/test.log"},
    "alerting": {"enabled": False},
}


class TestCLI:
    def test_init_command(self):
        from cli.commands import cli
        runner = CliRunner()

        with patch("cli.commands.load_config", return_value=BASE_CONFIG):
            result = runner.invoke(cli, ["init"])

        assert result.exit_code == 0
        assert "Database initialized" in result.output

    def test_watch_command_adds_target(self):
        from cli.commands import cli
        from core.database import init_db, get_db, WatchTarget
        import core.database as db_module
        db_module._engine = None
        db_module._SessionLocal = None
        init_db(BASE_CONFIG)

        runner = CliRunner()
        with patch("cli.commands.load_config", return_value=BASE_CONFIG):
            with patch("cli.commands.init_db"):
                result = runner.invoke(cli, ["watch", "example.com"])

        assert result.exit_code == 0
        assert "watching" in result.output.lower() or "example.com" in result.output

    def test_scan_command_no_results(self):
        from cli.commands import cli
        from core.database import init_db
        import core.database as db_module
        db_module._engine = None
        db_module._SessionLocal = None
        init_db(BASE_CONFIG)

        runner = CliRunner()
        with patch("cli.commands.load_config", return_value=BASE_CONFIG):
            with patch("cli.commands.init_db"):
                with patch("cli.commands.aggregate", new=AsyncMock(return_value=[])):
                    result = runner.invoke(cli, ["scan", "example.com"])

        assert result.exit_code == 0
        assert "No findings" in result.output
