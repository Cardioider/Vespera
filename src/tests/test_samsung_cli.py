import json

import pytest

from unsealer.samsung import cli


@pytest.fixture
def backup(mocker, tmp_path):
    source = tmp_path / "test.spass"
    source.write_bytes(b"synthetic-backup")
    mocker.patch.object(cli.Prompt, "ask", return_value="test-password")
    mocker.patch.object(cli, "_display_banner", return_value="test")
    mocker.patch.object(cli, "decrypt_and_parse", return_value={
        "logins": [{"title": "Example", "username": "test-user", "password": "test-password"}],
    })
    return source


def test_samsung_cli_success_flow(backup):
    assert cli.main([str(backup), "-f", "json"]) == 0
    result = json.loads(backup.with_suffix(".json").read_text(encoding="utf-8"))
    assert result["logins"][0]["username"] == "test-user"
    cli.decrypt_and_parse.assert_called_once_with(b"synthetic-backup", "test-password")


def test_samsung_cli_invalid_password(mocker, backup):
    mocker.patch.object(cli, "decrypt_and_parse", side_effect=ValueError("Decryption failed"))
    assert cli.main([str(backup)]) == 1
    assert not backup.with_suffix(".md").exists()


def test_samsung_cli_preview_does_not_write(backup):
    output = backup.with_suffix(".json")
    assert cli.main([str(backup), "--preview", "-o", str(output)]) == 0
    assert not output.exists()


def test_samsung_cli_rejects_input_overwrite(backup):
    assert cli.main([str(backup), "-o", str(backup)]) == 1
    assert backup.read_bytes() == b"synthetic-backup"
    cli.Prompt.ask.assert_not_called()


def test_samsung_empty_result_does_not_report_success(mocker, backup):
    mocker.patch.object(cli, "decrypt_and_parse", return_value={})
    assert cli.main([str(backup)]) == 1
    assert not backup.with_suffix(".md").exists()


def test_samsung_rejects_directory_before_password(mocker, tmp_path):
    prompt = mocker.patch.object(cli.Prompt, "ask")
    assert cli.main([str(tmp_path)]) == 1
    prompt.assert_not_called()
