import json
import sys

import pytest

from unsealer.google import cli

URI = "otpauth-migration://offline?data=ChkKCHBhc3N3b3JkEgR1c2VyGgdzZXJ2aWNl"


def test_google_cli_deduplication_and_export(tmp_path):
    output = tmp_path / "report.json"
    assert cli.main([URI, URI, "-o", str(output)]) == 0
    accounts = json.loads(output.read_text(encoding="utf-8"))["google_authenticator"]
    assert len(accounts) == 1
    assert accounts[0]["username"] == "user"
    assert accounts[0]["secret"]


def test_google_cli_interactive_mode(mocker):
    mocker.patch.object(sys.stdin, "isatty", return_value=True)
    prompt = mocker.patch.object(cli.Prompt, "ask", side_effect=[URI, ""])
    assert cli.main([]) == 0
    assert prompt.call_count == 2


def test_invalid_explicit_input_does_not_prompt(mocker, tmp_path):
    prompt = mocker.patch.object(cli.Prompt, "ask", side_effect=AssertionError("Unexpected prompt"))
    output = tmp_path / "report.json"
    assert cli.main([str(tmp_path / "missing.json"), "-o", str(output)]) == 1
    prompt.assert_not_called()
    assert not output.exists()


def test_noninteractive_empty_input_exits(mocker):
    mocker.patch.object(sys.stdin, "isatty", return_value=False)
    assert cli.main([]) == 1


def test_preview_never_exports(tmp_path):
    output = tmp_path / "report.json"
    assert cli.main([URI, "--preview", "-o", str(output)]) == 0
    assert not output.exists()


def test_one_failed_input_prevents_partial_export(tmp_path):
    output = tmp_path / "report.json"
    assert cli.main([URI, "otpauth-migration://offline?data=!!!!", "-o", str(output)]) == 1
    assert not output.exists()


def test_json_list_and_extra_round_trip(tmp_path):
    source = tmp_path / "input.JSON"
    source.write_text(json.dumps([
        {"title": "A", "username": "alice", "secret": "ABC", "extra": {"counter": 0}},
        {"title": "B", "username": "bob", "secret": "ABC", "algorithm": "SHA256"},
        {"title": "B", "username": "bob", "secret": "ABC", "algorithm": "SHA256"},
    ]), encoding="utf-8")
    output = tmp_path / "output.json"
    assert cli.main([str(source), "-o", str(output)]) == 0
    accounts = json.loads(output.read_text(encoding="utf-8"))["google_authenticator"]
    assert len(accounts) == 2
    assert accounts[0]["counter"] == 0
    assert accounts[1]["algorithm"] == "SHA256"
    second_output = tmp_path / "second.json"
    assert cli.main([str(output), "-o", str(second_output)]) == 0
    assert json.loads(second_output.read_text(encoding="utf-8"))["google_authenticator"] == accounts


@pytest.mark.parametrize("content", [
    "{", "null", "42", "[]", "[null]", '{"google_authenticator":{}}',
    '[{"title":"A","secret":123}]', '[{"title":"A","secret":"ABC","extra":"invalid"}]',
    '[{"title":"A","secret":"ABC","extra":[]}]',
])
def test_bad_json_returns_failure(tmp_path, content):
    source = tmp_path / "bad.json"
    source.write_text(content, encoding="utf-8")
    assert cli.main([str(source)]) == 1


def test_json_input_is_not_overwritten(tmp_path):
    source = tmp_path / "input.json"
    original = '[{"title":"A","secret":"ABC"}]'
    source.write_text(original, encoding="utf-8")
    assert cli.main([str(source), "-o", str(source)]) == 1
    assert source.read_text(encoding="utf-8") == original


def test_export_error_returns_failure(tmp_path):
    blocked = tmp_path / "file"
    blocked.write_text("existing", encoding="utf-8")
    assert cli.main([URI, "-o", str(blocked / "report.json")]) == 1
    assert blocked.read_text(encoding="utf-8") == "existing"


def test_unknown_output_extension_is_rejected(tmp_path):
    with pytest.raises(SystemExit) as error:
        cli.main([URI, "-o", str(tmp_path / "report.xml")])
    assert error.value.code == 2
