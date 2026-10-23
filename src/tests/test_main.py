import sys

import pytest

from unsealer.__main__ import main


@pytest.mark.parametrize("command", ["samsung", "google"])
def test_main_dispatches_arguments_and_status(mocker, command):
    handler = mocker.patch(f"unsealer.{command}.cli.main", return_value=1)
    assert main([command, "input", "--preview"]) == 1
    handler.assert_called_once_with(["input", "--preview"])


def test_global_help_needs_no_optional_dependencies(mocker):
    mocker.patch.dict(sys.modules, {"pyzbar": None, "pyzbar.pyzbar": None})
    with pytest.raises(SystemExit) as error:
        main(["--help"])
    assert error.value.code == 0


def test_uri_input_works_without_zbar(mocker):
    mocker.patch.dict(sys.modules, {"pyzbar": None, "pyzbar.pyzbar": None})
    uri = "otpauth-migration://offline?data=ChkKCHBhc3N3b3JkEgR1c2VyGgdzZXJ2aWNl"
    assert main(["google", uri, "--preview"]) == 0
