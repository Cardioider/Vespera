"""Regression cases use synthetic credentials only."""

import base64
import csv
import hashlib
import io
import json
from urllib.parse import quote

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from unsealer.common.exporter import DataExporter
from unsealer.google.decrypter import decrypt_google_auth_uri
from unsealer.samsung.decrypter import decrypt_and_parse, parse_decrypted_content


def migration_uri(otp_type=2, counter=0, secret=b"test-secret"):
    # A single OTP entry: secret, name, issuer, SHA1, six digits, type, counter.
    entry = (b"\x0a" + bytes([len(secret)]) + secret
             + b"\x12\x04user\x1a\x07service\x20\x01\x28\x01"
             + b"\x30" + bytes([otp_type]) + b"\x38" + bytes([counter]))
    payload = b"\x0a" + bytes([len(entry)]) + entry
    return "otpauth-migration://offline?data=" + quote(base64.b64encode(payload).decode(), safe="")


def samsung_table(headers, values):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, delimiter=";", lineterminator="\n")
    writer.writerow(headers)
    writer.writerow([base64.b64encode(v.encode()).decode() for v in values])
    return stream.getvalue()


def test_hotp_preserves_type_and_counter():
    account = decrypt_google_auth_uri(migration_uri(1, 42))[0]
    assert account.category == "hotp"
    assert account.extra["original_type"] == "HOTP"
    assert account.extra["counter"] == 42


@pytest.mark.parametrize("payload", [
    b"\x80",                       # truncated varint
    b"\x80" * 11,                  # oversized varint
    b"\x0a\x05x",                  # truncated message
    b"\x09\x00",                   # truncated fixed64
    b"\x0d\x00",                   # truncated fixed32
    b"\x0f",                       # reserved wire type
    b"\x00\x00",                   # field number zero
    b"\x0a\x02\x0a\x00",          # empty secret
    b"\x08\x01",                   # OTP entry has wrong wire type
    b"\x0a\x09\x09password",       # secret encoded as fixed64 instead of bytes
])
def test_malformed_migration_payload_is_rejected(payload):
    uri = "otpauth-migration://offline?data=" + quote(base64.b64encode(payload).decode(), safe="")
    with pytest.raises(ValueError):
        decrypt_google_auth_uri(uri)


@pytest.mark.parametrize("query", ["", "data=", "data=!!!!", "data=AA==&data=AA=="])
def test_missing_or_invalid_migration_data_is_rejected(query):
    with pytest.raises(ValueError):
        decrypt_google_auth_uri("otpauth-migration://offline?" + query)


def test_urlsafe_base64_without_padding():
    uri = migration_uri(secret=b"\xfb\xff\xff")
    from urllib.parse import unquote
    uri = unquote(uri).replace("+", "-").replace("/", "_")
    uri = uri.replace("otpauth-migration:__", "otpauth-migration://").rstrip("=")
    assert decrypt_google_auth_uri(uri)[0].secret == base64.b32encode(b"\xfb\xff\xff").decode().rstrip("=")


def test_repeated_samsung_tables_do_not_overwrite_records():
    first = samsung_table(["note_title", "note_detail"], ["first", "alpha"])
    second = samsung_table(["note_title", "note_detail"], ["second", "beta"])
    records = parse_decrypted_content(first + "next_table\n" + second)["notes"]
    assert [r["note"] for r in records] == ["alpha", "beta"]


def test_samsung_multivalue_fields_decode_each_segment():
    content = "name;telephone_number_list;email_address_list\n"
    content += "VGVzdA==;cGhvbmUx#1&&&cGhvbmUy#2;ZW1haWw=#1\n"
    record = parse_decrypted_content(content)["identities"][0]
    assert record["telephone_number_list"] == ["phone1", "phone2"]
    assert record["email_address_list"] == ["email"]


def test_samsung_extra_fields_and_otp_parameters_survive():
    content = samsung_table(
        ["title", "username_value", "password_value", "otp", "new_field"],
        ["test", "user", "password", '{"secret":"ABC","digits":8}', "keep me"],
    )
    record = parse_decrypted_content(content)["logins"][0]
    assert record["otp"]["digits"] == 8
    assert record["new_field"] == "keep me"


def test_single_column_samsung_table_is_not_dropped():
    records = parse_decrypted_content(samsung_table(["custom_field"], ["custom value"]))
    assert records["unknown_1"][0]["custom_field"] == "custom value"


def test_samsung_malformed_rows_fail_instead_of_partial_success():
    content = samsung_table(["note_title", "note_detail"], ["ok", "ok"])
    content += "extra;columns;silently-lost\n"
    with pytest.raises(ValueError):
        parse_decrypted_content(content)


def test_samsung_encryption_round_trip():
    content = samsung_table(["note_title", "note_detail"], ["Synthetic note", "hello"])
    salt, iv = bytes(range(20)), bytes(range(16))
    key = hashlib.pbkdf2_hmac("sha256", b"test-password", salt, 70000, dklen=32)
    encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(content.encode(), AES.block_size))
    backup = base64.b64encode(salt + iv + encrypted)
    assert decrypt_and_parse(backup, "test-password")["notes"][0]["note"] == "hello"
    with pytest.raises(ValueError):
        decrypt_and_parse(backup, "wrong-password")


def test_markdown_keeps_zero_and_other_named_fields(tmp_path):
    output = tmp_path / "report.md"
    DataExporter().export({"accounts": [{"title": "A", "issuer": "B", "counter": 0}]}, output, "md")
    content = output.read_text(encoding="utf-8")
    assert "Issuer" in content and "B" in content
    assert "Counter" in content and "0" in content


def test_export_unknown_format_is_an_error(tmp_path):
    with pytest.raises(ValueError):
        DataExporter().export({"accounts": [{"title": "A"}]}, tmp_path / "report.xml", "xml")


def test_export_returns_real_csv_destination(tmp_path):
    output = tmp_path / "report.csv"
    actual = DataExporter().export({"accounts": [{"title": "A"}]}, output, "csv")
    assert actual == tmp_path / "report_export"
    with (actual / "accounts.csv").open(encoding="utf-8-sig", newline="") as stream:
        assert list(csv.DictReader(stream)) == [{"title": "A"}]


def test_export_creates_nested_parent(tmp_path):
    output = tmp_path / "nested" / "report.json"
    DataExporter().export({"accounts": [{"title": "A"}]}, output, "json")
    assert json.loads(output.read_text(encoding="utf-8"))["accounts"][0]["title"] == "A"


def test_csv_table_name_cannot_escape_output_directory(tmp_path):
    with pytest.raises(ValueError):
        DataExporter().export({"../outside": [{"title": "A"}]}, tmp_path / "export", "csv")
    assert not (tmp_path / "outside.csv").exists()
