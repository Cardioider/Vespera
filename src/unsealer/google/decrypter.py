"""Decode Google Authenticator's migration protobuf without generated bindings."""

import base64
import binascii
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse

from unsealer.common.models import Credential


def _parse_varint(data: bytes, pos: int):
    value = 0
    for index in range(10):
        if pos >= len(data):
            raise ValueError("Truncated protobuf varint")
        byte = data[pos]
        pos += 1
        if index == 9 and byte > 1:
            raise ValueError("Protobuf varint exceeds 64 bits")
        value |= (byte & 0x7F) << (7 * index)
        if not byte & 0x80:
            return value, pos
    raise ValueError("Invalid protobuf varint")


def _parse_message(data: bytes, wire_types=None) -> Dict[int, List[Any]]:
    pos = 0
    result = {}
    while pos < len(data):
        key, pos = _parse_varint(data, pos)
        tag, wire_type = key >> 3, key & 7
        if not 0 < tag < 2 ** 29:
            raise ValueError("Invalid protobuf field number")
        if wire_types and tag in wire_types and wire_type != wire_types[tag]:
            raise ValueError("Unexpected protobuf wire type")
        if wire_type == 0:
            value, pos = _parse_varint(data, pos)
        else:
            if wire_type == 2:
                length, pos = _parse_varint(data, pos)
            elif wire_type == 1:
                length = 8
            elif wire_type == 5:
                length = 4
            else:
                raise ValueError("Unsupported protobuf wire type")
            if length > len(data) - pos:
                raise ValueError("Truncated protobuf field")
            value = data[pos:pos + length]
            pos += length
        result.setdefault(tag, []).append(value)
    return result


def _field(message, tag, default, expected_type):
    value = message.get(tag, [default])[-1]
    if not isinstance(value, expected_type):
        raise ValueError("Unexpected protobuf field type")
    return value


def decrypt_google_auth_uri(uri: str) -> List[Credential]:
    """Return complete OTP records, or reject a damaged/unsupported payload."""
    try:
        parsed_uri = urlparse(uri)
        if parsed_uri.scheme != "otpauth-migration" or parsed_uri.netloc != "offline":
            raise ValueError("Expected an otpauth-migration://offline URI")
        values = parse_qs(parsed_uri.query, keep_blank_values=True).get("data", [])
        if len(values) != 1 or not values[0]:
            raise ValueError("Expected exactly one non-empty data parameter")

        encoded_data = values[0].replace(" ", "+")
        encoded_data += "=" * (-len(encoded_data) % 4)
        payload = _parse_message(base64.b64decode(encoded_data, altchars=b"-_", validate=True),
                                 {1: 2, 2: 0, 3: 0, 4: 0, 5: 0})
        entries = payload.get(1, [])
        if not entries:
            raise ValueError("Migration payload contains no OTP accounts")

        algorithms = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}
        digits = {0: "6", 1: "6", 2: "8", 3: "7"}
        otp_types = {0: "TOTP", 1: "HOTP", 2: "TOTP"}
        results = []
        for raw_entry in entries:
            if not isinstance(raw_entry, bytes):
                raise ValueError("Invalid OTP message field")
            entry = _parse_message(raw_entry, {1: 2, 2: 2, 3: 2, 4: 0, 5: 0, 6: 0, 7: 0, 8: 2})
            secret = _field(entry, 1, b"", bytes)
            if not secret:
                raise ValueError("OTP account has no secret")
            name = _field(entry, 2, b"", bytes).decode("utf-8")
            issuer = _field(entry, 3, b"", bytes).decode("utf-8")
            algorithm = _field(entry, 4, 1, int)
            digit_count = _field(entry, 5, 1, int)
            otp_type = _field(entry, 6, 2, int)
            counter = _field(entry, 7, 0, int)
            if algorithm not in algorithms or digit_count not in digits or otp_type not in otp_types:
                raise ValueError("Unsupported OTP algorithm, digit count, or type")
            if counter >= 2 ** 63:
                raise ValueError("HOTP counter must be a non-negative int64")

            if ":" in name:
                prefix, account = name.split(":", 1)
                if not issuer or prefix.strip() == issuer:
                    issuer = issuer or prefix.strip()
                    name = account.strip()

            extra = {
                "algorithm": algorithms[algorithm],
                "digits": digits[digit_count],
                "original_type": otp_types[otp_type],
            }
            if otp_types[otp_type] == "HOTP":
                extra["counter"] = counter
            unique_id = _field(entry, 8, b"", bytes).decode("utf-8")
            if unique_id:
                extra["unique_id"] = unique_id
            results.append(Credential(
                title=issuer or name or "Google Authenticator",
                username=name,
                secret=base64.b32encode(secret).decode("ascii").rstrip("="),
                issuer=issuer,
                category=otp_types[otp_type].lower(),
                extra=extra,
            ))
        return results
    except (ValueError, TypeError, binascii.Error) as exc:
        # Never include the URI or secret bytes in terminal diagnostics.
        raise ValueError("Failed to parse migration data: invalid or unsupported payload") from exc
