"""SEED-128 ECB using only the Python standard library.

The SEED key is always 16 bytes. Input length is limited only by available
storage/memory; file transformation reads in chunks. The independent Python
implementation follows RFC 4269, including its S-box constants:
https://www.rfc-editor.org/rfc/rfc4269.html
"""

from __future__ import annotations

import base64
import binascii
import io
import re
import struct
from collections.abc import Callable
from typing import BinaryIO

BLOCK_SIZE = 16
CHUNK_SIZE = 64 * 1024
FORMATS = ("utf8", "hex", "base64")
PADDINGS = ("pkcs7", "none", "zero")

# RFC 4269, Appendix A.1: the two fixed 8-bit substitution tables.
_S0 = bytes.fromhex("""
A9 85 D6 D3 54 1D AC 25 5D 43 18 1E 51 FC CA 63 28
44 20 9D E0 E2 C8 17 A5 8F 03 7B BB 13 D2 EE 70 8C
3F A8 32 DD F6 74 EC 95 0B 57 5C 5B BD 01 24 1C 73
98 10 CC F2 D9 2C E7 72 83 9B D1 86 C9 60 50 A3 EB
0D B6 9E 4F B7 5A C6 78 A6 12 AF D5 61 C3 B4 41 52
7D 8D 08 1F 99 00 19 04 53 F7 E1 FD 76 2F 27 B0 8B
0E AB A2 6E 93 4D 69 7C 09 0A BF EF F3 C5 87 14 FE
64 DE 2E 4B 1A 06 21 6B 66 02 F5 92 8A 0C B3 7E D0
7A 47 96 E5 26 80 AD DF A1 30 37 AE 36 15 22 38 F4
A7 45 4C 81 E9 84 97 35 CB CE 3C 71 11 C7 89 75 FB
DA F8 94 59 82 C4 FF 49 39 67 C0 CF D7 B8 0F 8E 42
23 91 6C DB A4 34 F1 48 C2 6F 3D 2D 40 BE 3E BC C1
AA BA 4E 55 3B DC 68 7F 9C D8 4A 56 77 A0 ED 46 B5
2B 65 FA E3 B9 B1 9F 5E F9 E6 B2 31 EA 6D 5F E4 F0
CD 88 16 3A 58 D4 62 29 07 33 E8 1B 05 79 90 6A 2A
9A
""")
_S1 = bytes.fromhex("""
38 E8 2D A6 CF DE B3 B8 AF 60 55 C7 44 6F 6B 5B C3
62 33 B5 29 A0 E2 A7 D3 91 11 06 1C BC 36 4B EF 88
6C A8 17 C4 16 F4 C2 45 E1 D6 3F 3D 8E 98 28 4E F6
3E A5 F9 0D DF D8 2B 66 7A 27 2F F1 72 42 D4 41 C0
73 67 AC 8B F7 AD 80 1F CA 2C AA 34 D2 0B EE E9 5D
94 18 F8 57 AE 08 C5 13 CD 86 B9 FF 7D C1 31 F5 8A
6A B1 D1 20 D7 02 22 04 68 71 07 DB 9D 99 61 BE E6
59 DD 51 90 DC 9A A3 AB D0 81 0F 47 1A E3 EC 8D BF
96 7B 5C A2 A1 63 23 4D C8 9E 9C 3A 0C 2E BA 6E 9F
5A F2 92 F3 49 78 CC 15 FB 70 75 7F 35 10 03 64 6D
C6 74 D5 B4 EA 09 76 19 FE 40 12 E0 BD 05 FA 01 F0
2A 5E A9 56 43 85 14 89 9B B0 E5 48 79 97 FC 1E 82
21 8C 1B 5F 77 54 B2 1D 25 4F 00 46 ED 58 52 EB 7E
DA C9 FD 30 95 65 3C B6 E4 BB 7C 0E 50 39 26 32 84
69 93 37 E7 24 A4 CB 53 0A 87 D9 4C 83 8F CE 3B 4A
B7
""")

# Section 2.2 derives the extended lookup tables from the two S-boxes.
_SS0 = tuple(((s & 0x3F) << 24) | ((s & 0xCF) << 16) | ((s & 0xF3) << 8) | (s & 0xFC) for s in _S0)
_SS1 = tuple(((s & 0xFC) << 24) | ((s & 0x3F) << 16) | ((s & 0xCF) << 8) | (s & 0xF3) for s in _S1)
_SS2 = tuple(((s << 16) | (s >> 16)) & 0xFFFFFFFF for s in _SS0)
_SS3 = tuple(((s << 16) | (s >> 16)) & 0xFFFFFFFF for s in _SS1)
_MASK = 0xFFFFFFFF
_WORDS = struct.Struct(">4I")


def _g(value: int) -> int:
    return _SS0[value & 255] ^ _SS1[(value >> 8) & 255] ^ _SS2[(value >> 16) & 255] ^ _SS3[(value >> 24) & 255]


class SeedECB:
    """SEED's 16 rounds with the round keys reversed for decryption."""

    def __init__(self, key: bytes, *, decrypt: bool = False) -> None:
        if len(key) != BLOCK_SIZE:
            raise ValueError("SEED 키는 정확히 16바이트여야 합니다.")
        a, b, c, d = _WORDS.unpack(key)
        constant = 0x9E3779B9
        round_keys = []
        for index in range(16):
            round_keys.append((_g((a + c - constant) & _MASK), _g((b - d + constant) & _MASK)))
            if index % 2 == 0:
                a, b = ((a >> 8) | (b << 24)) & _MASK, ((b >> 8) | (a << 24)) & _MASK
            else:
                c, d = ((c << 8) | (d >> 24)) & _MASK, ((d << 8) | (c >> 24)) & _MASK
            constant = ((constant << 1) | (constant >> 31)) & _MASK
        self.round_keys = tuple(reversed(round_keys)) if decrypt else tuple(round_keys)

    def transform(self, data: bytes) -> bytes:
        if len(data) % BLOCK_SIZE:
            raise ValueError("블록 입력은 16바이트의 배수여야 합니다.")
        output = bytearray(len(data))
        g, mask, words = _g, _MASK, _WORDS
        for offset in range(0, len(data), BLOCK_SIZE):
            l0, l1, r0, r1 = words.unpack_from(data, offset)
            for k0, k1 in self.round_keys:
                t0 = r0 ^ k0
                t1 = g(t0 ^ r1 ^ k1)
                t0 = g((t0 + t1) & mask)
                t1 = g((t1 + t0) & mask)
                t0 = (t0 + t1) & mask
                l0, l1, r0, r1 = r0, r1, l0 ^ t0, l1 ^ t1
            words.pack_into(output, offset, r0, r1, l0, l1)
        return bytes(output)


def decode_value(value: str, fmt: str) -> bytes:
    """Read a UTF-8, hexadecimal, or Base64 value without silently truncating."""
    if fmt == "utf8":
        return value.encode("utf-8")
    if fmt == "hex":
        compact = re.sub(r"0x|[\s:,_-]", "", value, flags=re.IGNORECASE)
        if len(compact) % 2 or not re.fullmatch(r"[0-9a-fA-F]*", compact):
            raise ValueError("Hex 값은 두 자리씩 이루어진 16진수여야 합니다.")
        return bytes.fromhex(compact)
    if fmt == "base64":
        compact = re.sub(r"\s", "", value).replace("-", "+").replace("_", "/")
        if not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", compact) or len(compact) % 4 == 1:
            raise ValueError("Base64 형식을 확인하세요.")
        if "=" in compact and len(compact) % 4:
            raise ValueError("Base64 패딩(=) 위치를 확인하세요.")
        compact += "=" * (-len(compact) % 4)
        try:
            return base64.b64decode(compact, validate=True)
        except binascii.Error as exc:
            raise ValueError("Base64를 해석할 수 없습니다.") from exc
    raise ValueError("지원하지 않는 입력 형식입니다.")


def encode_value(data: bytes, fmt: str) -> str:
    if fmt == "utf8":
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("결과가 UTF-8 문자열이 아닙니다. Hex 또는 Base64로 표시하세요.") from exc
    if fmt == "hex":
        return data.hex()
    if fmt == "base64":
        return base64.b64encode(data).decode("ascii")
    raise ValueError("지원하지 않는 출력 형식입니다.")


def parse_key(value: str, fmt: str) -> bytes:
    key = decode_value(value, fmt)
    if len(key) != BLOCK_SIZE:
        raise ValueError(f"SEED 키는 정확히 16바이트여야 합니다. 현재 {len(key)}바이트입니다.")
    return key


def _write_zeros(destination: BinaryIO, count: int) -> int:
    zero_chunk = b"\x00" * CHUNK_SIZE
    written = 0
    while count:
        part = min(count, CHUNK_SIZE)
        destination.write(zero_chunk[:part])
        written += part
        count -= part
    return written


def transform_stream(
    source: BinaryIO,
    destination: BinaryIO,
    key: bytes,
    *,
    decrypt: bool,
    padding: str = "pkcs7",
    progress: Callable[[int], None] | None = None,
) -> tuple[int, int]:
    """Transform a binary stream, returning (input_bytes, output_bytes)."""
    if len(key) != BLOCK_SIZE:
        raise ValueError("SEED 키는 정확히 16바이트여야 합니다.")
    if padding not in PADDINGS:
        raise ValueError("지원하지 않는 패딩입니다.")

    cipher = SeedECB(key, decrypt=decrypt)
    buffer = b""
    input_count = output_count = pending_zero_count = 0

    def write_plain(plain: bytes) -> None:
        nonlocal output_count, pending_zero_count
        if not plain:
            return
        if padding == "zero":
            kept = plain.rstrip(b"\x00")
            if kept:
                output_count += _write_zeros(destination, pending_zero_count)
                pending_zero_count = 0
                destination.write(kept)
                output_count += len(kept)
            pending_zero_count += len(plain) - len(kept)
        else:
            destination.write(plain)
            output_count += len(plain)

    while True:
        chunk = source.read(CHUNK_SIZE)
        if not chunk:
            break
        input_count += len(chunk)
        buffer += chunk
        ready_length = len(buffer) // BLOCK_SIZE * BLOCK_SIZE
        # Keep the final ciphertext block for validation before PKCS#7 removal.
        if decrypt and padding == "pkcs7" and ready_length:
            ready_length -= BLOCK_SIZE
        ready, buffer = buffer[:ready_length], buffer[ready_length:]
        transformed = cipher.transform(ready)
        if decrypt:
            write_plain(transformed)
        else:
            destination.write(transformed)
            output_count += len(transformed)
        if progress is not None:
            progress(input_count)

    if decrypt:
        if input_count % BLOCK_SIZE or (padding == "pkcs7" and input_count == 0):
            raise ValueError("ECB 암호문 길이는 16바이트의 배수여야 합니다.")
        if padding == "pkcs7":
            tail = cipher.transform(buffer)
            count = tail[-1]
            if not 1 <= count <= BLOCK_SIZE or tail[-count:] != bytes([count]) * count:
                raise ValueError("PKCS#7 패딩이 맞지 않습니다. 키와 패딩 설정을 확인하세요.")
            write_plain(tail[:-count])
    else:
        if padding == "none" and buffer:
            raise ValueError("패딩 없음은 입력 길이가 16바이트의 배수여야 합니다.")
        tail = buffer
        if padding == "pkcs7":
            count = BLOCK_SIZE - len(tail)
            tail += bytes([count]) * count
        elif padding == "zero" and tail:
            tail += b"\x00" * (BLOCK_SIZE - len(tail))
        final_bytes = cipher.transform(tail)
        destination.write(final_bytes)
        output_count += len(final_bytes)
    return input_count, output_count


def transform_bytes(data: bytes, key: bytes, *, decrypt: bool, padding: str = "pkcs7") -> bytes:
    output = io.BytesIO()
    transform_stream(io.BytesIO(data), output, key, decrypt=decrypt, padding=padding)
    return output.getvalue()
