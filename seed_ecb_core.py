"""SEED-128 ECB interoperability helpers with streaming padding handling.

The SEED key is always 16 bytes. Input length is limited only by available
storage/memory; file transformation reads in chunks.
"""

from __future__ import annotations

import base64
import binascii
import io
import re
from collections.abc import Callable
from typing import BinaryIO

from cryptography.hazmat.decrepit.ciphers.algorithms import SEED
from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.primitives.ciphers import Cipher, modes

BLOCK_SIZE = 16
CHUNK_SIZE = 1024 * 1024
FORMATS = ("utf8", "hex", "base64")
PADDINGS = ("pkcs7", "none", "zero")


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

    cipher = Cipher(SEED(key), modes.ECB())
    context = cipher.decryptor() if decrypt else cipher.encryptor()
    padder = sympadding.PKCS7(128).padder() if not decrypt and padding == "pkcs7" else None
    unpadder = sympadding.PKCS7(128).unpadder() if decrypt and padding == "pkcs7" else None
    input_count = output_count = pending_zero_count = 0

    def write_plain(plain: bytes) -> None:
        nonlocal output_count, pending_zero_count
        if not plain:
            return
        if unpadder is not None:
            ready = unpadder.update(plain)
            destination.write(ready)
            output_count += len(ready)
        elif padding == "zero":
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
        if decrypt:
            write_plain(context.update(chunk))
        else:
            ready = padder.update(chunk) if padder is not None else chunk
            encrypted = context.update(ready)
            destination.write(encrypted)
            output_count += len(encrypted)
        if progress is not None:
            progress(input_count)

    if decrypt:
        if input_count == 0 or input_count % BLOCK_SIZE:
            raise ValueError("ECB 암호문 길이는 16바이트의 배수여야 합니다.")
        write_plain(context.finalize())
        if unpadder is not None:
            try:
                tail = unpadder.finalize()
            except ValueError as exc:
                raise ValueError("PKCS#7 패딩이 맞지 않습니다. 키와 패딩 설정을 확인하세요.") from exc
            destination.write(tail)
            output_count += len(tail)
    else:
        if padding == "none" and input_count % BLOCK_SIZE:
            raise ValueError("패딩 없음은 입력 길이가 16바이트의 배수여야 합니다.")
        tail = padder.finalize() if padder is not None else b""
        if padding == "zero":
            tail = b"\x00" * (-input_count % BLOCK_SIZE)
        final_bytes = context.update(tail) + context.finalize()
        destination.write(final_bytes)
        output_count += len(final_bytes)
    return input_count, output_count


def transform_bytes(data: bytes, key: bytes, *, decrypt: bool, padding: str = "pkcs7") -> bytes:
    output = io.BytesIO()
    transform_stream(io.BytesIO(data), output, key, decrypt=decrypt, padding=padding)
    return output.getvalue()
