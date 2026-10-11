"""Independent known-answer and stream-boundary checks; no dependencies.

Run with `python -S check_seed.py` to exclude third-party site packages.
"""

import importlib.util
import io
import random
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from seed_ecb_core import CHUNK_SIZE, decode_value, parse_key, transform_bytes, transform_stream
from seed_ecb_tool import convert_file

VECTORS = (
    ("00000000000000000000000000000000", "000102030405060708090a0b0c0d0e0f", "5ebac6e0054e166819aff1cc6d346cdb"),
    ("000102030405060708090a0b0c0d0e0f", "00000000000000000000000000000000", "c11f22f20140505084483597e4370f43"),
    ("4706480851e61be85d74bfb3fd956185", "83a2f8a288641fb9a4e9a5cc2f131c7d", "ee54d13ebcae706d226bc3142cd40d4a"),
    ("28dbc3bc49ffd87dcfa509b11d422be7", "b41e6be2eba84a148e2eed84593c5ec7", "9b9b7bfcd1813cb95d0b3618f40f5122"),
)


class ShortReads(io.BytesIO):
    def read(self, size=-1):
        return super().read(min(size, 23))


class SeedChecks(unittest.TestCase):
    key = bytes(range(16))

    def test_rfc4269_appendix_b(self):
        for key, plain, encrypted in VECTORS:
            with self.subTest(key=key):
                key, plain, encrypted = map(bytes.fromhex, (key, plain, encrypted))
                self.assertEqual(transform_bytes(plain, key, decrypt=False, padding="none"), encrypted)
                self.assertEqual(transform_bytes(encrypted, key, decrypt=True, padding="none"), plain)

    def test_pkcs7_boundaries_and_unicode(self):
        for length in (0, 1, 15, 16, 17, 31, 32, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 17):
            with self.subTest(length=length):
                data = random.Random(length).randbytes(length)
                encrypted = transform_bytes(data, self.key, decrypt=False)
                self.assertEqual(len(encrypted), (length // 16 + 1) * 16)
                self.assertEqual(transform_bytes(encrypted, self.key, decrypt=True), data)
        data = ("123456789012345678901234567890 긴 문자열\n" * 100).encode()
        self.assertEqual(transform_bytes(transform_bytes(data, self.key, decrypt=False), self.key, decrypt=True), data)

    def test_short_reads_and_zero_padding(self):
        data = b"first" + b"\0" * (CHUNK_SIZE * 2) + b"last"
        for padding in ("pkcs7", "zero"):
            encrypted, plain = io.BytesIO(), io.BytesIO()
            transform_stream(ShortReads(data), encrypted, self.key, decrypt=False, padding=padding)
            transform_stream(ShortReads(encrypted.getvalue()), plain, self.key, decrypt=True, padding=padding)
            self.assertEqual(plain.getvalue(), data)
        encrypted = transform_bytes(b"tail\0\0", self.key, decrypt=False, padding="zero")
        self.assertEqual(transform_bytes(encrypted, self.key, decrypt=True, padding="zero"), b"tail")

    def test_invalid_length_key_and_padding(self):
        for key in (b"", b"1" * 15, b"1" * 17):
            with self.assertRaises(ValueError):
                transform_bytes(b"text", key, decrypt=False)
        for encrypted in (b"", b"1", b"1" * 17):
            with self.assertRaises(ValueError):
                transform_bytes(encrypted, self.key, decrypt=True)
        for suffix in (b"\0", b"\x11", b"\x01\x02"):
            raw = b"A" * (16 - len(suffix)) + suffix
            encrypted = transform_bytes(raw, self.key, decrypt=False, padding="none")
            with self.assertRaises(ValueError):
                transform_bytes(encrypted, self.key, decrypt=True)
        with self.assertRaises(ValueError):
            transform_bytes(b"unaligned", self.key, decrypt=False, padding="none")

    def test_atomic_output_preserves_existing_file_on_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            source, result = Path(folder) / "in.bin", Path(folder) / "out.bin"
            source.write_bytes(b"incomplete ciphertext")
            result.write_bytes(b"existing")
            with self.assertRaises(ValueError):
                convert_file(source, result, self.key, decrypt=True, padding="pkcs7")
            self.assertEqual(result.read_bytes(), b"existing")
            self.assertFalse(list(Path(folder).glob("*.part")))
            source.write_bytes(b"large digits " * 10000)
            encrypted = Path(folder) / "encrypted.bin"
            convert_file(source, encrypted, self.key, decrypt=False, padding="pkcs7")
            convert_file(encrypted, result, self.key, decrypt=True, padding="pkcs7")
            self.assertEqual(result.read_bytes(), source.read_bytes())

    def test_key_formats_and_single_file(self):
        self.assertEqual(parse_key("000102030405060708090a0b0c0d0e0f", "hex"), self.key)
        self.assertEqual(parse_key("AAECAwQFBgcICQoLDA0ODw==", "base64"), self.key)
        self.assertEqual(decode_value("12 34 56", "hex"), bytes.fromhex("123456"))
        path = Path(__file__).with_name("SEED_ECB_portable.py")
        spec = importlib.util.spec_from_file_location("seed_portable_check", path)
        portable = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(portable)
        key, plain, expected = map(bytes.fromhex, VECTORS[0])
        self.assertEqual(portable.transform_bytes(plain, key, decrypt=False, padding="none"), expected)

    def test_portable_archive_without_site_packages_or_source_files(self):
        archive = Path(__file__).with_name("downloads") / "SEED_ECB_Python_portable.zip"
        with tempfile.TemporaryDirectory() as folder:
            with zipfile.ZipFile(archive) as zipped:
                self.assertEqual(set(zipped.namelist()), {"SEED_ECB_portable.py", "시작_SEED_ECB.bat", "SEED_ECB_사용안내.txt"})
                zipped.extractall(folder)
            script = Path(folder) / "SEED_ECB_portable.py"
            result = subprocess.run(
                [sys.executable, "-I", "-S", str(script), "--cli", "--help"],
                cwd=folder, capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            probe = (
                "import runpy, sys; m=runpy.run_path(sys.argv[1]); "
                "assert m['transform_bytes'](bytes(range(16)), bytes(16), decrypt=False, padding='none').hex()"
                " == '5ebac6e0054e166819aff1cc6d346cdb'"
            )
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-c", probe, str(script)],
                cwd=folder, capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
