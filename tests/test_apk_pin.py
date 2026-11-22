"""Native APK signer pin: host C compile, SHA-256 vectors and synthetic v2 block tests.

Synthetic fixture tests parser/identity only, NOT cryptographic APK verification.
Only an Android device can validate installed APK behavior and actual dlopen.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "upx-devel/src/stub/src/parallax_apk_cert_pin.h"

HOST_C = r"""
#define _GNU_SOURCE
#define __aarch64__ 1
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
typedef uint64_t Elf64_Addr;
#define Punmap munmap
static int parallax_parse_hex_range(
  const char *line, size_t len, Elf64_Addr *lo, Elf64_Addr *hi) {
    (void)line; (void)len; (void)lo; (void)hi; return 0;
}
long parallax_lseek(int fd, long off, int whence) {
    return (long)lseek(fd, (off_t)off, whence);
}
long parallax_pread64(int fd, void *out, size_t len, unsigned long off) {
    return (long)pread(fd, out, len, (off_t)off);
}
#include "parallax_apk_cert_pin.h"
int main(int argc,char **argv) {
    static const unsigned char sha_abc[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad };
    unsigned char digest[32];
    ParallaxPinSha sha;
    int i;
    parallax_pin_sha_init(&sha);
    parallax_pin_sha_update(&sha,(const unsigned char *)"abc",3);
    parallax_pin_sha_final(&sha,digest);
    if(memcmp(sha_abc,digest,32)!=0)return 15;
    if(argc!=3)return 16;
    if(strlen(argv[2])!=64)return 17;
    for(i=0;i<32;i++){
        unsigned x;
        if(sscanf(argv[2]+2*i,"%2x",&x)!=1)return 18;
        digest[i]=(unsigned char)x;
    }
    if(!parallax_pin_apk_file(argv[1],digest))return 19;
    (void)parallax_pin_verify_apk;
    return 0;
}
"""


def lp(data: bytes) -> bytes:
    return struct.pack("<I", len(data)) + data


def synthetic_apk(der: bytes, *, scheme: int = 0x7109871A) -> bytes:
    signed_data = lp(b"") + lp(lp(der)) + lp(b"")
    signer = lp(signed_data) + lp(b"") + lp(b"public-key")
    signers = lp(lp(signer))
    pair = struct.pack("<QI", len(signers) + 4, scheme) + signers
    size = len(pair) + 24
    block = struct.pack("<Q", size) + pair + struct.pack("<Q", size) + b"APK Sig Block 42"
    prefix = b"PK\x03\x04" + b"\0" * 26
    central = b"PK\x01\x02" + b"\0" * 42
    eocd = (b"PK\x05\x06" + b"\0" * 8 + struct.pack("<II", len(central),
            len(prefix) + len(block)) + b"\0\0")
    return prefix + block + central + eocd


class ApkPinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.name == "nt":
            raise unittest.SkipTest("POSIX mmap and pread native host harness")
        cc = shutil.which("cc") or shutil.which("gcc")
        if not cc:
            raise unittest.SkipTest("C compiler unavailable")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.root = Path(cls.tmp.name)
        c_path = cls.root / "apk_pin_host.c"
        c_path.write_text(HOST_C, encoding="utf-8")
        cls.binary = cls.root / "apk_pin_host"
        subprocess.run([cc, "-std=c11", "-O2", "-Wall", "-Wextra",
                        "-Wno-unused-function", "-I", str(SRC.parent),
                        str(c_path), "-o", str(cls.binary)], check=True)

    def check(self, apk: bytes, digest: bytes) -> int:
        path = self.root / "test.apk"
        path.write_bytes(apk)
        return subprocess.run([str(self.binary), str(path), digest.hex()],
                              capture_output=True, check=False).returncode

    def test_matching_cert(self):
        cert = b"\x30\x03\x02\x01\x01"
        self.assertEqual(self.check(synthetic_apk(cert), hashlib.sha256(cert).digest()), 0)

    def test_mismatched_cert(self):
        cert = b"\x30\x03\x02\x01\x01"
        self.assertNotEqual(self.check(synthetic_apk(cert), hashlib.sha256(b"different").digest()), 0)

    def test_v3_signing_block(self):
        cert = b"\x30\x03\x02\x01\x02"
        self.assertEqual(self.check(synthetic_apk(cert, scheme=0xF05368C0),
                                    hashlib.sha256(cert).digest()), 0)

    def test_truncated_and_unsigned(self):
        cert = b"\x30\x03\x02\x01\x01"
        digest = hashlib.sha256(cert).digest()
        self.assertNotEqual(self.check(synthetic_apk(cert)[:-30], digest), 0)
        self.assertNotEqual(self.check(b"PK\x05\x06" + b"\0" * 18, digest), 0)


if __name__ == "__main__":
    unittest.main()
