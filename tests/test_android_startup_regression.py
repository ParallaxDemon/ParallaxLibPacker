"""Regression checks for Android ARM64 shared-library startup fixes.

These are source guards. CI's protected ARM64 dlopen smoke remains the runtime
validation; actual 4 KiB and 16 KiB Android devices are still required.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
FOLD = ROOT / "upx-devel/src/stub/src/amd64-linux.elf-so_main.c"
ENTRY = ROOT / "upx-devel/src/stub/src/arm64-linux.elf-so_entry.S"
REBUILD = ROOT / "scripts/rebuild-pvm4-arm64-stub.sh"
ELF64 = ROOT / "upx-devel/src/p_lx_elf.cpp"


class AndroidStartupRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fold = FOLD.read_text(encoding="utf-8")
        cls.entry = ENTRY.read_text(encoding="utf-8")
        cls.rebuild = REBUILD.read_text(encoding="utf-8")
        cls.elf64 = ELF64.read_text(encoding="utf-8")

    def test_return_uses_arm64_ret_not_indirect_jump(self):
        self.assertIn("0xd65f03c0,  // ret", self.fold)
        self.assertNotIn("0xd61f03c0,  // br x30", self.fold)

    def test_page_mask_matches_unfolded_entry_stub(self):
        self.assertIn("defined(__riscv) || defined(__aarch64__)", self.fold)
        self.assertIn("extern ElfW(Addr) get_page_mask(void);", self.fold)
        self.assertIn("defined(__powerpc__) || defined(__aarch64__)", self.fold)

    def test_android_auxv_denial_uses_kernel_probe(self):
        for requirement in (
            "b.lt .Lprobe_page_size",
            ".Lauxv_bad_close:",
            ".Lprobe_page_size:",
            "PAGE_SIZE_16K",
            "PAGE_SIZE_64K",
            "__NR_mprotect",
            "do_sys __NR_munmap",
        ):
            self.assertIn(requirement, self.entry)

    def test_both_entry_and_runtime_stubs_are_regenerated(self):
        self.assertIn(
            "arm64-linux.elf-so_entry.h arm64-linux.elf-so_fold.h",
            self.rebuild,
        )
        self.assertIn('git diff --quiet -- "$ENTRY_TARGET"', self.rebuild)

    def test_loader_errors_not_silently_successful(self):
        self.assertNotIn("exit_group(0);  // silent", self.fold)
        self.assertIn("exit_group(a ? (a & 0xff) : 127)", self.fold)
        self.assertIn("err_exit(82); // anonymous transport", self.fold)

    def test_exported_code_is_never_compressed(self):
        """Other DSOs may call our exports before DT_INIT runs.

        Android dependency constructors call exported C++ runtime symbols
        (for example _Znwm) before the protected library's DT_INIT.  Those
        definitions must stay native, otherwise the caller lands in the
        PROT_NONE convex-hull gap and dies with SIGSEGV/SEGV_ACCERR.
        """
        self.assertIn("Parallax startup safety: never compress code", self.elf64)
        self.assertIn("sec_dynsym && dynsym && pload_x0", self.elf64)
        self.assertIn("if (safe_end > xct_va && safe_end < load_end)", self.elf64)


if __name__ == "__main__":
    unittest.main()
