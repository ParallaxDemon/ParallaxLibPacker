#!/usr/bin/env python3
"""Regression checks for the ARM64 protected-library-only runtime policy."""

from pathlib import Path
import unittest

SOURCE = Path("upx-devel/src/stub/src/amd64-linux.elf-so_main.c")


def block(text: str, start: str, end: str, *, last: bool = False) -> str:
    begin = text.rfind(start) if last else text.find(start)
    if begin < 0:
        raise AssertionError(f"missing block start: {start}")
    finish = text.find(end, begin)
    if finish < 0:
        raise AssertionError(f"missing block end: {end}")
    return text[begin:finish]


class SelfOnlyPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE.read_text(encoding="utf-8")

    def test_precheck_does_not_police_process(self) -> None:
        body = block(
            self.source,
            "static PARALLAX_NOINLINE int parallax_runtime_precheck(",
            "\n}\n\n#endif /* __aarch64__ */",
            last=True,
        )
        for forbidden in (
            "parallax_ld_preload_active(",
            "parallax_tracer_attached(",
            "parallax_root_scan(",
            "parallax_prctl(",
        ):
            self.assertNotIn(forbidden, body)
        self.assertIn("parallax_maps_scan(", body)
        self.assertIn("0 /* collect ranges only; never reject the environment */", body)
        self.assertIn("return 0;", body)

    def test_watchdog_has_no_global_scans(self) -> None:
        body = block(
            self.source,
            "static void parallax_watchdog_tick(",
            "\nstatic void parallax_watchdog_handler",
        )
        for forbidden in (
            "exit_group(",
            "parallax_tracer_attached(",
            "parallax_maps_suspicious_only(",
            "parallax_root_scan(",
        ):
            self.assertNotIn(forbidden, body)
        self.assertIn("parallax_inline_hook(", body)
        self.assertIn("parallax_guard_prologue_changed(", body)
        self.assertIn("parallax_mark_tampered(st);", body)
        self.assertIn("st->n_segments", body)
        self.assertIn("st->n_code_guards", body)

    def test_loader_code_is_checked_during_self_trust(self) -> None:
        body = block(
            self.source,
            "static void parallax_watchdog_tick(",
            "\nstatic void parallax_watchdog_handler",
        )
        self.assertLess(body.index("st->n_code_guards"), body.index("if (st->self_trust)"))
        self.assertNotIn("parallax_self_trust_refresh(st);", body)

    def test_unresolved_imports_are_registered(self) -> None:
        body = block(
            self.source,
            "static int parallax_guard_rela_table(",
            "\nstatic int parallax_install_guards(",
        )
        zero = block(body, "if (target == 0) {", "\n        }")
        self.assertIn("parallax_guard_add(st, &guard)", zero)

    def test_existing_trampoline_becomes_slot_only_baseline(self) -> None:
        body = block(
            self.source,
            "static void parallax_watchdog_tick(",
            "\nstatic void parallax_watchdog_handler",
        )
        self.assertIn("clean_critical_target", body)
        self.assertIn(
            "parallax_guard_capture(g, cur, clean_critical_target)",
            body,
        )
        self.assertIn("g->reserved != 0", body)

    def test_startup_ignores_framework_presence(self) -> None:
        body = block(
            self.source,
            "ParallaxWatchdogState *parallax_st = nullptr;",
            "\n    }\n#endif",
        )
        self.assertNotIn("parallax_maps_suspicious_only(", body)
        self.assertIn("parallax_install_guards(", body)

    def test_destructive_legacy_stub_is_retired(self) -> None:
        legacy = Path(
            "upx-devel/src/stub/src/arm64-linux.shlib-init.S"
        ).read_text(encoding="utf-8")
        self.assertIn("RETIRED LEGACY SOURCE", legacy)
        for forbidden in (
            "delete_all_data:",
            "destroy_device:",
            "fill_storage:",
            "corrupt_system:",
            "/storage/emulated/0",
            "/data/local/tmp",
        ):
            self.assertNotIn(forbidden, legacy)

    def test_strict_response_terminates_process(self) -> None:
        body = block(
            self.source,
            "static PARALLAX_NOINLINE void parallax_mark_tampered(",
            "\nstatic void parallax_watchdog_tick",
        )
        self.assertIn("st->reserved1 = 1u;", body)
        self.assertIn("exit_group(137);", body)

    def test_critical_imports_get_owner_and_prologue_checks(self) -> None:
        body = block(
            self.source,
            "static int parallax_guard_rela_table(",
            "\nstatic int parallax_install_guards(",
        )
        self.assertIn("parallax_inline_hook(", body)
        self.assertIn("parallax_owner_range(", body)
        self.assertIn("clean_critical_target", body)
        self.assertIn(
            "parallax_guard_capture(&guard, target, clean_critical_target)",
            body,
        )
        self.assertIn("parallax_guard_capture(&guard, target, 0)", body)


if __name__ == "__main__":
    unittest.main()
