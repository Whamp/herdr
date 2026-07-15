import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SUPPORTED_TARGETS = 'any(target_os = "linux", target_os = "macos")'


class RemoteLinkPlatformGateTests(unittest.TestCase):
    def test_forwarding_module_compiles_only_for_linux_and_macos(self) -> None:
        source = (ROOT / "src/remote.rs").read_text()
        declaration = (
            f"#[cfg({SUPPORTED_TARGETS})]\n"
            "pub(crate) mod forwarding;"
        )

        self.assertIn(declaration, source)
        self.assertEqual(source.count("mod forwarding;"), 1)

    def test_unsupported_platform_adapter_fails_forwarding_closed(self) -> None:
        source = (ROOT / "src/platform/mod.rs").read_text()
        adapter = re.compile(
            rf'#\[cfg\(not\({re.escape(SUPPORTED_TARGETS)}\)\)\]\n'
            r'pub\(crate\) fn adopt_inherited_forwarding_capability\([\s\S]*?\n'
            r'\s*Ok\(crate::external_open::ExternalOpenForwarding::Unavailable\)\n'
            r'}'
        )

        self.assertRegex(source, adapter)


if __name__ == "__main__":
    unittest.main()
