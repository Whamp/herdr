import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "install-port-forward-test.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "remote-link-test-release.yml"
GUIDE = ROOT / ".github" / "remote-link-test-guide.md"


class PortForwardInstallerCliTests(unittest.TestCase):
    def run_installer(
        self, *args: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(INSTALLER), *args],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_help_describes_generic_optional_remote_target(self) -> None:
        result = self.run_installer("--help")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--remote <ssh-target>", result.stdout)
        self.assertIn("herdr-port-forward", result.stdout)
        self.assertNotIn("desktop", result.stdout.lower())

    def test_remote_requires_a_target(self) -> None:
        result = self.run_installer("--remote")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--remote requires an SSH target", result.stderr)

    def test_remote_rejects_an_option_like_target_before_network_work(self) -> None:
        result = self.run_installer("--remote", "-oProxyCommand=unsafe")

        self.assertEqual(result.returncode, 2)
        self.assertIn("SSH target must not start with '-'", result.stderr)

    def test_installs_verified_local_artifact_without_replacing_stable_herdr(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            curl_log = root / "curl.log"
            curl = fake_bin / "curl"
            curl.write_text(
                "#!/bin/sh\n"
                "out=\n"
                "url=\n"
                "while [ $# -gt 0 ]; do\n"
                "  case $1 in\n"
                "    -o) out=$2; shift 2 ;;\n"
                "    http*) url=$1; shift ;;\n"
                "    *) shift ;;\n"
                "  esac\n"
                "done\n"
                f"printf '%s\\n' \"$url\" >> {curl_log}\n"
                "case $url in\n"
                "  *.sha256) printf 'test-hash  herdr-port-forward-linux-x86_64\\n' > \"$out\" ;;\n"
                "  *) cat > \"$out\" <<'EOF'\n"
                "#!/bin/sh\n"
                "printf '%s\\n' '{\"version\":\"0.7.3-port-forward-test.test\",\"protocol\":17}'\n"
                "EOF\n"
                "     chmod 755 \"$out\" ;;\n"
                "esac\n"
            )
            curl.chmod(0o755)
            checksum_log = root / "checksum.log"
            sha256sum = fake_bin / "sha256sum"
            sha256sum.write_text(
                "#!/bin/sh\n"
                f"printf '%s\\n' \"$@\" > {checksum_log}\n"
                "exit 0\n"
            )
            sha256sum.chmod(0o755)
            env = os.environ.copy()
            env["HOME"] = str(root / "home")
            env["PATH"] = f"{fake_bin}:{env['PATH']}"

            result = self.run_installer(env=env)

            self.assertEqual(result.returncode, 0, result.stderr)
            installed = root / "home" / ".local" / "bin" / "herdr-port-forward"
            self.assertTrue(installed.exists())
            self.assertTrue(installed.stat().st_mode & 0o111)
            self.assertFalse((root / "home" / ".local" / "bin" / "herdr").exists())
            urls = curl_log.read_text().splitlines()
            self.assertTrue(urls[0].endswith("herdr-port-forward-linux-x86_64"))
            self.assertTrue(urls[1].endswith("herdr-port-forward-linux-x86_64.sha256"))
            self.assertIn("-c", checksum_log.read_text().splitlines())
            self.assertIn('"protocol":17', result.stdout)

    def test_remote_install_streams_matching_artifact_to_arbitrary_ssh_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            curl_log = root / "curl.log"
            curl = fake_bin / "curl"
            curl.write_text(
                "#!/bin/sh\n"
                "out=\n"
                "url=\n"
                "while [ $# -gt 0 ]; do\n"
                "  case $1 in\n"
                "    -o) out=$2; shift 2 ;;\n"
                "    http*) url=$1; shift ;;\n"
                "    *) shift ;;\n"
                "  esac\n"
                "done\n"
                f"printf '%s\\n' \"$url\" >> {curl_log}\n"
                "case $url in\n"
                "  *.sha256) printf 'test-hash  %s\\n' \"${url##*/}\" | sed 's/.sha256$//' > \"$out\" ;;\n"
                "  *) cat > \"$out\" <<'EOF'\n"
                "#!/bin/sh\n"
                "printf '%s\\n' '{\"version\":\"0.7.3-port-forward-test.test\",\"protocol\":17}'\n"
                "EOF\n"
                "     chmod 755 \"$out\" ;;\n"
                "esac\n"
            )
            curl.chmod(0o755)
            sha256sum = fake_bin / "sha256sum"
            sha256sum.write_text("#!/bin/sh\nexit 0\n")
            sha256sum.chmod(0o755)
            ssh_log = root / "ssh.log"
            remote_binary = root / "remote-herdr-port-forward"
            ssh = fake_bin / "ssh"
            ssh.write_text(
                "#!/bin/sh\n"
                f"printf '%s\\n' \"$1\" >> {ssh_log}\n"
                "case ${2:-} in\n"
                "  'uname -s; uname -m') printf 'Darwin\\narm64\\n' ;;\n"
                "  *'status client --json'*) printf '%s\\n' '{\"version\":\"0.7.3-port-forward-test.test\",\"protocol\":17}' ;;\n"
                f"  *) cat > {remote_binary} ;;\n"
                "esac\n"
            )
            ssh.chmod(0o755)
            env = os.environ.copy()
            env["HOME"] = str(root / "home")
            env["PATH"] = f"{fake_bin}:{env['PATH']}"

            result = self.run_installer(
                "--remote", "other-user@remote.example", env=env
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(remote_binary.exists())
            self.assertIn(
                "herdr-port-forward-macos-aarch64",
                "\n".join(curl_log.read_text().splitlines()),
            )
            self.assertEqual(
                set(ssh_log.read_text().splitlines()), {"other-user@remote.example"}
            )
            self.assertIn("Installed remote", result.stdout)
            self.assertIn('"protocol":17', result.stdout)

    def test_release_workflow_publishes_only_linux_and_macos_alias_builds(self) -> None:
        workflow = WORKFLOW.read_text()

        self.assertIn("HERDR_BUILD_INSTALL_NAME: herdr-port-forward", workflow)
        self.assertIn("HERDR_BUILD_CHANNEL: port-forward-test", workflow)
        self.assertIn("test/remote-link-distribution", workflow)
        self.assertIn("github.repository == 'Whamp/herdr'", workflow)
        self.assertIn("remote-link-externalization-test", workflow)
        for artifact in (
            "herdr-port-forward-linux-x86_64",
            "herdr-port-forward-linux-aarch64",
            "herdr-port-forward-macos-x86_64",
            "herdr-port-forward-macos-aarch64",
        ):
            self.assertIn(artifact, workflow)
        self.assertNotIn("herdr-port-forward-windows", workflow)
        self.assertNotIn("windows-latest", workflow)
        self.assertIn("install-port-forward-test.sh", workflow)
        self.assertIn("--notes-file .github/remote-link-test-guide.md", workflow)
        self.assertIn(".sha256", workflow)
        self.assertNotIn("desktop", workflow.lower())

    def test_guide_uses_placeholders_and_an_isolated_session(self) -> None:
        guide = GUIDE.read_text()

        self.assertIn("--remote <ssh-target>", guide)
        self.assertIn("--session port-forward-test", guide)
        self.assertIn("~/.local/bin/herdr-port-forward", guide)
        self.assertNotIn("desktop", guide.lower())
        self.assertNotIn("windows", guide.lower())

    def test_dry_run_plans_local_and_arbitrary_remote_platforms_without_installing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            ssh_log = root / "ssh.log"
            ssh = fake_bin / "ssh"
            ssh.write_text(
                "#!/bin/sh\n"
                f"printf '%s\\n' \"$@\" > {ssh_log}\n"
                "printf 'Darwin\\narm64\\n'\n"
            )
            ssh.chmod(0o755)
            env = os.environ.copy()
            env["HOME"] = str(root / "home")
            env["PATH"] = f"{fake_bin}:{env['PATH']}"

            result = self.run_installer(
                "--dry-run",
                "--remote",
                "tester@example.internal",
                env=env,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("herdr-port-forward-linux-x86_64", result.stdout)
            self.assertIn("herdr-port-forward-macos-aarch64", result.stdout)
            self.assertIn("tester@example.internal", result.stdout)
            self.assertEqual(
                ssh_log.read_text().splitlines()[0], "tester@example.internal"
            )
            self.assertFalse((root / "home" / ".local" / "bin").exists())


if __name__ == "__main__":
    unittest.main()
