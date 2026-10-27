#!/usr/bin/env python3
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SETUP = ROOT / "git-setup"
MOCK_GH = r'''
using System;
using System.IO;
using System.Text;

public class MockGh
{
    public static int Main(string[] args)
    {
        string command = "<" + String.Join("> <", args) + ">";
        File.AppendAllText(
            Environment.GetEnvironmentVariable("MOCK_LOG"),
            command + Environment.NewLine, Encoding.UTF8);
        if (args.Length < 2) return 1;
        if (args[0] == "repo" && args[1] == "view")
        {
            File.AppendAllText(Environment.GetEnvironmentVariable("MOCK_LOG"),
                "cwd=" + Environment.CurrentDirectory + Environment.NewLine, Encoding.UTF8);
            Console.WriteLine("example/repo");
            return 0;
        }
        if (args[0] == "label" && args[1] == "create")
            return Environment.GetEnvironmentVariable("MOCK_FAIL") == "label" ? 1 : 0;
        if (args[0] != "api") return 1;
        if (args[1].Contains("/labels/")) return 1;
        if (args[1].Contains("/branches?"))
        {
            string develop = Environment.GetEnvironmentVariable("MOCK_DEVELOP");
            if (develop == "present" || develop == "partial-error")
                Console.WriteLine("develop");
            if (develop == "present" || develop == "absent") return 0;
            Console.Error.WriteLine("Mock branch lookup failed: " + develop);
            return 1;
        }
        if (command.Contains("<default_branch=develop>"))
        {
            if (Environment.GetEnvironmentVariable("MOCK_FAIL") == "default-branch")
            {
                Console.Error.WriteLine("Mock default branch update failed");
                return 1;
            }
            Console.WriteLine("{}");
            return 0;
        }
        if (command.Contains("<security_and_analysis[secret_scanning][status]=enabled>")
            && Environment.GetEnvironmentVariable("MOCK_FAIL") == "security-settings")
            return 1;

        string stage;
        string name;
        if (args[1].Contains("/rulesets?"))
        {
            stage = "list";
            name = command.Contains("MainProtection") ? "MainProtection" : "RequiredCI";
        }
        else if (args[1] == "-X" && args.Length > 3 && args[3].Contains("/rulesets"))
        {
            stage = "apply";
            name = command.Contains("gh-MainProtection.json") ? "MainProtection" : "RequiredCI";
        }
        else if (args[1].Contains("/rulesets/"))
        {
            stage = "verify";
            name = args[1].EndsWith("/102") ? "MainProtection" : "RequiredCI";
        }
        else
        {
            Console.WriteLine("{}");
            return 0;
        }

        string failure = Environment.GetEnvironmentVariable("MOCK_FAIL");
        bool target = name == Environment.GetEnvironmentVariable("MOCK_TARGET");
        if (target && failure == stage) return 1;
        if (stage == "verify") Console.WriteLine("{\"enforcement\":\"active\"}");
        else if (stage == "apply" && target && failure == "empty-id") return 0;
        else if (stage == "apply" && target && failure == "null-id") Console.WriteLine("null");
        else if (stage == "apply" || Environment.GetEnvironmentVariable("MOCK_EXISTING") == "1")
            Console.WriteLine(name == "MainProtection" ? "102" : "101");
        return 0;
    }
}
'''


class BranchProtectionTests(unittest.TestCase):
    def test_rulesets_and_workflow(self):
        main = json.loads((SETUP / "gh-MainProtection.json").read_text(encoding="utf-8"))
        develop = json.loads((SETUP / "gh-RequiredCI.json").read_text(encoding="utf-8"))
        self.assertEqual(main["name"], "MainProtection")
        for ruleset, branch in ((main, "main"), (develop, "develop")):
            self.assertEqual(ruleset["target"], "branch")
            self.assertEqual(ruleset["enforcement"], "active")
            self.assertEqual(ruleset["conditions"]["ref_name"], {
                "include": [f"refs/heads/{branch}"], "exclude": []
            })
            self.assertEqual(ruleset["bypass_actors"], [])
            rules = {rule["type"]: rule for rule in ruleset["rules"]}
            self.assertIn("deletion", rules)
            self.assertIn("non_fast_forward", rules)
            checks = rules["required_status_checks"]["parameters"]["required_status_checks"]
            self.assertEqual(checks, [
                {"context": "semgrep", "integration_id": 15368},
                {"context": "gitleaks", "integration_id": 15368},
            ])
        rules = {rule["type"]: rule for rule in main["rules"]}
        self.assertEqual(rules["pull_request"]["parameters"], {
            "required_approving_review_count": 0,
            "dismiss_stale_reviews_on_push": False,
            "require_code_owner_review": False,
            "require_last_push_approval": False,
            "required_review_thread_resolution": False,
        })
        self.assertNotIn("pull_request", {rule["type"] for rule in develop["rules"]})
        workflow = (ROOT / ".github" / "workflows" / "security-scan.yml").read_text(encoding="utf-8")
        for event, branches in (("push", ["develop", "main"]), ("pull_request", ["develop", "main"])):
            section = re.search(rf"(?m)^  {event}:\n    branches:\n((?:      - .+\n)+)", workflow)
            self.assertIsNotNone(section)
            self.assertEqual(re.findall(r"(?m)^      - (.+)$", section.group(1)), branches)
        for check in ("semgrep", "gitleaks"):
            self.assertRegex(workflow, rf"(?m)^    name: {check}$")

    def test_dependabot_and_auto_merge_targets(self):
        config = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r'(?m)^  - package-ecosystem:', config), [
            "  - package-ecosystem:"
        ] * 3)
        self.assertEqual(re.findall(r'(?m)^    target-branch: "([^"]+)"$', config), [
            "main", "main", "main"
        ])
        workflow = (ROOT / ".github" / "workflows" / "auto-merge-security-tool-updates.yml").read_text(encoding="utf-8")
        self.assertIn("if: github.event.pull_request.base.ref == 'develop' || github.event.pull_request.base.ref == 'main'", workflow)
        self.assertIn('docker/semgrep/Dockerfile|docker/gitleaks/Dockerfile)', workflow)
        self.assertIn('"$PR_AUTHOR" != "dependabot[bot]"', workflow)
        self.assertIn('"$PR_ACTOR" != "dependabot[bot]"', workflow)


@unittest.skipUnless(os.name == "nt", "Windows is required for batch script tests")
class WindowsBranchProtectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        powershell = shutil.which("powershell.exe")
        if powershell is None:
            raise unittest.SkipTest("Windows PowerShell is required to build the gh mock")
        temporary = tempfile.TemporaryDirectory(prefix="branch protection ")
        cls.addClassCleanup(temporary.cleanup)
        cls.mock_dir = Path(temporary.name)
        source = cls.mock_dir / "MockGh.cs"
        source.write_text(MOCK_GH, encoding="utf-8")
        env = os.environ.copy()
        env.update(MOCK_SOURCE=str(source), MOCK_EXE=str(cls.mock_dir / "gh.exe"))
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command",
             "$ErrorActionPreference = 'Stop'; "
             "Add-Type -TypeDefinition (Get-Content -Raw -LiteralPath $env:MOCK_SOURCE) "
             "-OutputAssembly $env:MOCK_EXE -OutputType ConsoleApplication"],
            capture_output=True, env=env, timeout=60
        )
        if result.returncode:
            raise RuntimeError(f"Could not build gh mock: {result.stderr!r}")

    def test_windows_creates_and_updates_both_rulesets(self):
        for existing, method in (("0", "POST"), ("1", "PUT")):
            with self.subTest(existing=existing):
                result, calls = self.run_windows(existing=existing)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for name, ruleset_id in (("RequiredCI", "101"), ("MainProtection", "102")):
                    endpoint = "repos/example/repo/rulesets"
                    if existing == "1":
                        endpoint += f"/{ruleset_id}"
                    self.assertIn(f"<-X> <{method}> <{endpoint}>", calls)
                    self.assertIn(f"gh-{name}.json", calls)
                    self.assertIn(f"<repos/example/repo/rulesets/{ruleset_id}>", calls)
                self.assertEqual(calls.count("<-X> <POST>"), 2 if existing == "0" else 0)
                self.assertIn("<--paginate> <--jq>", calls)
                self.assertIn('select(.name == "RequiredCI"', calls)
                self.assertIn('select(.name == "MainProtection"', calls)
                self.assertIn("<-X> <PATCH> <repos/example/repo>", calls)
                self.assertIn("<security_and_analysis[secret_scanning][status]=enabled>", calls)
                self.assertNotIn("[エラー]", result.stdout + result.stderr)

    def test_windows_stops_on_ruleset_errors(self):
        for existing in ("0", "1"):
            for target in ("RequiredCI", "MainProtection"):
                for failure in ("list", "apply", "verify", "empty-id", "null-id"):
                    with self.subTest(existing=existing, target=target, failure=failure):
                        result, calls = self.run_windows(
                            existing=existing, failure=failure, target=target
                        )
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn("[エラー]", result.stdout + result.stderr)
                        self.assertNotIn("<security_and_analysis[secret_scanning][status]=enabled>", calls)
                        self.assertNotIn("<default_branch=develop>", calls)
                        if target == "RequiredCI":
                            self.assertNotIn("MainProtection", calls)

    def test_dependabot_update_and_idempotence(self):
        for bom, newline in ((b"", b"\n"), (b"\xef\xbb\xbf", b"\r\n")):
            with self.subTest(bom=bom, newline=newline), tempfile.TemporaryDirectory(prefix="dependabot setup ") as temporary:
                self.check_dependabot_update(Path(temporary), bom, newline)

    def check_dependabot_update(self, temporary, bom, newline):
        root = self.make_repo(temporary)
        config = root / ".github" / "dependabot.yml"
        original = bom + config.read_bytes().replace(b"\n", newline).replace(
            b'target-branch: "main"', b"target-branch: 'feature/test' # kept"
        )
        config.write_bytes(original)
        first = self.run_updater(root)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        expected = original.replace(b"target-branch: 'feature/test'", b'target-branch: "develop"')
        self.assertEqual(config.read_bytes(), expected)
        second = self.run_updater(root)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(config.read_bytes(), expected)
        self.assertIn("already develop", second.stdout)

    def test_windows_configures_develop_after_required_settings(self):
        with tempfile.TemporaryDirectory(prefix="dependabot setup ") as temporary:
            root = self.make_repo(Path(temporary))
            result, calls = self.run_windows(root=root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            config = (root / ".github" / "dependabot.yml").read_text(encoding="utf-8")
            self.assertEqual(config.count('target-branch: "develop"'), 3)
            self.assertIn("commit", result.stdout)
            self.assertIn("push", result.stdout)
            self.assertIn("<default_branch=develop>", calls)
            self.assertIn("<security_and_analysis[secret_scanning][status]=enabled>", calls)
            self.assertLess(calls.index("<repos/example/repo/branches?per_page=100>"),
                            calls.index("<default_branch=develop>"))
            self.assertLess(calls.index("<repos/example/repo/labels/dependencies>"),
                            calls.index("<default_branch=develop>"))
            self.assertLess(calls.index("<repos/example/repo/rulesets/101>"),
                            calls.index("<default_branch=develop>"))
            self.assertLess(calls.index("<repos/example/repo/rulesets/102>"),
                            calls.index("<default_branch=develop>"))
            self.assertLess(calls.index("<security_and_analysis[secret_scanning][status]=enabled>"),
                            calls.index("<default_branch=develop>"))
            self.assertIn(f"cwd={root}", calls)

    def test_windows_skips_both_develop_changes_when_branch_is_absent(self):
        for with_config in (True, False):
            with self.subTest(with_config=with_config), tempfile.TemporaryDirectory(prefix="dependabot setup ") as temporary:
                root = self.make_repo(Path(temporary), with_config=with_config)
                config = root / ".github" / "dependabot.yml"
                original = config.read_bytes() if with_config else None
                result, calls = self.run_windows(root=root, develop="absent")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("[スキップ]", result.stdout)
                self.assertIn("[未完了]", result.stdout)
                self.assertIn("再実行", result.stdout)
                self.assertNotIn("<default_branch=develop>", calls)
                self.assertNotIn("Dependabot 設定はローカルの変更です", result.stdout)
                self.assertIn("gh-RequiredCI.json", calls)
                self.assertIn("gh-MainProtection.json", calls)
                self.assertIn("<security_and_analysis[secret_scanning][status]=enabled>", calls)
                self.assertIn("<repos/example/repo/private-vulnerability-reporting>", calls)
                if with_config:
                    self.assertEqual(config.read_bytes(), original)
                else:
                    self.assertFalse(config.exists())

    def test_windows_stops_on_branch_lookup_errors(self):
        for develop in ("auth-error", "permission-error", "network-error", "partial-error"):
            with self.subTest(develop=develop), tempfile.TemporaryDirectory(prefix="dependabot setup ") as temporary:
                root = self.make_repo(Path(temporary))
                config = root / ".github" / "dependabot.yml"
                original = config.read_bytes()
                result, calls = self.run_windows(root=root, develop=develop)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("[エラー]", result.stdout + result.stderr)
                self.assertNotIn("[スキップ]", result.stdout)
                self.assertNotIn("<default_branch=develop>", calls)
                self.assertNotIn("<label>", calls)
                self.assertNotIn("<-X>", calls)
                self.assertEqual(config.read_bytes(), original)

    def test_windows_stops_on_default_branch_update_error(self):
        with tempfile.TemporaryDirectory(prefix="dependabot setup ") as temporary:
            root = self.make_repo(Path(temporary))
            result, calls = self.run_windows(root=root, failure="default-branch")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("[エラー]", result.stdout + result.stderr)
            self.assertIn("ローカルで変更済み", result.stdout)
            self.assertIn("<default_branch=develop>", calls)
            self.assertIn("<label>", calls)
            self.assertIn("<security_and_analysis[secret_scanning][status]=enabled>", calls)

    def test_windows_does_not_change_default_when_security_settings_fail(self):
        with tempfile.TemporaryDirectory(prefix="dependabot setup ") as temporary:
            root = self.make_repo(Path(temporary))
            result, calls = self.run_windows(root=root, failure="security-settings")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("[エラー]", result.stdout + result.stderr)
            self.assertIn("<security_and_analysis[secret_scanning][status]=enabled>", calls)
            self.assertNotIn("<default_branch=develop>", calls)

    def test_windows_does_not_change_default_when_label_creation_fails(self):
        with tempfile.TemporaryDirectory(prefix="dependabot setup ") as temporary:
            root = self.make_repo(Path(temporary))
            result, calls = self.run_windows(root=root, failure="label")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("[エラー]", result.stdout + result.stderr)
            self.assertIn("<label> <create>", calls)
            self.assertNotIn("<default_branch=develop>", calls)

    def test_dependabot_invalid_input_stops_without_writing(self):
        for kind in ("missing-file", "missing-target", "duplicate", "unsupported"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="dependabot setup ") as temporary:
                root = self.make_repo(Path(temporary), with_config=kind != "missing-file")
                config = root / ".github" / "dependabot.yml"
                if kind != "missing-file":
                    data = config.read_bytes()
                    if kind == "missing-target":
                        data = data.replace(b'    target-branch: "main"\n', b"", 1)
                    elif kind == "duplicate":
                        data = data.replace(b'    target-branch: "main"\n', b'    target-branch: "main"\n    target-branch: "main"\n', 1)
                    else:
                        data = data.replace(b'target-branch: "main"', b'target-branch: [main, develop]', 1)
                    config.write_bytes(data)
                result, calls = self.run_windows(root=root)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("[エラー]", result.stdout + result.stderr)
                self.assertIn("<repos/example/repo/branches?per_page=100>", calls)
                self.assertNotIn("<-X>", calls)
                self.assertNotIn("<label>", calls)
                if kind != "missing-file":
                    self.assertEqual(config.read_bytes(), data)

    def make_repo(self, root, with_config=True):
        setup = root / "git-setup"
        setup.mkdir()
        (root / ".github").mkdir()
        for name in ("gh-enable-push-protection-win.bat", "set-dependabot-develop.ps1",
                     "gh-RequiredCI.json", "gh-MainProtection.json"):
            shutil.copyfile(SETUP / name, setup / name)
        if with_config:
            shutil.copyfile(ROOT / ".github" / "dependabot.yml", root / ".github" / "dependabot.yml")
        return root

    def run_updater(self, root):
        return subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-File", str(root / "git-setup" / "set-dependabot-develop.ps1")],
            capture_output=True, text=True, encoding="utf-8", timeout=30
        )

    def run_windows(self, existing="0", failure="", target="RequiredCI", root=None, develop="present"):
        if root is None:
            temporary = tempfile.TemporaryDirectory(prefix="branch protection repo ")
            self.addCleanup(temporary.cleanup)
            root = self.make_repo(Path(temporary.name))
        log = self.mock_dir / "calls.log"
        log.write_text("", encoding="utf-8")
        env = os.environ.copy()
        env.update(
            MOCK_EXISTING=existing, MOCK_FAIL=failure, MOCK_TARGET=target,
            MOCK_DEVELOP=develop,
            MOCK_LOG=str(log), PATH=str(self.mock_dir) + os.pathsep + env["PATH"]
        )
        script = root / "git-setup" / "gh-enable-push-protection-win.bat"
        cmd = os.environ["COMSPEC"]
        result = subprocess.run(
            f'"{cmd}" /d /c ""{script}""',
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            encoding="utf-8", env=env, cwd=self.mock_dir, timeout=30
        )
        return result, log.read_text(encoding="utf-8-sig")


if __name__ == "__main__":
    unittest.main()
