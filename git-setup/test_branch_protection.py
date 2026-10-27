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
            Console.WriteLine("example/repo");
            return 0;
        }
        if (args[0] == "label" && args[1] == "create") return 0;
        if (args[0] != "api") return 1;
        if (args[1].Contains("/labels/")) return 1;

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
        for event, branches in (("push", ["develop"]), ("pull_request", ["develop", "main"])):
            section = re.search(rf"(?m)^  {event}:\n    branches:\n((?:      - .+\n)+)", workflow)
            self.assertIsNotNone(section)
            self.assertEqual(re.findall(r"(?m)^      - (.+)$", section.group(1)), branches)
        for check in ("semgrep", "gitleaks"):
            self.assertRegex(workflow, rf"(?m)^    name: {check}$")


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
                        self.assertNotIn("<-X> <PATCH>", calls)
                        if target == "RequiredCI":
                            self.assertNotIn("MainProtection", calls)

    def run_windows(self, existing="0", failure="", target="RequiredCI"):
        log = self.mock_dir / "calls.log"
        log.write_text("", encoding="utf-8")
        env = os.environ.copy()
        env.update(
            MOCK_EXISTING=existing, MOCK_FAIL=failure, MOCK_TARGET=target,
            MOCK_LOG=str(log), PATH=str(self.mock_dir) + os.pathsep + env["PATH"]
        )
        script = SETUP / "gh-enable-push-protection-win.bat"
        cmd = os.environ["COMSPEC"]
        result = subprocess.run(
            f'"{cmd}" /d /c ""{script}""',
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            encoding="utf-8", env=env, cwd=self.mock_dir, timeout=30
        )
        return result, log.read_text(encoding="utf-8-sig")


if __name__ == "__main__":
    unittest.main()
