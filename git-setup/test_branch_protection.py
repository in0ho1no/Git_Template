#!/usr/bin/env python3
import json
import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SETUP = ROOT / "git-setup"
MOCK_GH = r'''
gh() {
  printf 'GH:' >&2
  printf ' <%s>' "$@" >&2
  printf '\n' >&2
  case "$1 $2" in
    "repo view") echo example/repo ;;
    "label create") return 0 ;;
    "api "*)
      case "$2" in
        */labels/*) return 1 ;;
        *rulesets\?*)
          [ "$MOCK_FAIL" = list ] && return 1
          if [ "$MOCK_EXISTING" = 1 ]; then
            case "$*" in *MainProtection*) echo 102 ;; *) echo 101 ;; esac
          fi
          ;;
        -X)
          [ "$MOCK_FAIL" = apply ] && return 1
          case "$*" in *gh-MainProtection.json*) echo 102 ;; *) echo 101 ;; esac
          ;;
        */rulesets/*)
          [ "$MOCK_FAIL" = verify ] && return 1
          echo '{"enforcement":"active"}'
          ;;
        *) echo '{}' ;;
      esac
      ;;
    *) return 1 ;;
  esac
}
export -f gh
exec bash "$1"
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

    @unittest.skipUnless(shutil.which("bash"), "bash is required for script tests")
    def test_mac_creates_and_updates_both_rulesets(self):
        for existing, method in (("0", "POST"), ("1", "PUT")):
            with self.subTest(existing=existing):
                result = self.run_mac(existing=existing)
                self.assertEqual(result.returncode, 0, result.stderr)
                for name, ruleset_id in (("RequiredCI", "101"), ("MainProtection", "102")):
                    endpoint = "repos/example/repo/rulesets"
                    if existing == "1":
                        endpoint += f"/{ruleset_id}"
                    self.assertIn(f"<-X> <{method}> <{endpoint}>", result.stderr)
                    self.assertIn(f"gh-{name}.json", result.stderr)
                    self.assertIn(f"<repos/example/repo/rulesets/{ruleset_id}>", result.stderr)
                self.assertIn("<--paginate> <--jq>", result.stderr)
                self.assertIn('select(.name == "RequiredCI"', result.stderr)
                self.assertIn('select(.name == "MainProtection"', result.stderr)

    @unittest.skipUnless(shutil.which("bash"), "bash is required for script tests")
    def test_mac_stops_on_ruleset_errors(self):
        for failure in ("list", "apply", "verify"):
            with self.subTest(failure=failure):
                result = self.run_mac(failure=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("[エラー]", result.stderr)
                self.assertNotIn("<-X> <PATCH>", result.stderr)

    def run_mac(self, existing="0", failure=""):
        env = os.environ.copy()
        env.update(MOCK_EXISTING=existing, MOCK_FAIL=failure)
        script = (SETUP / "gh-enable-push-protection-mac.sh").as_posix()
        bash = shutil.which("bash")
        if os.name == "nt":
            git_bin = Path(bash).parent.parent / "usr" / "bin"
            if (git_bin / "bash.exe").is_file():
                env["PATH"] = str(git_bin) + os.pathsep + env["PATH"]
                bash = str(git_bin / "bash.exe")
        return subprocess.run(
            [bash, "-c", MOCK_GH, "_", script],
            capture_output=True, text=True, encoding="utf-8", env=env, timeout=30
        )


if __name__ == "__main__":
    unittest.main()
