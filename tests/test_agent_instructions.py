import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AgentInstructionsTest(unittest.TestCase):
    def test_shared_rules_include_claude_specific_sections(self):
        shared = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        for heading in ("## セキュリティポリシー", "## 共通ルール",
                        "## Issue駆動開発ルール", "### 出力の簡潔さ",
                        "### 進捗報告の裏付け"):
            with self.subTest(heading=heading):
                self.assertIn(heading, shared)
        self.assertNotIn("Fable5などのフロンティアモデル利用時の注意", shared)

    def test_claude_import_resolves_to_shared_rules(self):
        entry = (ROOT / ".claude" / "CLAUDE.md").read_text(encoding="utf-8")
        imports = [line.strip()[1:] for line in entry.splitlines()
                   if line.strip().startswith("@")]
        self.assertEqual(imports, ["../AGENTS.md"])
        self.assertEqual((ROOT / ".claude" / imports[0]).resolve(), ROOT / "AGENTS.md")

    def test_entry_points_reference_rules_without_duplicating_them(self):
        shared = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        shared_rules = {line.strip() for line in shared.splitlines()
                        if line.strip().startswith("- ")}
        for path in (ROOT / ".claude" / "CLAUDE.md",
                     ROOT / ".github" / "copilot-instructions.md"):
            with self.subTest(path=path):
                entry = path.read_text(encoding="utf-8")
                self.assertIn("AGENTS.md", entry)
                self.assertFalse(shared_rules.intersection(
                    line.strip() for line in entry.splitlines()
                ))


if __name__ == "__main__":
    unittest.main()
