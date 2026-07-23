#!/usr/bin/env python3
"""
学習用の最小 PreToolUse hook サンプル。
Claude Code / GitHub Copilot などのAIエージェントが「ツールを呼ぶ直前」に
外部プロセスとして呼び出す hook の仕組みを理解するためのもの。

実用のhookは以下を参照:
  - .claude/hooks/pre_tool_inspect.py (Claude Code 向け)
  - .github/hooks/pre_tool_inspect.py (GitHub Copilot 向け)

このファイルは settings.json 等には登録していない(参考コードのみ)。
動作確認方法は docs/hooks-example.md を参照。
"""
import json
import sys


def main() -> None:
    # 1. エージェントは標準入力(stdin)にJSONで情報を渡してくる
    #    例: {"tool_name": "Bash", "tool_input": {"command": "echo hello"}}
    data = json.load(sys.stdin)

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    # 2. Bashツールが呼ばれようとしている場合だけ、コマンド内容を見る
    if tool_name == "Bash":
        command = tool_input.get("command", "")

        # 3. 危険そうな文字列を含むかどうかを判定する
        if "rm -rf" in command:
            # 4. 拒否したい場合は stderr に理由を書いて exit code 2 で終了する
            #    -> エージェントには「ブロックされた」ことと理由が伝わり、ツールは実行されない
            print(f"BLOCKED: dangerous command detected: {command!r}", file=sys.stderr)
            sys.exit(2)

    # 5. 問題なければ exit code 0 で終了する -> ツールはそのまま実行される
    sys.exit(0)


if __name__ == "__main__":
    main()
