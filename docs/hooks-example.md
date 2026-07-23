# AIエージェント向け Hook の仕組み(学習用サンプル)

このドキュメントは、Claude Code / GitHub Copilot などのAIコーディングエージェントが使う
「Tool Hook」の仕組みを理解するための最小サンプルを示す。

実際にチームで使っている本番用のhookは以下を参照。
- [.claude/hooks/](../.claude/hooks/)(Claude Code 向け)
- [.github/hooks/](../.github/hooks/)(GitHub Copilot 向け)

※ Git の `commit-msg` などの hook(`git-setup/hooks/`)とは別の仕組みなので混同しないこと。
  こちらは AIエージェントがツール(Bash, Read, Write等)を呼ぶ前後にだけ働く。

## Hook とは

エージェントがツールを呼ぶ前後に、外部コマンドとして登録したスクリプトを挟み込める仕組み。

- **PreToolUse**: ツール実行前に呼ばれる。exit code 2 で「実行をブロック」できる
- **PostToolUse**: ツール実行後に呼ばれる。exit code 2 で「警告をエージェントに見せる」(実行済みの結果自体は取り消せない)

エージェントは hook の標準入力(stdin)へ、対象のツール名と入力をJSON形式で渡す。

```json
{
  "tool_name": "Bash",
  "tool_input": { "command": "echo hello" }
}
```

hook 側はこのJSONを見て判定し、exit code で応答する。

| exit code | 意味 |
|---|---|
| 0 | 許可。ツールはそのまま実行される |
| 2 | 拒否/警告。stderr に書いた内容がエージェントに見える |
| その他 | 想定外エラー。ブロックはされないが警告が出る |

## 最小サンプル

[docs/examples/simple_example_hook.py](examples/simple_example_hook.py) は
「Bashコマンドに `rm -rf` が含まれていたら拒否するだけ」の最小 PreToolUse hook。
コメントを多めに書いているので、上記の仕組みと合わせて読むとわかりやすい。

## 動作確認方法

登録しなくても、ターミナルから直接JSONを流し込んで単体で試せる。

```powershell
# 許可されるケース (exit code 0)
echo '{"tool_name":"Bash","tool_input":{"command":"echo hello"}}' | python docs/examples/simple_example_hook.py
echo $LASTEXITCODE

# 拒否されるケース (exit code 2, stderrにBLOCKEDメッセージ)
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/foo"}}' | python docs/examples/simple_example_hook.py
echo $LASTEXITCODE
```

## settings.json への登録例(参考)

実際にエージェントへ組み込む場合は `.claude/settings.json` の `hooks` に以下のように追記する。
`matcher` でツール名を指定すると、そのツールが呼ばれるときだけ hook が発火する。

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "python docs/examples/simple_example_hook.py" }
        ]
      }
    ]
  }
}
```

※ このサンプルは学習目的のため、現状の `settings.json` には登録していない。

## 本番用hookとの違い

| | このサンプル | 本番用 (`.claude/hooks`, `.github/hooks`) |
|---|---|---|
| 目的 | 仕組みの学習 | 危険操作・機密情報・プロンプトインジェクション対策 |
| チェック内容 | 文字列 `rm -rf` が含まれるかだけ | 正規表現による多数の危険パターン、機密パス保護、不可視Unicode検知、監査ログなど |
| 登録有無 | 未登録(参考コード) | `settings.json` / `.github/hooks/*.json` に登録済み、常時有効 |

本番用hookの中身を読むときは、まずこのサンプルの5ステップ
(JSON受信 → tool_name判定 → tool_input検査 → 拒否ならexit 2 → それ以外はexit 0)
に当てはめて読むと構造を追いやすい。
