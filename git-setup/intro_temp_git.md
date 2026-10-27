# 環境構築

## Git セットアップ

チームで統一した Git 操作を行うためのセットアップスクリプトを用意している。  
リポジトリをクローンしたら、最初に一度だけ実行すること。  
セットアップの対応環境は Windows のみ。Mac はサポート対象外とする。

### 実行方法

#### Windows の場合

`git-setup/setup-win.bat` をダブルクリックして実行する。

#### 環境反映の確認

以下コマンドにより`.gitattributes`の変更を既存ファイルに再適用する。

```powershell
git add --renormalize .
```

※ 履歴汚染リスクあるので利用には気を付けること

### ファイル構成

各ファイルの役割および構成は下記の通り。

```text
git-setup/
├── check-setup-win.bat   # Windows用Gitローカル設定が期待値どおりか確認するスクリプト
├── COMMIT_TEMPLATE   # コミットメッセージのテンプレート
├── gh-enable-push-protection-win.bat # Windows用 GitHub Ruleset / Push protection / Auto-merge 有効化スクリプト
├── gh-RequiredCI.json                # developブランチ用 Ruleset 定義
├── gh-MainProtection.json            # mainブランチ用 Ruleset 定義
├── hooks/            # commit-msg などの共通Git hooksを管理するディレクトリ
└── setup-win.bat     # Windows用セットアップスクリプト
.github/workflows/security-scan.yml # CI でのセキュリティスキャン
.gitattributes        # 改行コード・バイナリファイルの管理設定
```

### コミットメッセージについて

`git-setup/COMMIT_TEMPLATE`をテンプレートとして設定している。  
`git commit`時にエディタが開き、書き方の雛形が表示される。  

setup 実行時には `core.hooksPath` を `git-setup/hooks` に設定する。  
標準の hooks ディレクトリは通常参照されず、案内ファイル `SETUP_CREATED_core.hooksPath_changed.txt` が作成される。  
Git hooks を追加・変更する場合は `git-setup/hooks` を編集する。  

セキュリティ検査は GitHub Actions 上の `security-scan.yml` で Semgrep / gitleaks を実行する。
シークレットの流出防止には、リポジトリ側で GitHub の Secret scanning / Push protection を有効化することを推奨する。
テンプレートから作成したリポジトリには設定が引き継がれないため、リポジトリ作成後に
`gh-enable-push-protection-win.bat` を実行して有効化する(gh CLI と管理者権限が必要)。同名の RequiredCI Ruleset が存在する場合は更新される。
このスクリプトはあわせて GitHub の `allow_auto_merge` と `allow_squash_merge` も有効化するため、限定された更新 PR に対して auto-merge を使える前提も整う。
`delete_branch_on_merge` も有効化するため、PR がマージされた head ブランチは自動削除される(未マージのブランチには影響しない。削除されたブランチは GitHub 上から復元可能)。
このテンプレートでは [ .github/workflows/auto-merge-security-tool-updates.yml ](.github/workflows/auto-merge-security-tool-updates.yml) により、GitHub が付与する PR メタデータ上で `dependabot[bot]` が作成した PR であり、変更ファイルが `docker/semgrep/Dockerfile` または `docker/gitleaks/Dockerfile` のみである場合に限って auto-squash merge を予約する。
ブランチ名、PR タイトル、ラベルのような偽装しやすい情報には依存していないため、通常の手作業 PR や他の Dependabot PR が誤って自動マージ対象になることは避けている。
ただし、実際のマージは RequiredCI Ruleset などの必須チェックを通過した後にのみ行われる。
また、auto-merge 予約後に条件を満たさない変更が push された場合は、同ワークフローが予約済みの auto-merge を解除する。
あわせて `dependencies`(Dependabot 用)、`task`(Issue Template の Task 用)、`ai-reported`(AI が起票した Issue 用) ラベルも扱う。既に存在する場合は y/n で確認してから色と説明を上書きするため、不要な上書きを避けられる。
Private vulnerability reporting も有効化し、`.github/SECURITY.md` から案内する非公開の脆弱性報告窓口を用意する(公開リポジトリのみ。非公開リポジトリでは警告を表示して続行する)。

#### main の保護と確認

初期設定スクリプトは、既存の `develop` 向け `RequiredCI` とは別に、`main` 向けの `MainProtection` Ruleset を作成する。同名のリポジトリ Ruleset がある場合は定義ファイルの内容で更新するため、再実行時には手動変更も上書きされる。両 Ruleset の適用後にそれぞれ設定内容が表示される。

`main` は PR 経由の変更が必要で、`semgrep` と `gitleaks` の成功をマージ条件とする。削除と force push も禁止する。`security-scan.yml` は `main` と `develop` 向けの PR で実行される。既存の `develop` 向け Dependabot 自動マージは変更しない。

個人開発を想定して承認の必須人数は 0 人、bypass は設定しない。したがって書き込み権限のない人は PR を作成できてもマージできないが、権限を持つ人による第三者レビューは強制されない。管理者も通常の push では保護を回避できず、緊急時に設定を変更できる人の管理が重要となる。必要に応じて承認人数や例外を定義ファイルで変更し、再適用する。既存の別 Ruleset や Organization のポリシーによって、さらに厳しい制限が適用される場合がある。

Push protection は push に含まれる機密情報の検出・流出防止を目的とする。一方、Ruleset はブランチへの変更方法やマージ条件を制御するもので、両者は別の設定である。Ruleset やセキュリティ機能の利用可否は GitHub のプランやリポジトリの公開設定に依存する。

設定後は GitHub の **Settings → Rules → Rulesets** で両 Ruleset の対象、ルール、bypass を確認する。`main` 向けの検証用 PR で両チェックが実行されること、チェック失敗時にマージがブロックされることを確認し、再度スクリプトを実行しても重複せず設定が維持されることを確認する。別の Ruleset の影響も含めた有効なルールは、GitHub の対象ブランチのルール画面でも確認する。実際に保護されるまで直接 push を避ける。

定義と Windows 用スクリプトのモックテストは `python -B git-setup\test_branch_protection.py` で実行できる。Windows 用の実行テストでは、Windows PowerShell で生成した `gh.exe` モックを使い、両 Ruleset の作成・更新とエラー時の中断を検証する。GitHub への通信や設定変更は行わない。Windows 以外では実行テストをスキップし、定義のみ検証する。このテストは GitHub 上の設定や PR の実動作を確認するものではない。

※ `-m` オプションを使用するとテンプレートは表示されない。
※ ユーザのコメントを上書することはしない。一度クリアしたり、何か入力されていたリするときは表示されない。

### hook の追加・変更ルール

- このテンプレートでは setup 実行時に `core.hooksPath` を `git-setup/hooks` に切り替える。
- hook を追加・変更するときは標準の `.git/hooks` ではなく、必ず `git-setup/hooks` を編集する。
- setup 実行済みでも、hook 追加後は `git-setup/check-setup-win.bat` で設定状態を再確認する。

### Windows バッチ (.bat) の編集ルール

- `chcp 65001` を実行する `.bat` では、処理の途中に日本語の `rem` 行を置かない。cmd の読み取り位置がずれ、`'�...' is not recognized as an internal or external command` のエラーになることがある。
- 説明コメントは、ファイル先頭の `rem "..."` 形式の説明欄にまとめる。この形式ではエラーは確認されていない。
- `call` / `goto` 先のラベルの直前行が日本語の場合も同様にずれるため、ラベルの直前には空行を挟む。
- 編集後は実際に実行し、上記のエラーが出ないことを確認する。

## GitHub CLI

### 本体のインストール

以下コマンドを用いてインストールする

winget install --id GitHub.cli --source winget

### ログイン

以下コマンドを用いてログインする

gh auth login

以下は実行例

```powershell
PS D:\work\> gh auth login
? Where do you use GitHub? GitHub.com
? What is your preferred protocol for Git operations on this host? HTTPS
? Authenticate Git with your GitHub credentials? Yes
? How would you like to authenticate GitHub CLI? Login with a web browser

! First copy your one-time code: XXXX-XXXX
Press Enter to open https://github.com/login/device in your browser...
✓ Authentication complete.
- gh config set -h github.com git_protocol https
✓ Configured git protocol
✓ Logged in as bell-f10works
PS D:\work\>
```

### アカウント切り替え

gh auth switch

### alias登録

ghの組み込みエイリアスによって初回だけは登録しておく。

gh alias set sw 'auth switch'

以降は gh sw で呼び出せる。

### 認証ヘルパーの設定

ghをgitの認証ヘルパーに設定してghによるアカウント切り替えを反映した操作ができるようにする。

gh auth setup-git

## .gitignore以外での除外手段

.gitignore と同様の除外パターンをローカル環境だけに設定できる。  
fork 先で個別に生成される未追跡ファイルなどを除外したい場合に有用。

```
.git/info/exclude
```
