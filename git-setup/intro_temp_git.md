# 環境構築

## Git セットアップ

チームで統一した Git 操作を行うためのセットアップスクリプトを用意している。  
リポジトリをクローンしたら、最初に一度だけ実行すること。  

### 実行方法

#### Windows の場合

`git-setup/setup-win.bat` をダブルクリックして実行する。

#### Mac の場合

ターミナルで以下を実行する。

```sh
./git-setup/setup-mac.sh
```

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
├── check-setup-mac.sh    # Mac用Gitローカル設定が期待値どおりか確認するスクリプト
├── COMMIT_TEMPLATE   # コミットメッセージのテンプレート
├── enable-push-protection-win.bat # Windows用 GitHub Push protection 有効化スクリプト
├── enable-push-protection-mac.sh  # Mac用 GitHub Push protection 有効化スクリプト
├── hooks/            # commit-msg などの共通Git hooksを管理するディレクトリ
├── setup-win.bat     # Windows用セットアップスクリプト
└── setup-mac.sh      # Mac用セットアップスクリプト
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
`enable-push-protection-win.bat` / `enable-push-protection-mac.sh` を一度実行して有効化する(gh CLI と管理者権限が必要)。

※ `-m` オプションを使用するとテンプレートは表示されない。
※ ユーザのコメントを上書することはしない。一度クリアしたり、何か入力されていたリするときは表示されない。

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
