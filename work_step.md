# Step of create work enviromental

## Git セットアップ

チームで統一した Git 操作を行うためのセットアップスクリプトを用意している。
リポジトリをクローンしたら、最初に一度だけ実行すること。

### 実行方法

#### Windows の場合

`git-setup/setup.bat` をダブルクリックして実行する。

#### Mac の場合

ターミナルで以下を実行する。

```sh
chmod +x git-setup/setup.sh
./git-setup/setup.sh
```

※ `chmod +x` は初回のみ必要となる。

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
├── check-setup.bat   # Git ローカル設定が期待値どおりか確認するスクリプト
├── COMMIT_TEMPLATE   # コミットメッセージのテンプレート
├── setup.bat         # Windows 用セットアップスクリプト
└── setup.sh          # Mac 用セットアップスクリプト
.gitattributes        # 改行コード・バイナリファイルの管理設定
```

### コミットメッセージについて

`git-setup/COMMIT_TEMPLATE`をテンプレートとして設定している。  
`git commit`時にエディタが開き、書き方の雛形が表示される。  

※ `-m` オプションを使用するとテンプレートは表示されない。
※ ユーザのコメントを上書することはしない。一度クリアしたり、何か入力されていたリするときは表示されない。
