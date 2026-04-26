@echo off
chcp 65001 > nul

echo =============================================
echo  Git ローカル設定セットアップ
echo =============================================
echo.


rem "---------------------------------------------------"
rem "目的: コミットメッセージのテンプレートを設定する。"
rem "概要: git commit時にエディタへテンプレを表示するため。"
rem "---------------------------------------------------"
git config --local commit.template git-setup/COMMIT_TEMPLATE
echo [設定] コミットテンプレート


rem "---------------------------------------------------"
rem "目的: fetch時にリモートで削除済みのブランチをローカルからも削除する。"
rem "概要: ブランチの扱いで混乱が生じるのを避けるため。"
rem "---------------------------------------------------"
git config --local fetch.prune true
echo [設定] fetch.prune


rem "---------------------------------------------------"
rem "目的: git pull時にマージコミットを作成する。"
rem "概要: 誰がいつ変更を取り込んだかを履歴に残すため。"
rem "---------------------------------------------------"
git config --local pull.rebase false
echo [設定] pull.rebase


rem "---------------------------------------------------"
rem "目的: git merge時にfast-forwardを行わず、必ずマージコミットを作成する。"
rem "概要: ブランチ単位の作業履歴を明確に残すため。"
rem "---------------------------------------------------"
git config --local merge.ff false
echo [設定] merge.ff


rem "---------------------------------------------------"
rem "目的: 改行コードを自動変換しない。"
rem "概要: .gitattributesにより厳密に制御しているため。"
rem "---------------------------------------------------"
git config --local core.autocrlf false
echo [設定] core.autocrlf


rem "---------------------------------------------------"
rem "目的: CRLFとLFが混じったテキストファイルのコミットに警告を出す。"
rem "概要: CRLFからLFへの変換でファイルが破損するリスクを抑える。"
rem "補足: 完全禁止は開発が止まりかねないのでtrueではなくwarnとする。"
rem "---------------------------------------------------"
git config --local core.safecrlf warn
echo [設定] core.safecrlf


rem "---------------------------------------------------"
rem "目的: git windiffコマンドを使えるようにする。"
rem "概要: WinMergeによる差分比較ができるようにするため。"
rem "補足: デフォルトパスに見つからない場合はスキップする。"
rem "---------------------------------------------------"
set WINMERGE=C:\Program Files\WinMerge\WinMergeU.exe
if exist "%WINMERGE%" (
    git config --local diff.tool WinMerge
    git config --local difftool.prompt false
    git config --local difftool.WinMerge.cmd "\"C:/Program Files/WinMerge/WinMergeU.exe\" -e -r -u -x -wl -wr -dl \"a/$MERGED\" -dr \"b/$MERGED\" \"$LOCAL\" \"$REMOTE\""
    git config --local difftool.WinMerge.trustExitCode false
    git config --local alias.windiff "difftool -y -d -t WinMerge"
    echo [設定] WinMerge    ^(git windiff が使用可能です^)
) else (
    echo git windiffコマンドの設定は行いませんでした。（スキップ）
)

echo.
echo =============================================
echo  セットアップが完了しました
echo =============================================
echo.
pause
