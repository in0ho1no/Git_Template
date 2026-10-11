@echo off
chcp 65001 > nul
setlocal

echo =============================================
echo  GitHub Ruleset / Secret scanning / Auto-merge 有効化
echo =============================================
echo.


rem "---------------------------------------------------"
rem "目的: GitHub の RequiredCI Ruleset、Secret scanning、Push protection、Auto-merge 関連設定を有効化し、"
rem "      Dependabot / Issue Template が使うラベルの作成と Private vulnerability reporting の有効化を行う。"
rem "概要: テンプレートから作成したリポジトリには設定が引き継がれないため、"
rem "      リポジトリ作成後に一度実行する。gh CLI と管理者権限が必要。"
rem "補足: プライベートリポジトリでは GitHub Advanced Security (Secret Protection) の契約が必要。"
rem "      Private vulnerability reporting は公開リポジトリのみ対応のため、失敗しても中断せず警告に留める。"
rem "---------------------------------------------------"

where gh > nul 2> nul
if errorlevel 1 (
  echo [エラー] gh CLI が見つかりません。https://cli.github.com/ から導入してください。
  pause
  exit /b 1
)

set REPO=
for /f "delims=" %%r in ('gh repo view --json nameWithOwner -q .nameWithOwner 2^>nul') do set REPO=%%r
if not defined REPO (
  echo [エラー] リポジトリを特定できませんでした。GitHub リモートのあるリポジトリ内で実行してください。
  pause
  exit /b 1
)

rem ラベルは Dependabot と Issue Template が付与する。存在しないラベルは付与されないため事前に用意する
call :ensure_label dependencies 0366d6 "Dependabot update"
if errorlevel 1 exit /b 1
call :ensure_label task c5def5 "Work without behavior change"
if errorlevel 1 exit /b 1
call :ensure_label ai-reported 8a63d2 "Filed by an AI agent"
if errorlevel 1 exit /b 1

set RULESET_FILE=%~dp0gh-RequiredCI.json
if not exist "%RULESET_FILE%" (
  echo [エラー] Ruleset 定義が見つかりません: %RULESET_FILE%
  pause
  exit /b 1
)

rem for /f 経由では ^| のキャレットが jq 式に混入し検出が失敗するため、一時ファイル経由で受け取る
set RULESET_TMP=%TEMP%\gh-ruleset-id.tmp
set RULESET_ID=
gh api "repos/%REPO%/rulesets" --jq "[.[] | select(.name == \"RequiredCI\" and .source_type == \"Repository\")][0].id // empty" > "%RULESET_TMP%"
if errorlevel 1 (
  del "%RULESET_TMP%" > nul 2> nul
  echo [エラー] Ruleset 一覧の取得に失敗しました。リポジトリの管理者権限があるか確認してください。
  pause
  exit /b 1
)
set /p RULESET_ID=<"%RULESET_TMP%"
del "%RULESET_TMP%" > nul 2> nul

if defined RULESET_ID (
  echo [設定] %REPO% の RequiredCI Ruleset を更新します
  gh api -X PUT "repos/%REPO%/rulesets/%RULESET_ID%" --input "%RULESET_FILE%" --silent
) else (
  echo [設定] %REPO% に RequiredCI Ruleset を作成します
  gh api -X POST "repos/%REPO%/rulesets" --input "%RULESET_FILE%" --silent
)
if errorlevel 1 (
  echo [エラー] RequiredCI Ruleset の設定に失敗しました。リポジトリの管理者権限があるか確認してください。
  pause
  exit /b 1
)
gh api "repos/%REPO%/rulesets" --jq "[.[] | select(.name == \"RequiredCI\" and .source_type == \"Repository\")][0].id // empty" > "%RULESET_TMP%" 2> nul
set RULESET_ID=
set /p RULESET_ID=<"%RULESET_TMP%"
del "%RULESET_TMP%" > nul 2> nul

echo [設定] %REPO% の Secret scanning / Push protection / Auto-merge 関連設定を有効化します
gh api -X PATCH "repos/%REPO%" --silent ^
  -f "security_and_analysis[secret_scanning][status]=enabled" ^
  -f "security_and_analysis[secret_scanning_push_protection][status]=enabled" ^
  -f "allow_auto_merge=true" ^
  -f "allow_squash_merge=true" ^
  -f "delete_branch_on_merge=true"
if errorlevel 1 (
  echo [エラー] 有効化に失敗しました。リポジトリの管理者権限があるか確認してください。
  echo          プライベートリポジトリでは GitHub Advanced Security ^(Secret Protection^) の契約が必要です。
  pause
  exit /b 1
)

echo [設定] %REPO% の Private vulnerability reporting を有効化します
gh api -X PUT "repos/%REPO%/private-vulnerability-reporting" --silent
if errorlevel 1 (
  echo [警告] Private vulnerability reporting の有効化に失敗しました。公開リポジトリ以外では利用できません。
)

echo [確認] 現在の設定:
gh api "repos/%REPO%" --jq "{allow_auto_merge, allow_squash_merge, delete_branch_on_merge, security_and_analysis: .security_and_analysis | {secret_scanning, secret_scanning_push_protection}}"
if defined RULESET_ID gh api "repos/%REPO%/rulesets/%RULESET_ID%" --jq "{name, enforcement, conditions, rules}"
gh api "repos/%REPO%/private-vulnerability-reporting" --jq "{private_vulnerability_reporting: .enabled}"

echo.
pause
exit /b 0


rem 引数: %1=ラベル名 %2=色 %3=説明
rem chcp 65001 下ではラベル直前の行が日本語だと call 後に読み取り位置がずれるため空行を挟む

:ensure_label
echo [設定] %REPO% の %~1 ラベルを作成/更新します
gh api "repos/%REPO%/labels/%~1" >nul 2>nul
if errorlevel 1 goto :ensure_label_create

choice /c YN /m "%~1 ラベルは既に存在します。色と説明を上書きしますか?"
if errorlevel 2 (
  echo [スキップ] %~1 ラベルの更新を見送りました。
  exit /b 0
)
gh label create "%~1" --repo "%REPO%" --color %~2 --description "%~3" --force
if errorlevel 1 (
  echo [エラー] %~1 ラベルの更新に失敗しました。リポジトリの管理者権限があるか確認してください。
  pause
  exit /b 1
)
exit /b 0

:ensure_label_create
gh label create "%~1" --repo "%REPO%" --color %~2 --description "%~3"
if errorlevel 1 (
  echo [エラー] %~1 ラベルの作成に失敗しました。リポジトリの管理者権限があるか確認してください。
  pause
  exit /b 1
)
exit /b 0
