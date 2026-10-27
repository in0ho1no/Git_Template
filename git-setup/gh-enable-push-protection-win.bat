@echo off
chcp 65001 > nul
setlocal

echo =============================================
echo  GitHub Ruleset / Secret scanning / Auto-merge 有効化
echo =============================================
echo.


rem "---------------------------------------------------"
rem "目的: develop がある場合はデフォルトブランチと Dependabot 更新先を develop に変更する。"
rem "      GitHub の RequiredCI Ruleset、Secret scanning、Push protection、Auto-merge 関連設定を有効化し、"
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

pushd "%~dp0.."
if errorlevel 1 (
  echo [エラー] スクリプトのリポジトリに移動できません。
  pause
  exit /b 1
)
set REPO=
for /f "delims=" %%r in ('gh repo view --json nameWithOwner -q .nameWithOwner 2^>nul') do set REPO=%%r
popd
if not defined REPO (
  echo [エラー] リポジトリを特定できませんでした。GitHub リモートのあるリポジトリ内で実行してください。
  pause
  exit /b 1
)

set "SKIPPED_DEVELOP="
call :configure_develop
if errorlevel 1 exit /b 1

rem ラベルは Dependabot と Issue Template が付与する。存在しないラベルは付与されないため事前に用意する
call :ensure_label dependencies 0366d6 "Dependabot update"
if errorlevel 1 exit /b 1
call :ensure_label task c5def5 "Work without behavior change"
if errorlevel 1 exit /b 1
call :ensure_label ai-reported 8a63d2 "Filed by an AI agent"
if errorlevel 1 exit /b 1

if not exist "%~dp0gh-RequiredCI.json" (
  echo [エラー] Ruleset 定義が見つかりません: %~dp0gh-RequiredCI.json
  pause
  exit /b 1
)
if not exist "%~dp0gh-MainProtection.json" (
  echo [エラー] Ruleset 定義が見つかりません: %~dp0gh-MainProtection.json
  pause
  exit /b 1
)

call :ensure_ruleset RequiredCI "%~dp0gh-RequiredCI.json"
if errorlevel 1 exit /b 1
call :ensure_ruleset MainProtection "%~dp0gh-MainProtection.json"
if errorlevel 1 exit /b 1

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

if not defined SKIPPED_DEVELOP (
  call :set_default_develop
  if errorlevel 1 exit /b 1
)

echo [確認] 現在の設定:
gh api "repos/%REPO%" --jq "{default_branch, allow_auto_merge, allow_squash_merge, delete_branch_on_merge, security_and_analysis: .security_and_analysis | {secret_scanning, secret_scanning_push_protection}}"
gh api "repos/%REPO%/private-vulnerability-reporting" --jq "{private_vulnerability_reporting: .enabled}"

echo.
if defined SKIPPED_DEVELOP (
  echo [未完了] develop がないため、デフォルトブランチと Dependabot 更新先の変更をスキップしました。
  echo          他の設定は適用済みです。GitHub 上に develop を作成してから、このスクリプトを再実行してください。
  pause
  exit /b 1
)
pause
exit /b 0


:configure_develop
set "DEVELOP_BRANCH="
for /f "delims=" %%i in ('gh api "repos/%REPO%/branches?per_page=100" --paginate --jq "map(select(.name == \"develop\"))[0].name // empty" ^|^| echo __GH_ERROR__') do set "DEVELOP_BRANCH=%%i"
if "%DEVELOP_BRANCH%"=="__GH_ERROR__" (
  echo [エラー] ブランチ一覧の取得に失敗しました。認証・権限・通信状態を確認してください。
  pause
  exit /b 1
)
if not defined DEVELOP_BRANCH (
  echo [エラー] GitHub 上に develop がありません。
  echo [スキップ] デフォルトブランチと Dependabot 更新先は変更せず、他の設定を続行します。
  set "SKIPPED_DEVELOP=1"
  exit /b 0
)
if not "%DEVELOP_BRANCH%"=="develop" (
  echo [エラー] develop の確認結果が不正なため、セットアップを中止します。
  pause
  exit /b 1
)
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0set-dependabot-develop.ps1"
if errorlevel 1 (
  echo [エラー] Dependabot の更新先を変更できなかったため、セットアップを中止します。
  pause
  exit /b 1
)
echo [確認] Dependabot 設定はローカルの変更です。GitHub に反映するには commit と push が必要です。
exit /b 0


:set_default_develop
echo [設定] %REPO% のデフォルトブランチを develop に変更します
gh api -X PATCH "repos/%REPO%" -f "default_branch=develop" --silent
if errorlevel 1 (
  echo [エラー] デフォルトブランチの変更に失敗したため、セットアップを中止します。
  echo          Dependabot 設定はローカルで変更済みです。他の GitHub 設定も適用済みのため、差分と GitHub の状態を確認してください。
  pause
  exit /b 1
)
exit /b 0


:ensure_ruleset
set "RULESET_NAME=%~1"
set "RULESET_FILE=%~2"
set "RULESET_ID="
for /f "delims=" %%i in ('gh api "repos/%REPO%/rulesets?per_page=100" --paginate --jq "map(select(.name == \"%RULESET_NAME%\" and .source_type == \"Repository\"))[0].id // empty" ^|^| echo __GH_ERROR__') do set "RULESET_ID=%%i"
if "%RULESET_ID%"=="__GH_ERROR__" (
  echo [エラー] Ruleset 一覧の取得に失敗しました。リポジトリの管理者権限があるか確認してください。
  pause
  exit /b 1
)
set "RULESET_EXISTING_ID=%RULESET_ID%"
set "RULESET_ID="
if defined RULESET_EXISTING_ID (
  echo [設定] %REPO% の %RULESET_NAME% Ruleset を更新します
  for /f "delims=" %%i in ('gh api -X PUT "repos/%REPO%/rulesets/%RULESET_EXISTING_ID%" --input "%RULESET_FILE%" --jq ".id" ^|^| echo __GH_ERROR__') do set "RULESET_ID=%%i"
) else (
  echo [設定] %REPO% に %RULESET_NAME% Ruleset を作成します
  for /f "delims=" %%i in ('gh api -X POST "repos/%REPO%/rulesets" --input "%RULESET_FILE%" --jq ".id" ^|^| echo __GH_ERROR__') do set "RULESET_ID=%%i"
)
if "%RULESET_ID%"=="__GH_ERROR__" (
  echo [エラー] %RULESET_NAME% Ruleset の設定に失敗しました。
  pause
  exit /b 1
)
if not defined RULESET_ID (
  echo [エラー] %RULESET_NAME% Ruleset の ID を取得できませんでした。
  pause
  exit /b 1
)
if "%RULESET_ID%"=="null" (
  echo [エラー] %RULESET_NAME% Ruleset の ID を取得できませんでした。
  pause
  exit /b 1
)
echo [確認] %RULESET_NAME% Ruleset:
gh api "repos/%REPO%/rulesets/%RULESET_ID%" --jq "{name, enforcement, conditions, rules, bypass_actors}"
if errorlevel 1 (
  echo [エラー] %RULESET_NAME% Ruleset の確認に失敗しました。
  pause
  exit /b 1
)
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
