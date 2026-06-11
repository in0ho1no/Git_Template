@echo off
chcp 65001 > nul
setlocal

echo =============================================
echo  GitHub Secret scanning / Push protection 有効化
echo =============================================
echo.


rem "---------------------------------------------------"
rem "目的: GitHub の Secret scanning と Push protection を有効化する。"
rem "概要: テンプレートから作成したリポジトリには設定が引き継がれないため、"
rem "      リポジトリ作成後に一度実行する。gh CLI と管理者権限が必要。"
rem "補足: プライベートリポジトリでは GitHub Advanced Security (Secret Protection) の契約が必要。"
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

echo [設定] %REPO% の Secret scanning / Push protection を有効化します
gh api -X PATCH "repos/%REPO%" --silent ^
  -f "security_and_analysis[secret_scanning][status]=enabled" ^
  -f "security_and_analysis[secret_scanning_push_protection][status]=enabled"
if errorlevel 1 (
  echo [エラー] 有効化に失敗しました。リポジトリの管理者権限があるか確認してください。
  echo          プライベートリポジトリでは GitHub Advanced Security ^(Secret Protection^) の契約が必要です。
  pause
  exit /b 1
)

echo [確認] 現在の設定:
gh api "repos/%REPO%" --jq ".security_and_analysis | {secret_scanning, secret_scanning_push_protection}"

echo.
pause
