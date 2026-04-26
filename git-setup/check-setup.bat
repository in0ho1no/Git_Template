@echo off
echo === Git ローカル設定の確認 ===
echo.

call :check "commit.template"
call :check "fetch.prune"
call :check "pull.rebase"
call :check "merge.ff"
call :check "core.autocrlf"
call :check "core.safecrlf"
echo.
pause
exit /b

:check
set key=%~1
for /f "delims=" %%v in ('git config --local %key% 2^>nul') do (
  echo [OK] %key% = %%v
  exit /b
)
echo [未設定] %key% -- setup.bat を実行してください
exit /b
