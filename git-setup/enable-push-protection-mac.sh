#!/bin/sh

set -eu

echo "============================================="
echo " GitHub Secret scanning / Push protection 有効化"
echo "============================================="
echo ""


# ---------------------------------------------------
# 目的: GitHub の Secret scanning と Push protection を有効化する。
# 概要: テンプレートから作成したリポジトリには設定が引き継がれないため、
#       リポジトリ作成後に一度実行する。gh CLI と管理者権限が必要。
# 補足: プライベートリポジトリでは GitHub Advanced Security (Secret Protection) の契約が必要。
# ---------------------------------------------------

if ! command -v gh >/dev/null 2>&1; then
  echo "[エラー] gh CLI が見つかりません。https://cli.github.com/ から導入してください。" >&2
  exit 1
fi

repo=$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || true)
if [ -z "$repo" ]; then
  echo "[エラー] リポジトリを特定できませんでした。GitHub リモートのあるリポジトリ内で実行してください。" >&2
  exit 1
fi

echo "[設定] $repo の Secret scanning / Push protection を有効化します"
if ! gh api -X PATCH "repos/$repo" --silent \
  -f "security_and_analysis[secret_scanning][status]=enabled" \
  -f "security_and_analysis[secret_scanning_push_protection][status]=enabled"; then
  echo "[エラー] 有効化に失敗しました。リポジトリの管理者権限があるか確認してください。" >&2
  echo "         プライベートリポジトリでは GitHub Advanced Security (Secret Protection) の契約が必要です。" >&2
  exit 1
fi

echo "[確認] 現在の設定:"
gh api "repos/$repo" --jq '.security_and_analysis | {secret_scanning, secret_scanning_push_protection}'
