#!/bin/sh

set -eu

echo "============================================="
echo " GitHub Ruleset / Secret scanning 有効化"
echo "============================================="
echo ""


# ---------------------------------------------------
# 目的: GitHub の RequiredCI Ruleset、Secret scanning、Push protection を有効化する。
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

echo "[設定] $repo の dependencies ラベルを作成/更新します"
if ! gh label create dependencies --repo "$repo" --color 0366d6 --description "Dependabot update" --force; then
  echo "[エラー] dependencies ラベルの作成/更新に失敗しました。リポジトリの管理者権限があるか確認してください。" >&2
  exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ruleset_file="$script_dir/gh-RequiredCI.json"
if [ ! -f "$ruleset_file" ]; then
  echo "[エラー] Ruleset 定義が見つかりません: $ruleset_file" >&2
  exit 1
fi

ruleset_id=$(gh api "repos/$repo/rulesets" \
  --jq '.[] | select(.name == "RequiredCI" and .source_type == "Repository") | .id' \
  2>/dev/null | head -n 1 || true)

if [ -n "$ruleset_id" ]; then
  echo "[設定] $repo の RequiredCI Ruleset を更新します"
  ruleset_endpoint="repos/$repo/rulesets/$ruleset_id"
  ruleset_method=PUT
else
  echo "[設定] $repo に RequiredCI Ruleset を作成します"
  ruleset_endpoint="repos/$repo/rulesets"
  ruleset_method=POST
fi

if ! gh api -X "$ruleset_method" "$ruleset_endpoint" --input "$ruleset_file" --silent; then
  echo "[エラー] RequiredCI Ruleset の設定に失敗しました。リポジトリの管理者権限があるか確認してください。" >&2
  exit 1
fi
ruleset_id=$(gh api "repos/$repo/rulesets" \
  --jq '.[] | select(.name == "RequiredCI" and .source_type == "Repository") | .id' | head -n 1)
ruleset_endpoint="repos/$repo/rulesets/$ruleset_id"

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
gh api "$ruleset_endpoint" --jq '{name, enforcement, conditions, rules}'
