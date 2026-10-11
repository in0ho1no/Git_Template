#!/bin/sh

set -eu

echo "============================================="
echo " GitHub Ruleset / Secret scanning / Auto-merge 有効化"
echo "============================================="
echo ""


# ---------------------------------------------------
# 目的: GitHub の RequiredCI Ruleset、Secret scanning、Push protection、Auto-merge 関連設定を有効化し、
#       Dependabot / Issue Template が使うラベルの作成と Private vulnerability reporting の有効化を行う。
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

# 引数: $1=ラベル名 $2=色 $3=説明
ensure_label() {
  echo "[設定] $repo の $1 ラベルを作成/更新します"
  if ! gh api "repos/$repo/labels/$1" >/dev/null 2>&1; then
    if ! gh label create "$1" --repo "$repo" --color "$2" --description "$3"; then
      echo "[エラー] $1 ラベルの作成に失敗しました。リポジトリの管理者権限があるか確認してください。" >&2
      exit 1
    fi
    return 0
  fi

  while :; do
    printf "%s ラベルは既に存在します。色と説明を上書きしますか? [y/n] " "$1"
    read -r answer
    case "$answer" in
      y|Y)
        if ! gh label create "$1" --repo "$repo" --color "$2" --description "$3" --force; then
          echo "[エラー] $1 ラベルの更新に失敗しました。リポジトリの管理者権限があるか確認してください。" >&2
          exit 1
        fi
        return 0
        ;;
      n|N|"")
        echo "[スキップ] $1 ラベルの更新を見送りました。"
        return 0
        ;;
      *)
        echo "y か n で入力してください。" >&2
        ;;
    esac
  done
}

# ラベルは Dependabot と Issue Template が付与する。存在しないラベルは付与されないため事前に用意する
ensure_label dependencies 0366d6 "Dependabot update"
ensure_label task c5def5 "Work without behavior change"
ensure_label ai-reported 8a63d2 "Filed by an AI agent"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ruleset_file="$script_dir/gh-RequiredCI.json"
if [ ! -f "$ruleset_file" ]; then
  echo "[エラー] Ruleset 定義が見つかりません: $ruleset_file" >&2
  exit 1
fi

# 一覧取得の失敗を握りつぶすと POST に進んで重複作成/422 になるため、ここで明示的に止める
if ! ruleset_id=$(gh api "repos/$repo/rulesets" \
  --jq '[.[] | select(.name == "RequiredCI" and .source_type == "Repository")][0].id // empty'); then
  echo "[エラー] Ruleset 一覧の取得に失敗しました。リポジトリの管理者権限があるか確認してください。" >&2
  exit 1
fi

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
  --jq '[.[] | select(.name == "RequiredCI" and .source_type == "Repository")][0].id // empty' \
  2>/dev/null || true)

echo "[設定] $repo の Secret scanning / Push protection / Auto-merge 関連設定を有効化します"
if ! gh api -X PATCH "repos/$repo" --silent \
  -f "security_and_analysis[secret_scanning][status]=enabled" \
  -f "security_and_analysis[secret_scanning_push_protection][status]=enabled" \
  -f "allow_auto_merge=true" \
  -f "allow_squash_merge=true" \
  -f "delete_branch_on_merge=true"; then
  echo "[エラー] 有効化に失敗しました。リポジトリの管理者権限があるか確認してください。" >&2
  echo "         プライベートリポジトリでは GitHub Advanced Security (Secret Protection) の契約が必要です。" >&2
  exit 1
fi

echo "[設定] $repo の Private vulnerability reporting を有効化します"
# 非公開リポジトリでは利用できず失敗するが、他の設定は適用済みのため中断せず警告に留める
if ! gh api -X PUT "repos/$repo/private-vulnerability-reporting" --silent; then
  echo "[警告] Private vulnerability reporting の有効化に失敗しました。公開リポジトリ以外では利用できません。" >&2
fi

echo "[確認] 現在の設定:"
gh api "repos/$repo" --jq '{allow_auto_merge, allow_squash_merge, delete_branch_on_merge, security_and_analysis: .security_and_analysis | {secret_scanning, secret_scanning_push_protection}}'
if [ -n "$ruleset_id" ]; then
  gh api "repos/$repo/rulesets/$ruleset_id" --jq '{name, enforcement, conditions, rules}'
fi
gh api "repos/$repo/private-vulnerability-reporting" --jq '{private_vulnerability_reporting: .enabled}'
